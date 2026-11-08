// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package netconf

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

// rpcError is an <rpc-error> (RFC 6241 section 4.3 and appendix A).
type rpcError struct {
	Type    string // transport, rpc, protocol, application
	Tag     string
	Message string
	Path    string
}

func (e *rpcError) Error() string { return e.Message }

func protocolErr(tag, format string, args ...any) *rpcError {
	return &rpcError{Type: "protocol", Tag: tag, Message: fmt.Sprintf(format, args...)}
}

func appErr(tag, path, format string, args ...any) *rpcError {
	return &rpcError{Type: "application", Tag: tag, Path: path, Message: fmt.Sprintf(format, args...)}
}

// asRPCError makes any error an rpc-error: the datastore's carry their
// path, a lock is lock-denied.
func asRPCError(err error) *rpcError {
	var re *rpcError
	if errors.As(err, &re) {
		return re
	}
	var le *datastore.LockedError
	if errors.As(err, &le) {
		return protocolErr("lock-denied", "%s", le.Error())
	}
	var de *datastore.Error
	if errors.As(err, &de) {
		return appErr("invalid-value", de.Path, "%s", de.Msg)
	}
	return appErr("operation-failed", "", "%s", err.Error())
}

var operations = []string{"merge", "replace", "create", "delete", "remove", "none"}

// editor applies an edit-config's <config> to a tree.
type editor struct {
	t        *datastore.Tree
	canWrite func(datastore.Path) bool
}

// apply applies the elements es below the node at p (schema s) with the
// operation inherited from above.
func (ed *editor) apply(p datastore.Path, s *schema.Node, es []*elem, inherited string) error {
	replaced := map[string]bool{} // leaf-lists already replaced by this request
	for _, fe := range es {
		if s.Parent == nil && fe.Space != schema.Namespace {
			return protocolErr("unknown-namespace", "the namespace %q", fe.Space)
		}
		c := s.Child(fe.Local)
		if c == nil {
			return appErr("unknown-element", p.String(ed.t.Root.S), "%s has no %q", nameOf(s), fe.Local)
		}
		if c.State {
			path := append(slices.Clone(p), datastore.Elem{Name: c.Name}).String(ed.t.Root.S)
			return appErr("invalid-value", path, "%s is state (config false), read-only", c.Name)
		}
		op := inherited
		if v, ok := fe.attr(nsBase, "operation"); ok {
			if !slices.Contains(operations, v) || v == "none" {
				return protocolErr("bad-attribute", "operation %q", v)
			}
			op = v
		}
		if c.IsKey() {
			continue // used to name the entry
		}
		here := append(slices.Clone(p), datastore.Elem{Name: c.Name})
		if c.Kind == schema.List {
			keys, err := entryKeys(c, fe, p, ed.t)
			if err != nil {
				return err
			}
			here[len(here)-1].Keys = keys
		}
		path := here.String(ed.t.Root.S)
		if op != "none" && !ed.canWrite(here) {
			return &rpcError{Type: "application", Tag: "access-denied", Path: path, Message: "you may not change " + path}
		}
		exists := ed.exists(here, c)
		switch c.Kind {
		case schema.Leaf:
			v := fe.Text
			if c.Type.Kind != "string" {
				v = fe.text()
			}
			switch op {
			case "merge", "replace", "create":
				if op == "create" && exists {
					return appErr("data-exists", path, "%s is set", path)
				}
				if err := ed.t.Set(here, v); err != nil {
					return err
				}
			case "delete", "remove":
				if !exists {
					if op == "delete" {
						return appErr("data-missing", path, "%s is not set", path)
					}
					continue
				}
				if err := ed.t.Delete(here); err != nil {
					return err
				}
			}
		case schema.LeafList:
			v := fe.Text
			if c.Type.Kind != "string" {
				v = fe.text()
			}
			has := ed.hasValue(here, v)
			switch op {
			case "merge", "create":
				if op == "create" && has {
					return appErr("data-exists", path, "%s has %q", path, v)
				}
				if err := ed.t.Add(here, v); err != nil {
					return err
				}
			case "replace":
				if !replaced[c.Name] {
					replaced[c.Name] = true
					var vals []string
					for _, o := range es {
						if o.Local == c.Name {
							vals = append(vals, o.text())
						}
					}
					if err := ed.t.SetList(here, vals); err != nil {
						return err
					}
				}
			case "delete", "remove":
				if !has {
					if op == "delete" {
						return appErr("data-missing", path, "%s has no %q", path, v)
					}
					continue
				}
				if err := ed.t.Delete(here, v); err != nil {
					return err
				}
			}
		default:
			if err := ed.node(here, c, fe, op, exists); err != nil {
				return err
			}
		}
	}
	return nil
}

// node applies an operation on a container or list entry.
func (ed *editor) node(here datastore.Path, c *schema.Node, fe *elem, op string, exists bool) error {
	path := here.String(ed.t.Root.S)
	switch op {
	case "delete", "remove":
		if !exists {
			if op == "delete" {
				return appErr("data-missing", path, "%s is not there", path)
			}
			return nil
		}
		return ed.t.Delete(here)
	case "none":
		return ed.apply(here, c, fe.Children, "none")
	case "create":
		if exists {
			return appErr("data-exists", path, "%s exists", path)
		}
		fallthrough
	case "replace":
		var old *datastore.Node
		if exists {
			n, _, _ := ed.t.Find(here)
			old = n.Clone(nil)
			if err := ed.t.Delete(here); err != nil {
				return err
			}
		}
		n, err := ed.t.Ensure(here)
		if err != nil {
			return err
		}
		if err := ed.insert(here, c, fe); err != nil {
			return err
		}
		if err := ed.apply(here, c, fe.Children, "merge"); err != nil {
			return err
		}
		if old != nil {
			datastore.KeepSecrets(old, n)
		}
		return nil
	}
	// merge
	if _, err := ed.t.Ensure(here); err != nil {
		return err
	}
	if !exists {
		if err := ed.insert(here, c, fe); err != nil {
			return err
		}
	}
	return ed.apply(here, c, fe.Children, "merge")
}

// insert places a new entry of an ordered-by user list by yang:insert
// (RFC 7950 section 7.8.6).
func (ed *editor) insert(here datastore.Path, c *schema.Node, fe *elem) error {
	where, ok := fe.attr(nsYang, "insert")
	if !ok || c.Kind != schema.List {
		return nil
	}
	if !c.OrderedByUser {
		return protocolErr("bad-attribute", "%s is ordered by the system", c.Name)
	}
	var ref []string
	if where == "before" || where == "after" {
		k, ok := fe.attr(nsYang, "key")
		if !ok {
			return protocolErr("missing-attribute", "insert %s needs key", where)
		}
		var err error
		if ref, err = predicateKeys(c, k); err != nil {
			return protocolErr("bad-attribute", "key: %v", err)
		}
	}
	return ed.t.Move(here, where, ref)
}

var predicate = regexp.MustCompile(`\[\s*(?:[\w-]+:)?([\w-]+)\s*=\s*(?:'([^']*)'|"([^"]*)")\s*\]`)

// predicateKeys reads a yang:key attribute, [name='x'][vrf='y'], into
// the list's key values.
func predicateKeys(c *schema.Node, s string) ([]string, error) {
	vals := map[string]string{}
	for _, m := range predicate.FindAllStringSubmatch(s, -1) {
		vals[m[1]] = m[2] + m[3]
	}
	keys := make([]string, len(c.Keys))
	for i, k := range c.Keys {
		v, ok := vals[k]
		if !ok {
			return nil, fmt.Errorf("no %s in %q", k, s)
		}
		keys[i] = v
	}
	return keys, nil
}

func entryKeys(c *schema.Node, fe *elem, p datastore.Path, t *datastore.Tree) ([]string, error) {
	keys := make([]string, len(c.Keys))
	for i, k := range c.Keys {
		ke := fe.child(k)
		if ke == nil {
			path := append(slices.Clone(p), datastore.Elem{Name: c.Name}).String(t.Root.S)
			return nil, &rpcError{Type: "protocol", Tag: "missing-element", Path: path, Message: fmt.Sprintf("%s needs its key %s", c.Name, k)}
		}
		keys[i] = ke.Text
		if c.Child(k).Type.Kind != "string" {
			keys[i] = ke.text()
		}
	}
	return keys, nil
}

func (ed *editor) exists(p datastore.Path, s *schema.Node) bool {
	n, leaf, err := ed.t.Find(p)
	if err != nil || n == nil {
		return false
	}
	switch {
	case leaf == nil:
		return true
	case leaf.Kind == schema.Leaf:
		_, ok := n.Leaves[s.Name]
		return ok
	}
	_, ok := n.LeafLists[s.Name]
	return ok
}

func (ed *editor) hasValue(p datastore.Path, v string) bool {
	n, leaf, err := ed.t.Find(p)
	return err == nil && n != nil && leaf != nil && slices.Contains(n.LeafLists[leaf.Name], v)
}

func nameOf(s *schema.Node) string {
	if s.Parent == nil {
		return "the configuration"
	}
	return s.Name
}

// joinErrors writes problems one per line.
func joinErrors(errs []error) string {
	parts := make([]string, len(errs))
	for i, e := range errs {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "\n")
}
