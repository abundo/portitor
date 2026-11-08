// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/abundo/portitor/internal/schema"
)

// EditOp is how EditJSON applies its body.
type EditOp uint8

const (
	// EditMerge merges the body into what is at the path, making what is
	// missing (RESTCONF's PATCH). A leaf-list in the body replaces the
	// leaf-list's values; null deletes a leaf.
	EditMerge EditOp = iota
	// EditReplace makes what is at the path the body (PUT); the secrets the
	// body leaves out are kept, since a client can't read them back.
	EditReplace
	// EditCreate makes what the body is, which must not exist (POST): at a
	// list's path, a new entry; elsewhere, the node itself.
	EditCreate
)

// EditJSON applies an RFC 7951 JSON body at p: an object for a container
// or list entry (or the root), an array of entries for a whole list (one
// entry object for EditCreate), a value for a leaf and an array for a
// leaf-list. Every value is checked against its type, and state can't be
// written.
func (t *Tree) EditJSON(p Path, op EditOp, data []byte) error {
	ss, err := ResolveAll(t.Root.S, p)
	if err != nil {
		return err
	}
	if err := writable(ss); err != nil {
		return err
	}
	s := t.Root.S
	if len(ss) > 0 {
		s = ss[len(ss)-1]
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return errAt(t, p, "the body: %v", err)
	}
	switch {
	case s.Kind == schema.Leaf:
		if v == nil {
			return t.deleteIfThere(p)
		}
		if op == EditCreate && t.has(p, s) {
			return errAt(t, p, "%s is set", s.Name)
		}
		str, err := jsonScalar(v)
		if err != nil {
			return errAt(t, p, "%v", err)
		}
		return t.Set(p, str)
	case s.Kind == schema.LeafList:
		vals, err := jsonScalars(v)
		if err != nil {
			return errAt(t, p, "%v", err)
		}
		if op == EditReplace {
			return t.SetList(p, vals)
		}
		for _, x := range vals {
			if op == EditCreate && slices.Contains(t.values(p), x) {
				return errAt(t, p, "%q is there", x)
			}
			if err := t.Add(p, x); err != nil {
				return err
			}
		}
		return nil
	case s.Kind == schema.List && p[len(p)-1].Keys == nil && len(s.Keys) > 0:
		return t.editList(p, s, op, v)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return errAt(t, p, "the body must be an object")
	}
	exists := len(p) == 0 || t.has(p, s)
	switch op {
	case EditCreate:
		if exists {
			return errAt(t, p, "%s exists", s.Name)
		}
	case EditReplace:
		var old *Node
		if exists {
			n, _, _ := t.Find(p)
			old = n.Clone(nil)
			if err := t.Delete(p); err != nil {
				return err
			}
		}
		if err := t.mergeObject(p, s, obj); err != nil {
			return err
		}
		if old != nil {
			n, _, _ := t.Find(p)
			KeepSecrets(old, n)
		}
		return nil
	}
	return t.mergeObject(p, s, obj)
}

// editList applies a body at a whole list's path p.
func (t *Tree) editList(p Path, s *schema.Node, op EditOp, v any) error {
	if op == EditCreate {
		obj, ok := v.(map[string]any)
		if !ok {
			return errAt(t, p, "the body must be the new entry, an object")
		}
		ep, err := t.entryPath(p, s, obj)
		if err != nil {
			return err
		}
		if t.has(ep, s) {
			return errAt(t, ep, "%s exists", s.Name)
		}
		return t.mergeObject(ep, s, obj)
	}
	arr, ok := v.([]any)
	if !ok {
		return errAt(t, p, "the body must be an array of entries")
	}
	parent, _, err := t.Find(p[:len(p)-1])
	if err != nil {
		return err
	}
	var old []*Node
	if op == EditReplace && parent != nil {
		for _, e := range parent.Lists[s.Name] {
			old = append(old, e.Clone(nil))
		}
		delete(parent.Lists, s.Name)
	}
	for _, x := range arr {
		obj, ok := x.(map[string]any)
		if !ok {
			return errAt(t, p, "an entry must be an object")
		}
		ep, err := t.entryPath(p, s, obj)
		if err != nil {
			return err
		}
		if err := t.mergeObject(ep, s, obj); err != nil {
			return err
		}
		if op == EditReplace {
			n, _, _ := t.Find(ep)
			for _, o := range old {
				if slices.Equal(o.Keys(), n.Keys()) {
					KeepSecrets(o, n)
				}
			}
		}
	}
	return nil
}

// entryPath is the path of the entry of list p (schema s) whose keys obj
// holds.
func (t *Tree) entryPath(p Path, s *schema.Node, obj map[string]any) (Path, error) {
	keys := make([]string, len(s.Keys))
	for i, k := range s.Keys {
		raw, ok := objMember(obj, k)
		if !ok {
			return nil, errAt(t, p, "an entry without its key %s", k)
		}
		v, err := jsonScalar(raw)
		if err != nil {
			return nil, errAt(t, p, "%s: %v", k, err)
		}
		keys[i] = v
	}
	ep := slices.Clone(p)
	ep[len(ep)-1] = Elem{Name: s.Name, Keys: keys}
	return ep, nil
}

// mergeObject merges obj into the container or entry at p (schema s),
// making it.
func (t *Tree) mergeObject(p Path, s *schema.Node, obj map[string]any) error {
	n, err := t.Ensure(p)
	if err != nil {
		return err
	}
	for name := range obj {
		local := name
		if i := strings.IndexByte(name, ':'); i >= 0 {
			if name[:i] != schema.Module {
				return errAt(t, p, "unknown module of %q", name)
			}
			local = name[i+1:]
		}
		if s.Child(local) == nil {
			return errAt(t, p, "%s has no %q", nameOf(s), local)
		}
	}
	for _, c := range s.Children {
		raw, ok := objMember(obj, c.Name)
		if !ok {
			continue
		}
		here := append(slices.Clone(p), Elem{Name: c.Name})
		switch c.Kind {
		case schema.Leaf:
			if c.IsKey() {
				v, err := jsonScalar(raw)
				if err != nil {
					return errAt(t, here, "%v", err)
				}
				if cv, err := c.Type.Check(v); err != nil || cv != n.Leaves[c.Name] {
					return errAt(t, here, "the key is %q, not %q; rename the entry to change it", n.Leaves[c.Name], v)
				}
				continue
			}
			if raw == nil {
				if err := t.deleteIfThere(here); err != nil {
					return err
				}
				continue
			}
			v, err := jsonScalar(raw)
			if err != nil {
				return errAt(t, here, "%v", err)
			}
			if err := t.Set(here, v); err != nil {
				return err
			}
		case schema.LeafList:
			vals, err := jsonScalars(raw)
			if err != nil {
				return errAt(t, here, "%v", err)
			}
			if err := t.SetList(here, vals); err != nil {
				return err
			}
		case schema.Container:
			sub, ok := raw.(map[string]any)
			if !ok {
				return errAt(t, here, "must be an object")
			}
			if err := t.mergeObject(here, c, sub); err != nil {
				return err
			}
		case schema.List:
			if err := t.editList(here, c, EditMerge, raw); err != nil {
				return err
			}
		}
	}
	return nil
}

// objMember is obj's member name, plain or qualified with the module.
func objMember(obj map[string]any, name string) (any, bool) {
	if v, ok := obj[name]; ok {
		return v, true
	}
	v, ok := obj[schema.Module+":"+name]
	return v, ok
}

func (t *Tree) has(p Path, s *schema.Node) bool {
	n, leaf, err := t.Find(p)
	if err != nil || n == nil {
		return false
	}
	if leaf == nil {
		return true
	}
	if leaf.Kind == schema.Leaf {
		_, ok := n.Leaves[s.Name]
		return ok
	}
	_, ok := n.LeafLists[s.Name]
	return ok
}

func (t *Tree) values(p Path) []string {
	n, leaf, err := t.Find(p)
	if err != nil || n == nil || leaf == nil {
		return nil
	}
	return n.LeafLists[leaf.Name]
}

func (t *Tree) deleteIfThere(p Path) error {
	ss, err := Resolve(t.Root.S, p)
	if err != nil {
		return err
	}
	if !t.has(p, ss[len(ss)-1]) {
		return nil
	}
	return t.Delete(p)
}

// jsonScalar is a JSON value of a leaf as the datastore holds it.
func jsonScalar(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case json.Number:
		return x.String(), nil
	case bool:
		if x {
			return "true", nil
		}
		return "false", nil
	case []any:
		// RFC 7951's empty type is [null].
		if len(x) == 1 && x[0] == nil {
			return "", nil
		}
	}
	return "", fmt.Errorf("not a value: %v", v)
}

func jsonScalars(v any) ([]string, error) {
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("must be an array")
	}
	out := make([]string, len(arr))
	for i, x := range arr {
		s, err := jsonScalar(x)
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

// KeepSecrets copies the secrets of old into new where new has none: a
// client can't read them back, so a replace without them keeps them.
func KeepSecrets(old, new *Node) {
	for name, v := range old.Leaves {
		if s := old.S.Child(name); s != nil && s.Secret() {
			if _, ok := new.Leaves[name]; !ok {
				new.Leaves[name] = v
			}
		}
	}
	for name, vs := range old.LeafLists {
		if s := old.S.Child(name); s != nil && s.Secret() {
			if _, ok := new.LeafLists[name]; !ok {
				new.LeafLists[name] = slices.Clone(vs)
			}
		}
	}
	for name, oc := range old.Containers {
		if nc := new.Containers[name]; nc != nil {
			KeepSecrets(oc, nc)
		}
	}
	for name, es := range old.Lists {
		for _, oe := range es {
			if ne := new.Entry(name, oe.Keys()); ne != nil {
				KeepSecrets(oe, ne)
			}
		}
	}
}
