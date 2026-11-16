// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package confcheck holds the checks of the configuration that its schema
// can't say: a value's format is the schema's (portitor-types.yang), a
// reference's target a leafref's, but "a route needs a gateway or an
// interface" is a hook here, on the list's schema path. Every frontend
// gets them: Normalize runs on each edit (Store.Normalize), Check at each
// commit and its validate (Store.Check), and the API checks what a save
// changed (CheckEntries) to refuse it at once, as the GUI expects.
//
// The builder and fwconfig.Validate still check the document at the
// deploy; these checks say earlier, and by path, what they would refuse.
package confcheck

import (
	"errors"
	"fmt"
	"slices"

	"github.com/abundo/portitor/internal/datastore"
)

// hook is what one list's entries get.
type hook struct {
	// normalize fixes up an entry when it is changed: defaults that depend
	// on other leaves, lists made unique. An error refuses the edit; it is
	// for what is wrong in the entry alone, never for what is missing yet
	// (a CLI user builds an entry leaf by leaf).
	normalize func(c *Ctx, e *datastore.Node) error
	// check reports what is wrong with the entry in the whole tree.
	check func(c *Ctx, e *datastore.Node) []error
}

// hooks by the list's schema path, /instance/route.
var hooks = map[string]hook{}

func register(path string, h hook) {
	if _, ok := hooks[path]; ok {
		panic("confcheck: " + path + " twice")
	}
	hooks[path] = h
}

// Ctx is the tree a hook sees, and for normalize the tree before the edit.
type Ctx struct {
	T      *datastore.Tree
	Before *datastore.Tree
}

// old is e as it was before the edit, or nil for a new entry.
func (c *Ctx) old(e *datastore.Node) *datastore.Node {
	if c.Before == nil {
		return nil
	}
	p := datastore.PathOf(e)
	// An entry renamed by the edit was at its old path.
	for _, r := range slices.Backward(c.T.Renamed) {
		to := slices.Clone(r.Path)
		to[len(to)-1].Keys = r.Keys
		if pathEqual(to, p) {
			p = r.Path
		}
	}
	n, _, err := c.Before.Find(p)
	if err != nil {
		return nil
	}
	return n
}

func pathEqual(a, b datastore.Path) bool {
	return slices.EqualFunc(a, b, func(x, y datastore.Elem) bool { return x.Name == y.Name && slices.Equal(x.Keys, y.Keys) })
}

// Normalize runs the normalize hooks of the entries of t changed since
// before.
func Normalize(before, t *datastore.Tree, changed []*datastore.Node) error {
	c := &Ctx{T: t, Before: before}
	for _, e := range changed {
		if h := hookFor(e); h.normalize != nil {
			if err := h.normalize(c, e); err != nil {
				return at(e, err)
			}
		}
	}
	return nil
}

// Check is every check of t, in tree order.
func Check(t *datastore.Tree) []error {
	c := &Ctx{T: t}
	var errs []error
	var walk func(n *datastore.Node)
	walk = func(n *datastore.Node) {
		for _, s := range n.S.Children {
			if s.State {
				continue
			}
			if cn := n.Containers[s.Name]; cn != nil {
				walk(cn)
			}
			for _, e := range n.Lists[s.Name] {
				errs = append(errs, checkEntry(c, e)...)
				walk(e)
			}
		}
	}
	errs = append(errs, checkEntry(c, t.Root)...) // the host
	walk(t.Root)
	return append(errs, checkAccess(t)...)
}

// CheckEntries is the checks of the given entries alone.
func CheckEntries(t *datastore.Tree, entries []*datastore.Node) []error {
	c := &Ctx{T: t}
	var errs []error
	for _, e := range entries {
		errs = append(errs, checkEntry(c, e)...)
	}
	return errs
}

func checkEntry(c *Ctx, e *datastore.Node) []error {
	h := hookFor(e)
	if h.check == nil {
		return nil
	}
	errs := h.check(c, e)
	for i, err := range errs {
		errs[i] = at(e, err)
	}
	return errs
}

// at puts the entry's path on err, unless it has one.
func at(e *datastore.Node, err error) error {
	var de *datastore.Error
	if errors.As(err, &de) {
		return err
	}
	return &datastore.Error{Path: datastore.PathOf(e).String(rootOf(e).S), Msg: err.Error()}
}

func rootOf(n *datastore.Node) *datastore.Node {
	for n.Parent != nil {
		n = n.Parent
	}
	return n
}

// fail is a check's problem.
func fail(format string, args ...any) error { return fmt.Errorf(format, args...) }

// instanceOf is the node of the virtual firewall e is in: its instance
// entry, or the top level for the host's (isHost).
func instanceOf(e *datastore.Node) *datastore.Node {
	if in := vfOf(e); in != nil {
		return in
	}
	return rootOf(e)
}

// vfOf is the instance entry (a virtual firewall) e is in, or nil for the
// host's entries and the top level's own lists.
func vfOf(e *datastore.Node) *datastore.Node {
	for n := e; n != nil; n = n.Parent {
		if n.Parent != nil && n.Parent.Parent == nil && n.S.Name == "instance" {
			return n
		}
	}
	return nil
}

// isHost reports whether in (instanceOf's) is the host: the top level.
func isHost(in *datastore.Node) bool { return in != nil && in.Parent == nil }

// instName is the name of instanceOf's node: an instance's, or the host's
// host-name.
func instName(in *datastore.Node) string {
	if isHost(in) {
		return in.Leaf("host-name")
	}
	return in.Leaf("name")
}

// hookFor is the hook of e's list: by its schema path; the host's lists at
// the top level, and the top level itself, have their virtual firewalls'
// (/interface is /instance/interface, / is /instance) unless they have
// their own.
func hookFor(e *datastore.Node) hook {
	p := e.S.Path()
	if h, ok := hooks[p]; ok {
		return h
	}
	if p == "/" {
		return hooks["/instance"]
	}
	if root := rootOf(e).S; root.Child("instance") != nil && root.Child("instance").Find(p) != nil {
		return hooks["/instance"+p]
	}
	return hook{}
}

// dedupe drops repeated values, keeping the first.
func dedupe(vs []string) []string {
	out := vs[:0]
	for _, v := range vs {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// instances are the host (the top level) and every virtual firewall.
func instances(t *datastore.Tree) []*datastore.Node {
	return append([]*datastore.Node{t.Root}, t.Root.Lists["instance"]...)
}

// instanceNamed is the virtual firewall named name, or the top level for
// the host's host-name; nil for neither.
func instanceNamed(t *datastore.Tree, name string) *datastore.Node {
	if name != "" && name == t.Root.Leaf("host-name") {
		return t.Root
	}
	return t.Root.Entry("instance", []string{name})
}
