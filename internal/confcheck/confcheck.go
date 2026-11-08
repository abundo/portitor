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
	n, _, err := c.Before.Find(datastore.PathOf(e))
	if err != nil {
		return nil
	}
	return n
}

// Normalize runs the normalize hooks of the entries of t changed since
// before.
func Normalize(before, t *datastore.Tree, changed []*datastore.Node) error {
	c := &Ctx{T: t, Before: before}
	for _, e := range changed {
		if h := hooks[e.S.Path()]; h.normalize != nil {
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
	walk(t.Root)
	return errs
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
	h := hooks[e.S.Path()]
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

// instanceOf is the instance entry e is in, or nil.
func instanceOf(e *datastore.Node) *datastore.Node {
	for n := e; n != nil; n = n.Parent {
		if n.Parent != nil && n.Parent.Parent == nil && n.S.Name == "instance" {
			return n
		}
	}
	return nil
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
