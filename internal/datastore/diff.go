// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"slices"

	"github.com/abundo/portitor/internal/schema"
)

// Op is what a Change does.
type Op uint8

const (
	OpSet    Op = iota // a leaf gets New
	OpDelete           // a leaf, leaf-list, container or entry goes
	OpList             // a leaf-list gets Values
	OpCreate           // a container or entry is made (with nothing but its keys)
	OpOrder            // an ordered list's entries are in Order
)

// Change is one difference between two trees, as an edit of the first.
type Change struct {
	Op     Op
	Path   Path
	Old    string   // OpSet, of a leaf that had a value
	HadOld bool     // OpSet
	New    string   // OpSet
	Values []string // OpList
	Order  [][]string
}

// Diff lists the changes that make a into b: entries and containers made
// and removed, leaves set and deleted, leaf-lists and order changed.
func Diff(a, b *Tree) []Change {
	var out []Change
	diffNode(a.Root, b.Root, nil, &out)
	return out
}

func diffNode(a, b *Node, p Path, out *[]Change) {
	for _, s := range b.S.Children {
		if s.State {
			continue
		}
		here := append(slices.Clone(p), Elem{Name: s.Name})
		switch s.Kind {
		case schema.Leaf:
			if s.IsKey() {
				continue
			}
			av, aok := a.Leaves[s.Name]
			bv, bok := b.Leaves[s.Name]
			switch {
			case bok && (!aok || av != bv):
				*out = append(*out, Change{Op: OpSet, Path: here, Old: av, HadOld: aok, New: bv})
			case aok && !bok:
				*out = append(*out, Change{Op: OpDelete, Path: here})
			}
		case schema.LeafList:
			av, aok := a.LeafLists[s.Name]
			bv, bok := b.LeafLists[s.Name]
			switch {
			case bok && !slices.Equal(av, bv):
				*out = append(*out, Change{Op: OpList, Path: here, Values: slices.Clone(bv)})
			case aok && !bok:
				*out = append(*out, Change{Op: OpDelete, Path: here})
			}
		case schema.Container:
			ac, bc := a.Containers[s.Name], b.Containers[s.Name]
			switch {
			case bc != nil && ac == nil:
				*out = append(*out, Change{Op: OpCreate, Path: here})
				diffNode(newNode(s, a), bc, here, out)
			case bc != nil:
				diffNode(ac, bc, here, out)
			case ac != nil:
				*out = append(*out, Change{Op: OpDelete, Path: here})
			}
		case schema.List:
			for _, ae := range a.Lists[s.Name] {
				if b.Entry(s.Name, ae.Keys()) == nil {
					*out = append(*out, Change{Op: OpDelete, Path: append(slices.Clone(p), Elem{Name: s.Name, Keys: ae.Keys()})})
				}
			}
			for _, be := range b.Lists[s.Name] {
				ep := append(slices.Clone(p), Elem{Name: s.Name, Keys: be.Keys()})
				ae := a.Entry(s.Name, be.Keys())
				if ae == nil {
					*out = append(*out, Change{Op: OpCreate, Path: ep})
					ae = newNode(s, a)
				}
				diffNode(ae, be, ep, out)
			}
			if s.OrderedByUser && !sameOrder(a.Lists[s.Name], b.Lists[s.Name]) {
				order := make([][]string, len(b.Lists[s.Name]))
				for i, e := range b.Lists[s.Name] {
					order[i] = e.Keys()
				}
				*out = append(*out, Change{Op: OpOrder, Path: here, Order: order})
			}
		}
	}
}

// sameOrder reports whether b's entries are in the order applying the
// other changes gives: a's that b keeps, in a's order, then b's new ones.
func sameOrder(a, b []*Node) bool {
	var want [][]string
	for _, e := range a {
		if slices.ContainsFunc(b, func(f *Node) bool { return slices.Equal(e.Keys(), f.Keys()) }) {
			want = append(want, e.Keys())
		}
	}
	for _, f := range b {
		if !slices.ContainsFunc(a, func(e *Node) bool { return slices.Equal(e.Keys(), f.Keys()) }) {
			want = append(want, f.Keys())
		}
	}
	got := make([][]string, len(b))
	for i, f := range b {
		got[i] = f.Keys()
	}
	return slices.EqualFunc(want, got, slices.Equal)
}

// Apply makes the changes in t. It is lenient, as a rebase needs: a
// delete of what is gone and a set below what is gone (which is made
// again) are not errors.
func (t *Tree) Apply(changes []Change) error {
	for _, c := range changes {
		switch c.Op {
		case OpSet:
			if err := t.Set(c.Path, c.New); err != nil {
				return err
			}
		case OpList:
			if err := t.SetList(c.Path, c.Values); err != nil {
				return err
			}
		case OpCreate:
			if _, err := t.Ensure(c.Path); err != nil {
				return err
			}
		case OpDelete:
			if n, leaf, err := t.Find(c.Path[:len(c.Path)-1]); err == nil && n != nil && leaf == nil {
				_ = t.Delete(c.Path)
			}
		case OpOrder:
			parent, _, err := t.Find(c.Path[:len(c.Path)-1])
			if err != nil || parent == nil {
				continue
			}
			name := c.Path[len(c.Path)-1].Name
			es := parent.Lists[name]
			var sorted []*Node
			for _, k := range c.Order {
				if e := parent.Entry(name, k); e != nil {
					sorted = append(sorted, e)
				}
			}
			for _, e := range es {
				if !slices.Contains(sorted, e) {
					sorted = append(sorted, e)
				}
			}
			parent.Lists[name] = sorted
		}
	}
	return nil
}

// Equal reports whether a and b hold the same configuration.
func Equal(a, b *Tree) bool { return len(Diff(a, b)) == 0 }

// ChangedEntries are the list entries of b that differ from a: for each
// change, the deepest entry of b on its path, once each, in the order of
// the changes. A deleted entry's parent entry counts as changed.
func ChangedEntries(a, b *Tree) []*Node {
	var out []*Node
	seen := map[*Node]bool{}
	for _, c := range Diff(a, b) {
		var deepest *Node
		n := b.Root
		for _, e := range c.Path {
			if e.Keys != nil {
				n = n.Entry(e.Name, e.Keys)
				if n == nil {
					break
				}
				deepest = n
			} else if next := n.Containers[e.Name]; next != nil {
				n = next
			} else {
				break
			}
		}
		if deepest != nil && !seen[deepest] {
			seen[deepest] = true
			out = append(out, deepest)
		}
	}
	return out
}
