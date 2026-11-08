// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"fmt"
	"slices"
	"sort"

	"github.com/abundo/portitor/internal/schema"
)

// Validate checks the tree against its schema: every value's type,
// mandatory leaves, and that what a leafref (or px:global-ref) names
// exists. A union with a member that takes the value as it is, a string
// say, needs no target. The problems come back sorted by path.
func (t *Tree) Validate() []error {
	var errs []error
	add := func(n *Node, leaf string, format string, args ...any) {
		p := PathOf(n)
		if leaf != "" {
			p = append(p, Elem{Name: leaf})
		}
		errs = append(errs, errAt(t, p, format, args...))
	}
	var walk func(n *Node)
	walk = func(n *Node) {
		for _, s := range n.S.Children {
			if s.State {
				continue
			}
			switch s.Kind {
			case schema.Leaf:
				v, ok := n.Leaves[s.Name]
				if !ok {
					if s.Mandatory {
						add(n, s.Name, "missing; it is mandatory")
					}
					continue
				}
				if _, err := s.Type.Check(v); err != nil {
					add(n, s.Name, "%v", err)
					continue
				}
				if msg := t.checkRef(n, s, v); msg != "" {
					add(n, s.Name, "%s", msg)
				}
			case schema.LeafList:
				for _, v := range n.LeafLists[s.Name] {
					if _, err := s.Type.Check(v); err != nil {
						add(n, s.Name, "%v", err)
						continue
					}
					if msg := t.checkRef(n, s, v); msg != "" {
						add(n, s.Name, "%s", msg)
					}
				}
			case schema.Container:
				if c := n.Containers[s.Name]; c != nil {
					walk(c)
				}
			case schema.List:
				for _, e := range n.Lists[s.Name] {
					walk(e)
				}
			}
		}
	}
	walk(t.Root)
	sort.SliceStable(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	return errs
}

// checkRef is what is wrong with a reference held by a leaf of n, or "".
func (t *Tree) checkRef(n *Node, s *schema.Node, v string) string {
	if !isRef(s) {
		return ""
	}
	if s.Type.Kind == "union" {
		for _, u := range s.Type.Union {
			if u.Kind == "leafref" {
				continue
			}
			if _, err := u.Check(v); err == nil {
				return ""
			}
		}
	}
	if _, ok := s.Ext["null-value"]; ok && v == s.Ext["null-value"] {
		return ""
	}
	for _, tg := range t.targets(n, s) {
		if tg.entry.Leaves[tg.leaf] == v {
			return ""
		}
	}
	paths := s.Type.Leafrefs()
	if p, ok := s.Ext["global-ref"]; ok {
		paths = append(paths, p)
	}
	return fmt.Sprintf("%q doesn't name a %s", v, describePaths(paths))
}

func describePaths(paths []string) string {
	var names []string
	for _, p := range paths {
		_, rest := splitUps(p)
		if len(rest) >= 2 {
			if n := rest[len(rest)-2]; !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	switch len(names) {
	case 0:
		return "target"
	case 1:
		return names[0]
	}
	return fmt.Sprintf("%s or %s", joinComma(names[:len(names)-1]), names[len(names)-1])
}

func joinComma(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

// Using lists the references to the entry n: the paths of the leaves
// that name it, for a delete to warn about.
func (t *Tree) Using(n *Node) []string {
	var out []string
	keys := n.Keys()
	t.eachRef(func(holder *Node, leaf *schema.Node, value string, _ func(string)) {
		for i, k := range n.S.Keys {
			if value != keys[i] {
				continue
			}
			if slices.ContainsFunc(t.targets(holder, leaf), func(tg target) bool { return tg.entry == n && tg.leaf == k }) {
				p := append(PathOf(holder), Elem{Name: leaf.Name})
				if s := p.CLI(); !slices.Contains(out, s) {
					out = append(out, s)
				}
			}
		}
	})
	sort.Strings(out)
	return out
}
