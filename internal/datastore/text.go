// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/abundo/portitor/internal/schema"
)

// TextOptions are how Text writes.
type TextOptions struct {
	// Defaults writes the leaves not set, with their default, as comments.
	Defaults bool
}

// Text writes n's contents as the CLI's info: a block per container and
// entry, a line per leaf, leaf-lists in [ ]. Pasted into the CLI, it sets
// them again. A secret leaf is a comment that says it is set.
func Text(w io.Writer, n *Node, o TextOptions) {
	writeBody(w, n, "", o)
}

func writeBody(w io.Writer, n *Node, ind string, o TextOptions) {
	for _, s := range n.S.Children {
		switch s.Kind {
		case schema.Leaf:
			if s.IsKey() {
				continue
			}
			v, ok := n.Leaves[s.Name]
			switch {
			case ok && s.Secret():
				fmt.Fprintf(w, "%s# %s is set (secret)\n", ind, s.Name)
			case ok:
				fmt.Fprintf(w, "%s%s %s\n", ind, s.Name, Quote(v))
			case o.Defaults && s.HasDefault:
				fmt.Fprintf(w, "%s# %s %s (default)\n", ind, s.Name, Quote(s.Default))
			}
		case schema.LeafList:
			vs, ok := n.LeafLists[s.Name]
			if !ok {
				continue
			}
			if s.Secret() {
				fmt.Fprintf(w, "%s# %s is set (secret)\n", ind, s.Name)
				continue
			}
			fmt.Fprintf(w, "%s%s %s\n", ind, s.Name, listWords(vs))
		case schema.Container:
			if c := n.Containers[s.Name]; c != nil {
				fmt.Fprintf(w, "%s%s {\n", ind, s.Name)
				writeBody(w, c, ind+"    ", o)
				fmt.Fprintf(w, "%s}\n", ind)
			}
		case schema.List:
			for _, e := range n.Lists[s.Name] {
				fmt.Fprintf(w, "%s%s {\n", ind, entryHead(e))
				writeBody(w, e, ind+"    ", o)
				fmt.Fprintf(w, "%s}\n", ind)
			}
		}
	}
}

func entryHead(e *Node) string {
	parts := []string{e.S.Name}
	for _, k := range e.Keys() {
		parts = append(parts, Quote(k))
	}
	return strings.Join(parts, " ")
}

func listWords(vs []string) string {
	q := make([]string, len(vs))
	for i, v := range vs {
		q[i] = Quote(v)
	}
	return "[ " + strings.Join(q, " ") + " ]"
}

// Flat writes n's contents as set commands from the root, one per line:
// set / instance host interface wan0 mtu 1500. An entry with nothing set
// but its keys gets a line of its own.
func Flat(w io.Writer, n *Node) {
	writeFlat(w, n, PathOf(n))
}

func writeFlat(w io.Writer, n *Node, p Path) {
	wrote := false
	line := func(rest string) {
		wrote = true
		head := p.CLI()
		if head != "" {
			head += " "
		}
		fmt.Fprintf(w, "set / %s%s\n", head, rest)
	}
	for _, s := range n.S.Children {
		switch s.Kind {
		case schema.Leaf:
			if s.IsKey() {
				continue
			}
			if v, ok := n.Leaves[s.Name]; ok {
				if s.Secret() {
					wrote = true
					fmt.Fprintf(w, "# %s %s is set (secret)\n", p.CLI(), s.Name)
					continue
				}
				line(s.Name + " " + Quote(v))
			}
		case schema.LeafList:
			if vs, ok := n.LeafLists[s.Name]; ok && !s.Secret() {
				line(s.Name + " " + listWords(vs))
			}
		case schema.Container:
			if c := n.Containers[s.Name]; c != nil {
				wrote = true
				writeFlat(w, c, append(slices.Clone(p), Elem{Name: s.Name}))
			}
		case schema.List:
			for _, e := range n.Lists[s.Name] {
				wrote = true
				writeFlat(w, e, append(slices.Clone(p), Elem{Name: s.Name, Keys: e.Keys()}))
			}
		}
	}
	if !wrote && n.IsEntry() {
		fmt.Fprintf(w, "set / %s\n", p.CLI())
	}
}

// DiffText writes the differences between a and b below the nodes at p
// as the CLI's diff: their blocks, with + before what b adds and - before
// what it removes. It writes nothing when they are the same.
func DiffText(w io.Writer, a, b *Tree, p Path) {
	an, _, _ := a.Find(p)
	bn, _, _ := b.Find(p)
	var lines []string
	diffBlock(an, bn, schemaAt(b.Root.S, p), "", &lines)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}

func schemaAt(root *schema.Node, p Path) *schema.Node {
	ss, err := Resolve(root, p)
	if err != nil || len(ss) == 0 {
		return root
	}
	return ss[len(ss)-1]
}

// diffBlock adds the lines of the differences in the body of a and b
// (either may be nil: all added or removed) to lines.
func diffBlock(a, b *Node, s *schema.Node, ind string, lines *[]string) {
	mark := func(sign, text string) { *lines = append(*lines, sign+"     "+ind+text) }
	for _, c := range s.Children {
		switch c.Kind {
		case schema.Leaf:
			if c.IsKey() {
				continue
			}
			av, aok := leafOf(a, c.Name)
			bv, bok := leafOf(b, c.Name)
			if aok == bok && av == bv {
				continue
			}
			text := func(v string) string {
				if c.Secret() {
					return "# " + c.Name + " (secret)"
				}
				return c.Name + " " + Quote(v)
			}
			if aok {
				mark("-", text(av))
			}
			if bok {
				mark("+", text(bv))
			}
		case schema.LeafList:
			av, aok := listOf(a, c.Name)
			bv, bok := listOf(b, c.Name)
			if aok == bok && slices.Equal(av, bv) {
				continue
			}
			if aok {
				mark("-", c.Name+" "+listWords(av))
			}
			if bok {
				mark("+", c.Name+" "+listWords(bv))
			}
		case schema.Container:
			ac, bc := containerOf(a, c.Name), containerOf(b, c.Name)
			block(ac, bc, c, c.Name, ind, lines)
		case schema.List:
			var heads [][]string
			for _, e := range entriesOf(b, c.Name) {
				heads = append(heads, e.Keys())
			}
			for _, e := range entriesOf(a, c.Name) {
				if !slices.ContainsFunc(heads, func(k []string) bool { return slices.Equal(k, e.Keys()) }) {
					heads = append(heads, e.Keys())
				}
			}
			for _, k := range heads {
				var ae, be *Node
				if a != nil {
					ae = a.Entry(c.Name, k)
				}
				if b != nil {
					be = b.Entry(c.Name, k)
				}
				head := c.Name
				for _, x := range k {
					head += " " + Quote(x)
				}
				block(ae, be, c, head, ind, lines)
			}
		}
	}
}

// block adds a container's or entry's lines: all + or - when only one
// side has it, else its head as context around the differences inside.
func block(a, b *Node, s *schema.Node, head, ind string, lines *[]string) {
	switch {
	case a == nil && b == nil:
	case a == nil || b == nil:
		sign, n := "+", b
		if b == nil {
			sign, n = "-", a
		}
		var body strings.Builder
		writeBody(&body, n, ind+"    ", TextOptions{})
		*lines = append(*lines, sign+"     "+ind+head+" {")
		for _, l := range strings.Split(strings.TrimRight(body.String(), "\n"), "\n") {
			if l != "" {
				*lines = append(*lines, sign+"     "+l)
			}
		}
		*lines = append(*lines, sign+"     "+ind+"}")
	default:
		var inner []string
		diffBlock(a, b, s, ind+"    ", &inner)
		if len(inner) == 0 {
			return
		}
		*lines = append(*lines, "      "+ind+head+" {")
		*lines = append(*lines, inner...)
		*lines = append(*lines, "      "+ind+"}")
	}
}

func leafOf(n *Node, name string) (string, bool) {
	if n == nil {
		return "", false
	}
	v, ok := n.Leaves[name]
	return v, ok
}

func listOf(n *Node, name string) ([]string, bool) {
	if n == nil {
		return nil, false
	}
	v, ok := n.LeafLists[name]
	return v, ok
}

func containerOf(n *Node, name string) *Node {
	if n == nil {
		return nil
	}
	return n.Containers[name]
}

func entriesOf(n *Node, name string) []*Node {
	if n == nil {
		return nil
	}
	return n.Lists[name]
}
