// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cli

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

// Item is a word that may come next, with its help. A word in < > is a
// placeholder (a key or value to type), never completed.
type Item struct {
	Word string
	Help string
}

func (i Item) placeholder() bool { return strings.HasPrefix(i.Word, "<") }

// Suggest lists what may follow line: the word being typed (partial) and
// the words that fit there.
func (s *Session) Suggest(ctx context.Context, line string) (partial string, items []Item) {
	toks, open, _ := lex(line)
	if len(toks) > 0 && (open || !endsInSpace(line)) {
		partial = toks[len(toks)-1].text
		toks = toks[:len(toks)-1]
	}
	if len(toks) == 0 {
		for _, c := range commands {
			items = append(items, Item{c.name, c.help})
		}
		items = append(items, s.pathItems(ctx, nil)...)
		return partial, filter(items, partial)
	}
	cmd := s.commandOf(toks[0])
	args := toks[1:]
	words := func(ws ...string) []Item {
		out := make([]Item, len(ws))
		for i, w := range ws {
			out[i] = Item{Word: w}
		}
		return out
	}
	switch cmd {
	case "":
		items = s.pathItems(ctx, toks)
	case "enter":
		if len(args) == 0 {
			items = []Item{{"candidate", "edit the shared candidate"}, {"running", "read the running configuration"}}
		}
	case "commit":
		if len(args) == 0 {
			items = []Item{{"now", "commit and leave candidate mode"}, {"stay", "commit and stay"},
				{"validate", "check the candidate as far as it goes without applying it"},
				{"confirmed", "commit; roll back unless confirmed in time (seconds next)"}}
		} else if len(args) == 1 && args[0].text == "confirmed" {
			items = []Item{{"<seconds>", "the confirm window; none: the settings'"}}
		}
	case "discard":
		if len(args) == 0 {
			items = words("now", "stay")
		}
	case "show", "diff":
		if cmd == "show" && s.showSystem(args) {
			if len(args) == 1 && args[0].text == "api" {
				items = []Item{{"<path>", "/api/..."}}
			}
			break
		}
		for len(args) > 0 && !args[0].quoted {
			if args[0].text == "from" && len(args) == 1 {
				return partial, filter(words("running", "candidate", "state"), partial)
			}
			if args[0].text == "from" {
				args = args[2:]
				continue
			}
			if slices.Contains([]string{"flat", "json", "detail"}, args[0].text) {
				args = args[1:]
				continue
			}
			break
		}
		if len(args) == 0 {
			if cmd == "show" {
				items = words("from", "flat", "json", "detail")
				for _, it := range []Item{{"deployments", "the commits and their deployments"}, {"api", "the answer of a GET of the API"}} {
					if s.showSystem([]token{{text: it.Word}}) {
						items = append(items, it)
					}
				}
			} else {
				items = words("flat")
			}
		}
		items = append(items, s.dirItems(ctx, args)...)
	case "set", "delete", "tree":
		items = s.pathItems(ctx, args)
	case "rename":
		if _, to, ok := splitAt(args, "to"); ok {
			if len(to) == 0 {
				items = []Item{{"<keys>", "the entry's new keys"}}
			}
			break
		}
		items = s.dirItems(ctx, args)
		if p, err := s.parsePath(args); err == nil && p.node.Kind == schema.List && len(args) > 0 {
			items = append(items, Item{"to", "the new keys follow"})
		}
	case "move":
		for _, w := range []string{"first", "last", "before", "after"} {
			if _, _, ok := splitAt(args, w); ok {
				if w == "before" || w == "after" {
					items = []Item{{"<keys>", "the entry to move " + w}}
				}
				return partial, items
			}
		}
		items = s.dirItems(ctx, args)
		if p, err := s.parsePath(args); err == nil && p.node.Kind == schema.List && len(args) > 0 {
			items = append(items, words("first", "last", "before", "after")...)
		}
	}
	return partial, filter(items, partial)
}

func endsInSpace(line string) bool {
	return line != "" && unicode.IsSpace(rune(line[len(line)-1]))
}

func filter(items []Item, partial string) []Item {
	var out []Item
	seen := map[string]bool{}
	for _, it := range items {
		if seen[it.Word] {
			continue
		}
		if it.placeholder() || strings.HasPrefix(it.Word, partial) {
			out = append(out, it)
			seen[it.Word] = true
		}
	}
	return out
}

// dirItems are pathItems without values: for commands that take a path
// alone.
func (s *Session) dirItems(ctx context.Context, toks []token) []Item {
	var out []Item
	for _, it := range s.pathItems(ctx, toks) {
		if !strings.HasPrefix(it.Word, "<value") && it.Word != "[" {
			out = append(out, it)
		}
	}
	return out
}

// pathItems are the words that may follow the path toks: a child's name,
// a list's key, a leaf's value.
func (s *Session) pathItems(ctx context.Context, toks []token) []Item {
	tree, err := s.tree(ctx, s.candidate)
	if err != nil {
		return nil
	}
	inState := false
	at := s.env.Schema
	path := datastore.Path{}
	if len(toks) > 0 && toks[0].is("/") {
		toks = toks[1:]
	} else {
		at, path = s.schemaHere(), slices.Clone(s.cwd)
	}
	for i := 0; i < len(toks); i++ {
		if at.Kind == schema.Leaf || at.Kind == schema.LeafList {
			if at.Kind == schema.LeafList {
				return s.valueItems(tree, path, at)
			}
			return nil
		}
		c, err := childOf(at, toks[i])
		if err != nil {
			return nil
		}
		if c.State && !inState {
			if st, err := s.stateTree(ctx); err == nil {
				tree, inState = st, true
			}
		}
		e := datastore.Elem{Name: c.Name}
		if c.Kind == schema.List {
			for j := range c.Keys {
				if i+1+j >= len(toks) {
					return s.keyItems(tree, path, c, e.Keys)
				}
				e.Keys = append(e.Keys, toks[i+1+j].text)
			}
			i += len(c.Keys)
		}
		path = append(path, e)
		at = c
	}
	switch at.Kind {
	case schema.Leaf, schema.LeafList:
		return s.valueItems(tree, path, at)
	}
	var out []Item
	for _, c := range at.Children {
		if c.IsKey() || (c.State && s.candidate && !at.State) {
			continue
		}
		help := c.Description
		switch c.Kind {
		case schema.Leaf, schema.LeafList:
			if help == "" {
				help = c.Type.String()
			}
		case schema.List:
			help = strings.TrimSpace("list, by " + strings.Join(c.Keys, " ") + ". " + help)
		}
		out = append(out, Item{c.Name, help})
	}
	if len(path) > 0 && len(toks) > 0 {
		out = append(out, Item{"{", "open a block here (for pasted text; } closes it)"})
	}
	return out
}

// keyItems are a list's entries' key (the next one after have) and the
// placeholder for a new one.
func (s *Session) keyItems(tree *datastore.Tree, parent datastore.Path, list *schema.Node, have []string) []Item {
	key := list.Keys[len(have)]
	ks := list.Child(key)
	help := ks.Description
	if help == "" {
		help = ks.Type.String()
	}
	out := []Item{{"<" + key + ">", help}}
	n, _, err := tree.Find(parent)
	if err != nil || n == nil {
		return out
	}
	for _, e := range n.Lists[list.Name] {
		keys := e.Keys()
		if !slices.Equal(keys[:len(have)], have) {
			continue
		}
		if s.env.Access.CanRead(append(slices.Clone(parent), datastore.Elem{Name: list.Name, Keys: keys})) {
			out = append(out, Item{Word: keys[len(have)]})
		}
	}
	return out
}

// valueItems are what a leaf (at path) may be set to.
func (s *Session) valueItems(tree *datastore.Tree, path datastore.Path, leaf *schema.Node) []Item {
	help := leaf.Description
	if help == "" {
		help = leaf.Type.String()
	} else {
		help = leaf.Type.String() + ". " + help
	}
	out := []Item{{"<value>", help}}
	if leaf.Kind == schema.LeafList {
		out = append(out, Item{"[", "the values, all of them, up to ]"})
	}
	var words []string
	var collect func(t *schema.Type)
	collect = func(t *schema.Type) {
		switch t.Kind {
		case "enumeration":
			words = append(words, t.Enums...)
		case "boolean":
			words = append(words, "true", "false")
		case "union":
			for _, u := range t.Union {
				collect(u)
			}
		}
	}
	collect(leaf.Type)
	if len(leaf.Type.Leafrefs()) > 0 || leaf.Ext["global-ref"] != "" {
		work := tree.Clone()
		if holder, err := work.Ensure(path[:len(path)-1]); err == nil {
			words = append(words, work.RefValues(holder, leaf)...)
		}
	}
	for _, w := range words {
		out = append(out, Item{Word: w})
	}
	return out
}

// Complete is the line with its last word completed as far as the
// suggestions agree, and the suggestions to list when they don't.
func (s *Session) Complete(ctx context.Context, line string) (string, []Item) {
	partial, items := s.Suggest(ctx, line)
	var words []string
	for _, it := range items {
		if !it.placeholder() {
			words = append(words, it.Word)
		}
	}
	if len(words) == 0 {
		return line, items
	}
	common := words[0]
	for _, w := range words[1:] {
		for !strings.HasPrefix(w, common) {
			common = common[:len(common)-1]
		}
	}
	base := line[:len(line)-len(partial)]
	if len(words) == 1 {
		return base + datastore.Quote(words[0]) + " ", nil
	}
	if len(common) > len(partial) {
		return base + common, nil
	}
	return line, items
}

// WriteHelp writes the suggestions as ? shows them.
func WriteHelp(w io.Writer, items []Item) {
	if len(items) == 0 {
		fmt.Fprint(w, "  (nothing more)\r\n")
		return
	}
	width := 0
	for _, it := range items {
		width = max(width, len(it.Word))
	}
	width = min(width, 28)
	for _, it := range items {
		help := it.Help
		if len(help) > 100 {
			help = help[:97] + "..."
		}
		fmt.Fprintf(w, "  %-*s  %s\r\n", width, it.Word, help)
	}
}
