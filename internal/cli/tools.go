// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

// tools runs an action of an entry (the YANG modules' actions), as SR
// Linux's tools: tools <path to the entry> <action> [<input> <value>]...,
// a leaf-list's values one by one or in [ ]. A view answers from the
// session's datastore; an operation acts on the firewalls in either mode;
// a change edits the candidate, in candidate mode.
func (s *Session) tools(ctx context.Context, args []token) error {
	p, a, in, err := s.parseTools(args)
	if err != nil {
		return err
	}
	if (a.Kind == schema.ActionChange || a.Kind == schema.ActionCreate) && !s.candidate {
		return fmt.Errorf("%s changes the candidate: enter candidate first", a.Name)
	}
	input, err := toolsInput(a, in)
	if err != nil {
		return err
	}
	out, warnings, err := s.env.Action(ctx, p.path, a.Name, input, s.candidate)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		s.printf("Warning: %s\n", w)
	}
	datastore.Text(s.out, out, datastore.TextOptions{})
	return nil
}

// parseTools splits tools' words into the entry's path, its action and
// the input's words.
func (s *Session) parseTools(args []token) (parsed, *schema.Action, []token, error) {
	for i := 1; i < len(args); i++ {
		p, err := s.parsePath(args[:i])
		if err != nil || !isEntry(p) {
			continue
		}
		if args[i].quoted {
			break
		}
		if p.node.Child(args[i].text) != nil {
			continue // a child, not an action
		}
		a, err := actionOf(p.node, args[i].text)
		if err != nil {
			return p, nil, nil, err
		}
		return p, a, args[i+1:], nil
	}
	return parsed{}, nil, nil, errors.New("tools <path to an entry> <action> [<input> <value>]...")
}

// isEntry reports whether p ends at a list's entry.
func isEntry(p parsed) bool {
	return !p.list && p.node.Kind == schema.List && len(p.path) > 0 && p.path[len(p.path)-1].Keys != nil
}

// actionOf is the action of list a word names: its name, or a prefix of
// one name alone.
func actionOf(list *schema.Node, w string) (*schema.Action, error) {
	if a := list.Action(w); a != nil {
		return a, nil
	}
	var found []*schema.Action
	for _, a := range list.Actions {
		if strings.HasPrefix(a.Name, w) {
			found = append(found, a)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return nil, fmt.Errorf("%s has no action %q", list.Name, w)
	}
	names := make([]string, len(found))
	for i, a := range found {
		names[i] = a.Name
	}
	return nil, fmt.Errorf("%q is ambiguous: %s", w, strings.Join(names, ", "))
}

// toolsInput reads an action's input from its words: a leaf's name and
// value, a leaf-list's name and a value (again for more) or [ values ].
func toolsInput(a *schema.Action, words []token) (*datastore.Node, error) {
	obj := map[string]any{}
	for i := 0; i < len(words); i++ {
		c, err := childOf(a.Input, words[i])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a.Name, err)
		}
		if i+1 >= len(words) {
			return nil, fmt.Errorf("%s needs its value", c.Name)
		}
		switch c.Kind {
		case schema.Leaf:
			obj[c.Name] = words[i+1].text
			i++
		case schema.LeafList:
			vals, _ := obj[c.Name].([]string)
			if words[i+1].is("[") {
				j := i + 2
				for ; j < len(words) && !words[j].is("]"); j++ {
					vals = append(vals, words[j].text)
				}
				if j >= len(words) {
					return nil, errors.New("[ without ]")
				}
				i = j
			} else {
				vals = append(vals, words[i+1].text)
				i++
			}
			obj[c.Name] = vals
		default:
			return nil, fmt.Errorf("%s: only leaves are given here", c.Name)
		}
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return datastore.ReadValues(a.Input, data)
}

// toolsItems are what may follow tools' words: the path to an entry, then
// its actions, then their input.
func (s *Session) toolsItems(ctx context.Context, args []token) []Item {
	if _, a, in, err := s.parseTools(args); err == nil {
		// After a leaf's name, its value; else the input's names.
		if len(in)%2 == 1 {
			if c, err := childOf(a.Input, in[len(in)-1]); err == nil {
				help := c.Type.String()
				if c.Description != "" {
					help += ". " + c.Description
				}
				items := []Item{{"<value>", help}}
				if c.Type.Kind == "enumeration" {
					for _, e := range c.Type.Enums {
						items = append(items, Item{Word: e})
					}
				}
				return items
			}
			return nil
		}
		var items []Item
		for _, c := range a.Input.Children {
			items = append(items, Item{c.Name, strings.TrimSpace(c.Type.String() + ". " + c.Description)})
		}
		return items
	}
	items := s.dirItems(ctx, args)
	if p, err := s.parsePath(args); err == nil && len(args) > 0 && isEntry(p) {
		for _, a := range p.node.Actions {
			items = append(items, Item{a.Name, a.Kind + ": " + a.Description})
		}
	}
	return items
}
