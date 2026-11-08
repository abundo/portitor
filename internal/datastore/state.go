// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/abundo/portitor/internal/schema"
)

// Fill fills n from v, a value of the agent API (a struct or decoded
// JSON): each member to the child of its name with - for _, objects to
// containers, arrays of objects to list entries (those without their
// keys left out), arrays of values to leaf-lists. Members the schema
// doesn't have are left out. It is how the state (config false) is read.
func Fill(n *Node, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) != nil {
		return
	}
	fillObject(n, obj)
}

// FillList adds entries to the list name of n from items, an array.
func FillList(n *Node, name string, items any) {
	s := n.S.Child(name)
	if s == nil || s.Kind != schema.List {
		return
	}
	data, err := json.Marshal(items)
	if err != nil {
		return
	}
	var arr []json.RawMessage
	if json.Unmarshal(data, &arr) != nil {
		return
	}
	fillEntries(n, s, arr)
}

func fillObject(n *Node, obj map[string]json.RawMessage) {
	for k, raw := range obj {
		s := n.S.Child(strings.ReplaceAll(k, "_", "-"))
		if s == nil {
			continue
		}
		switch s.Kind {
		case schema.Leaf:
			if v, err := scalar(raw); err == nil && v != "" {
				n.Leaves[s.Name] = v
			}
		case schema.LeafList:
			var arr []json.RawMessage
			if json.Unmarshal(raw, &arr) != nil {
				continue
			}
			var vals []string
			for _, r := range arr {
				if v, err := scalar(r); err == nil {
					vals = append(vals, v)
				}
			}
			if len(vals) > 0 {
				n.LeafLists[s.Name] = vals
			}
		case schema.Container:
			var sub map[string]json.RawMessage
			dec := json.NewDecoder(bytes.NewReader(raw))
			if dec.Decode(&sub) != nil || sub == nil {
				continue
			}
			fillObject(n.AddContainer(s), sub)
		case schema.List:
			var arr []json.RawMessage
			if json.Unmarshal(raw, &arr) == nil {
				fillEntries(n, s, arr)
			}
		}
	}
}

func fillEntries(n *Node, s *schema.Node, arr []json.RawMessage) {
	for _, r := range arr {
		var obj map[string]json.RawMessage
		if json.Unmarshal(r, &obj) != nil {
			continue
		}
		e := newNode(s, n)
		fillObject(e, obj)
		missing := false
		for _, k := range s.Keys {
			if _, ok := e.Leaves[k]; !ok {
				missing = true
			}
		}
		if missing || (len(s.Keys) > 0 && n.Entry(s.Name, e.Keys()) != nil) {
			continue
		}
		n.insert(e)
	}
}
