// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"bytes"
	"fmt"

	"github.com/abundo/portitor/internal/schema"
)

// ReadValues reads an action's input or output (a schema.Action's Input
// or Output) from RFC 7951 JSON, empty for none: each value checked by its
// type and made canonical, the unset leaves that have a default given it,
// and a mandatory leaf missing an error.
func ReadValues(s *schema.Node, data []byte) (*Node, error) {
	t := New(s)
	if len(bytes.TrimSpace(data)) > 0 {
		if err := t.UnmarshalJSON(data); err != nil {
			return nil, err
		}
	}
	if err := checkValues(t.Root); err != nil {
		return nil, err
	}
	return t.Root, nil
}

func checkValues(n *Node) error {
	for _, c := range n.S.Children {
		switch c.Kind {
		case schema.Leaf:
			v, ok := n.Leaves[c.Name]
			if !ok {
				switch {
				case c.HasDefault:
					n.Leaves[c.Name] = c.Default
				case c.Mandatory:
					return fmt.Errorf("%s: missing; it is mandatory", c.Name)
				}
				continue
			}
			cv, err := c.Type.Check(v)
			if err != nil {
				return fmt.Errorf("%s: %w", c.Name, err)
			}
			n.Leaves[c.Name] = cv
		case schema.LeafList:
			for i, v := range n.LeafLists[c.Name] {
				cv, err := c.Type.Check(v)
				if err != nil {
					return fmt.Errorf("%s: %w", c.Name, err)
				}
				n.LeafLists[c.Name][i] = cv
			}
		case schema.Container:
			if cn := n.Containers[c.Name]; cn != nil {
				if err := checkValues(cn); err != nil {
					return err
				}
			}
		case schema.List:
			for _, e := range n.Lists[c.Name] {
				if err := checkValues(e); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ValuesJSON writes values read by ReadValues as a JSON object of their
// names without the module, as the API's actions take and answer them.
func ValuesJSON(n *Node) ([]byte, error) {
	return NodeJSON(n, JSONOptions{Secrets: true, Bare: true})
}
