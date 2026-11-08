// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/abundo/portitor/internal/schema"
)

// JSON options.
type JSONOptions struct {
	// Secrets writes secret leaves; without it they are left out.
	Secrets bool
	// Indent pretty-prints.
	Indent bool
}

// MarshalJSON writes the tree as RFC 7951 JSON: top-level names
// qualified with the module, 64-bit numbers as strings.
func (t *Tree) MarshalJSON() ([]byte, error) {
	return t.JSON(JSONOptions{Secrets: true})
}

// JSON writes the tree (or, with node, that part of it) as RFC 7951 JSON.
func (t *Tree) JSON(o JSONOptions) ([]byte, error) {
	return NodeJSON(t.Root, o)
}

// NodeJSON writes n as a JSON object of RFC 7951.
func NodeJSON(n *Node, o JSONOptions) ([]byte, error) {
	v := nodeValue(n, o, n.Parent == nil)
	if o.Indent {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}

// ordered keeps an object's members in schema order.
type ordered []member

type member struct {
	name  string
	value any
}

func (o ordered) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(m.name)
		b.Write(k)
		b.WriteByte(':')
		v, err := json.Marshal(m.value)
		if err != nil {
			return nil, err
		}
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func nodeValue(n *Node, o JSONOptions, top bool) ordered {
	out := ordered{}
	name := func(s string) string {
		if top {
			return schema.Module + ":" + s
		}
		return s
	}
	for _, s := range n.S.Children {
		switch s.Kind {
		case schema.Leaf:
			v, ok := n.Leaves[s.Name]
			if !ok || (s.Secret() && !o.Secrets) {
				continue
			}
			out = append(out, member{name(s.Name), leafJSON(s, v)})
		case schema.LeafList:
			vs, ok := n.LeafLists[s.Name]
			if !ok || (s.Secret() && !o.Secrets) {
				continue
			}
			arr := make([]any, len(vs))
			for i, v := range vs {
				arr[i] = leafJSON(s, v)
			}
			out = append(out, member{name(s.Name), arr})
		case schema.Container:
			if c := n.Containers[s.Name]; c != nil {
				out = append(out, member{name(s.Name), nodeValue(c, o, false)})
			}
		case schema.List:
			es := n.Lists[s.Name]
			if len(es) == 0 {
				continue
			}
			arr := make([]any, len(es))
			for i, e := range es {
				arr[i] = nodeValue(e, o, false)
			}
			out = append(out, member{name(s.Name), arr})
		}
	}
	return out
}

// jsonKind is how a leaf's values are written: "number", "bool" or
// "string"; a leafref's as its target's.
func jsonKind(s *schema.Node) string {
	t := s.Type
	if t.Kind == "leafref" {
		if tgt := leafrefTarget(s, t.Path); tgt != nil {
			t = tgt.Type
		}
	}
	switch t.Kind {
	case "int8", "int16", "int32", "uint8", "uint16", "uint32":
		return "number"
	case "boolean":
		return "bool"
	}
	return "string"
}

// LeafrefTarget is the schema leaf a leafref path of the leaf s names
// (a key of a list, mostly), or nil.
func LeafrefTarget(s *schema.Node, path string) *schema.Node { return leafrefTarget(s, path) }

// leafrefTarget is the schema leaf a leafref path of s names.
func leafrefTarget(s *schema.Node, path string) *schema.Node {
	ups, rest := splitUps(path)
	n := s.Parent
	for i := 1; i < ups && n != nil; i++ {
		n = n.Parent
	}
	if n == nil {
		return nil
	}
	return n.Find(strings.Join(rest, "/"))
}

func leafJSON(s *schema.Node, v string) any {
	switch jsonKind(s) {
	case "number":
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	case "bool":
		return v == "true"
	}
	if s.Type.Kind == "empty" {
		return []any{nil}
	}
	return v
}

// UnmarshalJSON reads RFC 7951 JSON into the tree, which must have its
// schema root (New). Names may be qualified with the module.
func (t *Tree) UnmarshalJSON(data []byte) error {
	if t.Root == nil {
		return fmt.Errorf("datastore: UnmarshalJSON into a tree without a schema")
	}
	root := newNode(t.Root.S, nil)
	if err := readObject(root, data, PathOf(root), t.Root.S); err != nil {
		return err
	}
	t.Root = root
	return nil
}

// ReadJSON reads JSON into the node at p: an object of its members.
func (t *Tree) ReadJSON(p Path, data []byte) error {
	n, err := t.Ensure(p)
	if err != nil {
		return err
	}
	return readObject(n, data, p, t.Root.S)
}

func readObject(n *Node, data []byte, p Path, root *schema.Node) error {
	var obj map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return fmt.Errorf("%s: %w", p.String(root), err)
	}
	for name, raw := range obj {
		local := name
		if i := strings.IndexByte(name, ':'); i >= 0 {
			if name[:i] != schema.Module {
				return fmt.Errorf("%s: unknown module of %q", p.String(root), name)
			}
			local = name[i+1:]
		}
		s := n.S.Child(local)
		if s == nil {
			return fmt.Errorf("%s: no %q", p.String(root), local)
		}
		here := append(p, Elem{Name: local})
		switch s.Kind {
		case schema.Leaf:
			v, err := scalar(raw)
			if err != nil {
				return fmt.Errorf("%s: %w", here.String(root), err)
			}
			n.Leaves[local] = v
		case schema.LeafList:
			var arr []json.RawMessage
			if err := json.Unmarshal(raw, &arr); err != nil {
				return fmt.Errorf("%s: %w", here.String(root), err)
			}
			vals := make([]string, 0, len(arr))
			for _, r := range arr {
				v, err := scalar(r)
				if err != nil {
					return fmt.Errorf("%s: %w", here.String(root), err)
				}
				vals = append(vals, v)
			}
			if len(vals) > 0 {
				n.LeafLists[local] = vals
			}
		case schema.Container:
			c := newNode(s, n)
			if err := readObject(c, raw, here, root); err != nil {
				return err
			}
			n.Containers[local] = c
		case schema.List:
			var arr []json.RawMessage
			if err := json.Unmarshal(raw, &arr); err != nil {
				return fmt.Errorf("%s: %w", here.String(root), err)
			}
			for _, r := range arr {
				e := newNode(s, n)
				if err := readObject(e, r, here, root); err != nil {
					return err
				}
				for _, k := range s.Keys {
					if _, ok := e.Leaves[k]; !ok {
						return fmt.Errorf("%s: an entry without its key %s", here.String(root), k)
					}
				}
				if n.Entry(local, e.Keys()) != nil {
					return fmt.Errorf("%s: two entries %v", here.String(root), e.Keys())
				}
				n.insert(e)
			}
		}
	}
	return nil
}

func scalar(raw json.RawMessage) (string, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	switch x := v.(type) {
	case string:
		return x, nil
	case json.Number:
		return x.String(), nil
	case bool:
		return strconv.FormatBool(x), nil
	case []any:
		if len(x) == 1 && x[0] == nil {
			return "", nil // empty
		}
	}
	return "", fmt.Errorf("not a value: %s", raw)
}
