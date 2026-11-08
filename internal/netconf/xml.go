// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package netconf

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

// Namespaces.
const (
	nsBase       = "urn:ietf:params:xml:ns:netconf:base:1.0"
	nsMonitoring = "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"
	nsYang       = "urn:ietf:params:xml:ns:yang:1"
)

// elem is an XML element as read: name, attributes, text and children.
type elem struct {
	Space, Local string
	Attrs        []xml.Attr
	Text         string
	Children     []*elem
}

func parseXML(data []byte) (*elem, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var stack []*elem
	var root *elem
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			e := &elem{Space: t.Name.Space, Local: t.Name.Local, Attrs: t.Attr}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.Children = append(p.Children, e)
			} else if root == nil {
				root = e
			}
			stack = append(stack, e)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].Text += string(t)
			}
		}
	}
	if root == nil {
		return nil, errors.New("no element")
	}
	return root, nil
}

// text is the element's text, trimmed unless it has no children (a
// leaf's value keeps its spaces only inside).
func (e *elem) text() string { return strings.TrimSpace(e.Text) }

// child is the first child named local.
func (e *elem) child(local string) *elem {
	for _, c := range e.Children {
		if c.Local == local {
			return c
		}
	}
	return nil
}

func (e *elem) attr(space, local string) (string, bool) {
	for _, a := range e.Attrs {
		if a.Name.Local == local && (space == "" || a.Name.Space == space) {
			return a.Value, true
		}
	}
	return "", false
}

func escape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// writeNode writes n's contents as XML elements: the top level with the
// module's namespace. Secret leaves are left out.
func writeNode(b *strings.Builder, n *datastore.Node, top bool) {
	ns := ""
	if top {
		ns = ` xmlns="` + schema.Namespace + `"`
	}
	for _, s := range n.S.Children {
		switch s.Kind {
		case schema.Leaf:
			if v, ok := n.Leaves[s.Name]; ok && !s.Secret() {
				b.WriteString("<" + s.Name + ns + ">" + escape(v) + "</" + s.Name + ">")
			}
		case schema.LeafList:
			if s.Secret() {
				continue
			}
			for _, v := range n.LeafLists[s.Name] {
				b.WriteString("<" + s.Name + ns + ">" + escape(v) + "</" + s.Name + ">")
			}
		case schema.Container:
			if c := n.Containers[s.Name]; c != nil {
				b.WriteString("<" + s.Name + ns + ">")
				writeNode(b, c, false)
				b.WriteString("</" + s.Name + ">")
			}
		case schema.List:
			for _, e := range n.Lists[s.Name] {
				b.WriteString("<" + s.Name + ns + ">")
				writeNode(b, e, false)
				b.WriteString("</" + s.Name + ">")
			}
		}
	}
}

// filter is the part of the tree a subtree filter (RFC 6241 section 6)
// selects: the filter element's children against the root.
func filter(t *datastore.Tree, f *elem) *datastore.Tree {
	out := datastore.New(t.Root.S)
	var mine []*elem
	for _, c := range f.Children {
		if c.Space == "" || c.Space == schema.Namespace {
			mine = append(mine, c)
		}
	}
	selectInto(out.Root, t.Root, mine)
	return out
}

// selectInto copies into dst what the filter elements fs select of src.
func selectInto(dst, src *datastore.Node, fs []*elem) {
	for _, fe := range fs {
		s := src.S.Child(fe.Local)
		if s == nil {
			continue
		}
		switch s.Kind {
		case schema.Leaf:
			if v, ok := src.Leaves[s.Name]; ok && (fe.text() == "" || fe.text() == v) {
				dst.Leaves[s.Name] = v
			}
		case schema.LeafList:
			for _, v := range src.LeafLists[s.Name] {
				if (fe.text() == "" || fe.text() == v) && !slices.Contains(dst.LeafLists[s.Name], v) {
					dst.LeafLists[s.Name] = append(dst.LeafLists[s.Name], v)
				}
			}
		case schema.Container:
			c := src.Containers[s.Name]
			if c == nil {
				continue
			}
			d := dst.AddContainer(s)
			if len(fe.Children) == 0 {
				copyNode(d, c)
			} else {
				selectInto(d, c, fe.Children)
			}
		case schema.List:
			for _, e := range src.Lists[s.Name] {
				if !matches(e, fe) {
					continue
				}
				keys := map[string]string{}
				for _, k := range s.Keys {
					keys[k] = e.Leaves[k]
				}
				d := dst.Entry(s.Name, e.Keys())
				if d == nil {
					d = dst.AddEntry(s, keys)
				}
				if onlyContentMatches(fe) {
					copyNode(d, e)
				} else {
					selectInto(d, e, fe.Children)
				}
			}
		}
	}
}

// matches reports whether the entry has the values of the filter's
// content match nodes (its leaves with text).
func matches(e *datastore.Node, fe *elem) bool {
	for _, c := range fe.Children {
		s := e.S.Child(c.Local)
		if s == nil || s.Kind != schema.Leaf || c.text() == "" || len(c.Children) > 0 {
			continue
		}
		if e.Leaf(s.Name) != c.text() {
			return false
		}
	}
	return true
}

// onlyContentMatches reports whether the filter element has no children
// but content match nodes, which selects the whole entry.
func onlyContentMatches(fe *elem) bool {
	for _, c := range fe.Children {
		if c.text() == "" || len(c.Children) > 0 {
			return false
		}
	}
	return true
}

// copyNode copies src's contents into dst.
func copyNode(dst, src *datastore.Node) {
	c := src.Clone(dst.Parent)
	dst.Leaves, dst.LeafLists, dst.Containers, dst.Lists = c.Leaves, c.LeafLists, c.Containers, c.Lists
	for _, cs := range dst.Containers {
		cs.Parent = dst
	}
	for _, es := range dst.Lists {
		for _, e := range es {
			e.Parent = dst
		}
	}
}
