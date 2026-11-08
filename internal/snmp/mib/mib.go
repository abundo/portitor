// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mib maps the YANG state (config false nodes, yang/portitor-state.yang)
// onto SNMP objects under a base OID, for the AgentX subagent and the MIB
// file: the top-level state container is a group of scalars, each list a
// table whose index is its parents' keys and its own (its row number when
// it has none), and a container's leaves are scalars or columns of the
// table around it. The numbers are kept in oids.json, so adding a leaf
// never renumbers another; `go test ./internal/snmp/mib -update` gives new
// nodes theirs.
package mib

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/internal/snmp/agentx"
)

// DefaultBase is the base OID until Portitor has a Private Enterprise
// Number: net-snmp's playpen for local experiments (netSnmpPlaypen), .1.
const DefaultBase = "1.3.6.1.4.1.8072.9999.9999.1"

//go:embed oids.json
var registryJSON []byte

// Registry numbers the objects: by number space (the base, "", for the
// groups and tables; a table's or group's path for its columns), the
// number of each key (a node's schema path; an index column of a parent's
// key "table@key path"; a row number "table@#").
type Registry map[string]map[string]uint32

// LoadRegistry is the embedded registry.
func LoadRegistry() (Registry, error) {
	r := Registry{}
	if err := json.Unmarshal(registryJSON, &r); err != nil {
		return nil, fmt.Errorf("oids.json: %w", err)
	}
	return r, nil
}

// number is key's number in space; a new one when assign is set (one above
// the space's highest), else 0.
func (r Registry) number(space, key string, assign bool) uint32 {
	if n, ok := r[space][key]; ok {
		return n
	}
	if !assign {
		return 0
	}
	var high uint32
	for _, n := range r[space] {
		high = max(high, n)
	}
	if r[space] == nil {
		r[space] = map[string]uint32{}
	}
	r[space][key] = high + 1
	return high + 1
}

// Column is a scalar of a group or a column of a table.
type Column struct {
	Num  uint32
	Name string // its SMI descriptor
	// Path is the leaf's path from the group's container or the table's
	// entry, through containers.
	Path []string
	Leaf *schema.Node
	// Index is the index part it is (an index column), -1 for none.
	Index int
}

// IndexPart is one part of a table's index: a key of the table's list or
// of a list around it, or the row number of a list without keys.
type IndexPart struct {
	List *schema.Node
	Key  *schema.Node // nil: the row number
}

// Table is a list's table.
type Table struct {
	Num     uint32
	Name    string // ptXxxTable; the entry is ptXxxEntry
	Stem    string // ptXxx
	List    *schema.Node
	Index   []IndexPart
	Columns []*Column
}

// Group is a top-level state container's scalars.
type Group struct {
	Num     uint32
	Name    string
	Node    *schema.Node
	Scalars []*Column
}

// MIB is the state's objects under Base.
type MIB struct {
	Base    agentx.OID
	Groups  []*Group
	Tables  []*Table
	// Conformance is the number of the MIB's conformance statements.
	Conformance uint32
	byList  map[*schema.Node]*Table
	missing []string
}

// New maps root's state onto OIDs under base by reg; with assign, nodes
// reg lacks get numbers (added to reg), else they are left out and listed
// by Missing.
func New(root *schema.Node, base agentx.OID, reg Registry, assign bool) *MIB {
	m := &MIB{Base: base, byList: map[*schema.Node]*Table{}}
	num := func(space, key string) uint32 {
		n := reg.number(space, key, assign)
		if n == 0 {
			m.missing = append(m.missing, space+" "+key)
		}
		return n
	}
	m.Conformance = num("", "#conformance")
	// The groups first: their numbers come before the tables'.
	for _, c := range root.Children {
		if c.Kind == schema.Container && c.State {
			num("", c.Path())
		}
	}
	for _, c := range root.Children {
		switch {
		case c.Kind == schema.Container && c.State:
			g := &Group{Num: num("", c.Path()), Name: descriptor(c.Path()), Node: c}
			if g.Num == 0 {
				continue
			}
			m.Groups = append(m.Groups, g)
			m.walk(c, nil, func(path []string, leaf *schema.Node) {
				if n := num(c.Path(), leaf.Path()); n != 0 {
					g.Scalars = append(g.Scalars, &Column{Num: n, Name: descriptor(leaf.Path()), Path: path, Leaf: leaf, Index: -1})
				}
			}, nil, num)
		case c.Kind == schema.List && hasState(c):
			m.table(c, nil, num)
		}
	}
	return m
}

// Missing are the nodes New left out for want of a number.
func (m *MIB) Missing() []string { return m.missing }

// hasState reports whether n is state or holds some.
func hasState(n *schema.Node) bool {
	if n.State {
		return true
	}
	return slices.ContainsFunc(n.Children, hasState)
}

// walk visits the state leaves under n through containers, and makes a
// table of each list under it (parents: the index parts around it).
func (m *MIB) walk(n *schema.Node, path []string, leaf func([]string, *schema.Node), parents []IndexPart, num func(string, string) uint32) {
	for _, c := range n.Children {
		if !hasState(c) {
			continue
		}
		p := append(slices.Clone(path), c.Name)
		switch c.Kind {
		case schema.Leaf, schema.LeafList:
			leaf(p, c)
		case schema.Container:
			m.walk(c, p, leaf, parents, num)
		case schema.List:
			m.table(c, parents, num)
		}
	}
}

// table makes list's table and those of the lists under it.
func (m *MIB) table(list *schema.Node, parents []IndexPart, num func(string, string) uint32) {
	t := &Table{Num: num("", list.Path()), List: list}
	if t.Num == 0 {
		return
	}
	t.Stem = descriptor(list.Path())
	t.Name = t.Stem + "Table"
	space := list.Path()
	t.Index = slices.Clone(parents)
	for i, p := range parents {
		key := "#"
		name := t.Stem + upper(p.List.Name) + "Index"
		if p.Key != nil {
			key, name = p.Key.Path(), t.Stem+upper(p.List.Name)+camel(p.Key.Name)
		}
		if n := num(space, space+"@"+key); n != 0 {
			t.Columns = append(t.Columns, &Column{Num: n, Name: name, Leaf: p.Key, Index: i})
		}
	}
	own := []IndexPart{{List: list}}
	if len(list.Keys) > 0 {
		own = nil
		for _, k := range list.Keys {
			own = append(own, IndexPart{List: list, Key: list.Child(k)})
		}
	}
	for _, p := range own {
		key, name := space+"@#", t.Stem+"Index"
		if p.Key != nil {
			key, name = p.Key.Path(), t.Stem+camel(p.Key.Name)
		}
		if n := num(space, key); n != 0 {
			t.Columns = append(t.Columns, &Column{Num: n, Name: name, Path: pathOf(p.Key), Leaf: p.Key, Index: len(t.Index)})
		}
		t.Index = append(t.Index, p)
	}
	m.Tables = append(m.Tables, t)
	m.byList[list] = t
	m.walk(list, nil, func(path []string, leaf *schema.Node) {
		if leaf.IsKey() && leaf.Parent == list {
			return
		}
		if n := num(space, leaf.Path()); n != 0 {
			t.Columns = append(t.Columns, &Column{Num: n, Name: t.Stem + camel(strings.Join(path, "-")), Path: path, Leaf: leaf, Index: -1})
		}
	}, t.Index, num)
	sort.Slice(t.Columns, func(i, j int) bool { return t.Columns[i].Num < t.Columns[j].Num })
}

func pathOf(key *schema.Node) []string {
	if key == nil {
		return nil
	}
	return []string{key.Name}
}

// descriptor is an SMI name for a schema path: "pt" and its parts in camel
// case, without the "state" containers ("/instance/state/interfaces" is
// ptInstanceInterfaces).
func descriptor(path string) string {
	var parts []string
	for _, p := range strings.Split(strings.Trim(path, "/"), "/") {
		if p != "state" {
			parts = append(parts, p)
		}
	}
	return "pt" + camel(strings.Join(parts, "-"))
}

// camel is a-b/c as ABC: each word's first letter upper case.
func camel(s string) string {
	var b strings.Builder
	for _, w := range strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '/' || r == '_' || r == '.' }) {
		b.WriteString(upper(w))
	}
	return b.String()
}

func upper(w string) string {
	if w == "" {
		return w
	}
	return strings.ToUpper(w[:1]) + w[1:]
}

// Syntax is a leaf's SMI syntax and the AgentX type of its values.
func Syntax(leaf *schema.Node) (string, agentx.Type) {
	if leaf == nil {
		return "Unsigned32", agentx.Gauge32
	}
	if leaf.Kind == schema.LeafList {
		return "DisplayString", agentx.OctetString
	}
	switch leaf.Type.Kind {
	case "boolean":
		return "TruthValue", agentx.Integer
	case "int8", "int16", "int32":
		return "Integer32", agentx.Integer
	case "uint8", "uint16", "uint32":
		return "Unsigned32", agentx.Gauge32
	case "int64", "uint64":
		if leaf.Type.Typedef == "counter" {
			return "Counter64", agentx.Counter64
		}
		return "CounterBasedGauge64", agentx.Counter64
	}
	return "DisplayString", agentx.OctetString
}

// value is a leaf's value as its syntax has it; false when it can't be.
func value(leaf *schema.Node, s string) (agentx.Value, bool) {
	_, t := Syntax(leaf)
	switch t {
	case agentx.Integer:
		if leaf.Type.Kind == "boolean" {
			if s == "true" {
				return agentx.Value{Type: t, Data: int64(1)}, true
			}
			return agentx.Value{Type: t, Data: int64(2)}, true
		}
		n, err := strconv.ParseInt(s, 10, 32)
		return agentx.Value{Type: t, Data: n}, err == nil
	case agentx.Gauge32:
		n, err := strconv.ParseUint(s, 10, 32)
		return agentx.Value{Type: t, Data: uint32(n)}, err == nil
	case agentx.Counter64:
		if n, err := strconv.ParseUint(s, 10, 64); err == nil {
			return agentx.Value{Type: t, Data: n}, true
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil && n < 0 {
			return agentx.Value{Type: t, Data: uint64(0)}, true
		}
		return agentx.Value{}, false
	}
	if len(s) > 255 { // DisplayString
		s = s[:255]
	}
	return agentx.Value{Type: agentx.OctetString, Data: []byte(s)}, true
}

// indexSubIDs encodes an index value: a number as itself, anything else
// as a string, its length then its bytes (RFC 2578 7.7).
func indexSubIDs(key *schema.Node, s string) agentx.OID {
	if key != nil && key.Type.Numeric() {
		if n, err := strconv.ParseUint(s, 10, 32); err == nil {
			return agentx.OID{uint32(n)}
		}
	}
	out := agentx.OID{uint32(len(s))}
	for i := 0; i < len(s); i++ {
		out = append(out, uint32(s[i]))
	}
	return out
}

// maxOIDLen is SNMP's limit on an OID's sub-identifiers.
const maxOIDLen = 128

// Snapshot is the state tree t as SNMP objects, ordered by OID.
func (m *MIB) Snapshot(t *datastore.Tree) Snapshot {
	var out []agentx.VarBind
	add := func(oid agentx.OID, leaf *schema.Node, n *datastore.Node) {
		if n == nil || len(oid) > maxOIDLen {
			return
		}
		var s string
		var ok bool
		if leaf.Kind == schema.LeafList {
			var vs []string
			vs, ok = n.LeafLists[leaf.Name]
			s = strings.Join(vs, ", ")
		} else {
			s, ok = n.Leaves[leaf.Name]
		}
		if !ok {
			return
		}
		if v, ok := value(leaf, s); ok {
			out = append(out, agentx.VarBind{Name: oid, Value: v})
		}
	}
	for _, g := range m.Groups {
		data := t.Root.Containers[g.Node.Name]
		for _, c := range g.Scalars {
			add(m.Base.Append(g.Num, c.Num, 0), c.Leaf, follow(data, c.Path))
		}
		m.rows(data, g.Node, nil, nil, &out)
	}
	for _, l := range t.Root.S.Children {
		if tb := m.byList[l]; tb != nil {
			m.listRows(t.Root, tb, nil, nil, &out)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name.Compare(out[j].Name) < 0 })
	return Snapshot(out)
}

// follow is the node holding the leaf at path (its containers), or nil.
func follow(n *datastore.Node, path []string) *datastore.Node {
	for _, p := range path[:max(len(path)-1, 0)] {
		if n == nil {
			return nil
		}
		n = n.Containers[p]
	}
	return n
}

// rows adds the rows of the tables of the lists under n (schema s),
// through containers: idx and vals are the index around them.
func (m *MIB) rows(n *datastore.Node, s *schema.Node, idx agentx.OID, vals []string, out *[]agentx.VarBind) {
	if n == nil {
		return
	}
	for _, c := range s.Children {
		switch {
		case c.Kind == schema.Container && hasState(c):
			m.rows(n.Containers[c.Name], c, idx, vals, out)
		case c.Kind == schema.List:
			if tb := m.byList[c]; tb != nil {
				m.listRows(n, tb, idx, vals, out)
			}
		}
	}
}

// listRows adds the rows of tb's list under parent.
func (m *MIB) listRows(parent *datastore.Node, tb *Table, idx agentx.OID, vals []string, out *[]agentx.VarBind) {
	for i, e := range parent.Lists[tb.List.Name] {
		rowIdx, rowVals := slices.Clone(idx), slices.Clone(vals)
		if len(tb.List.Keys) == 0 {
			rowIdx = append(rowIdx, uint32(i+1))
			rowVals = append(rowVals, strconv.Itoa(i+1))
		}
		for _, k := range tb.List.Keys {
			rowIdx = append(rowIdx, indexSubIDs(tb.List.Child(k), e.Leaves[k])...)
			rowVals = append(rowVals, e.Leaves[k])
		}
		entry := m.Base.Append(tb.Num, 1)
		for _, c := range tb.Columns {
			if c.Index >= 0 {
				continue // index columns are not-accessible
			}
			oid := append(entry.Append(c.Num), rowIdx...)
			m.addLeaf(oid, c, e, out)
		}
		m.rows(e, tb.List, rowIdx, rowVals, out)
	}
}

func (m *MIB) addLeaf(oid agentx.OID, c *Column, e *datastore.Node, out *[]agentx.VarBind) {
	n := follow(e, c.Path)
	if n == nil || len(oid) > maxOIDLen {
		return
	}
	var s string
	var ok bool
	if c.Leaf.Kind == schema.LeafList {
		var vs []string
		vs, ok = n.LeafLists[c.Leaf.Name]
		s = strings.Join(vs, ", ")
	} else {
		s, ok = n.Leaves[c.Leaf.Name]
	}
	if !ok {
		return
	}
	if v, ok := value(c.Leaf, s); ok {
		*out = append(*out, agentx.VarBind{Name: oid, Value: v})
	}
}

// Snapshot is the state's objects in OID order: an agentx.Handler.
type Snapshot []agentx.VarBind

// Get is the value of exactly oid.
func (s Snapshot) Get(oid agentx.OID) (agentx.Value, bool) {
	i := sort.Search(len(s), func(i int) bool { return s[i].Name.Compare(oid) >= 0 })
	if i < len(s) && s[i].Name.Compare(oid) == 0 {
		return s[i].Value, true
	}
	return agentx.Value{}, false
}

// Next is the first object after oid (or oid itself, with include),
// before end.
func (s Snapshot) Next(oid agentx.OID, include bool, end agentx.OID) (agentx.VarBind, bool) {
	i := sort.Search(len(s), func(i int) bool {
		c := s[i].Name.Compare(oid)
		return c > 0 || (include && c == 0)
	})
	if i == len(s) || (len(end) > 0 && s[i].Name.Compare(end) >= 0) {
		return agentx.VarBind{}, false
	}
	return s[i], true
}
