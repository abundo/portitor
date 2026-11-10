// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sqlmap maps the configuration tree onto rows, as the px:
// extensions of the YANG modules say: a list is a table (px:table), its
// entries rows under their parent's row (px:parent-column), in order
// (px:position); a leaf is a column of its name, or of a row id
// (px:column) of the entry a leafref names; a nested list is a JSON column
// (px:json). The rows are portitor-config's code's view of the
// configuration (package confview, Rows) and what its imports make it
// with (Adder); there are no tables behind them. The entries' ids are
// kept by path (IDs, the table config_ids).
package sqlmap

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

// Mapping is the schema's tables.
type Mapping struct {
	root   *schema.Node
	tables []*table // parents before children
	byList map[*schema.Node]*table
}

type table struct {
	s         *schema.Node
	name      string
	singleton int64
	parent    *table // the nearest table above; nil at the root
	parentCol string
	position  string
	cols      []*col
	jsons     []*jsonCol
}

type colKind uint8

const (
	plain colKind = iota
	leafList
	ref      // a row id of the entry a leafref names
	external // a row id of a table outside the tree, by name
)

type col struct {
	leaf      *schema.Node
	column    string
	kind      colKind
	target    *table // ref: the referenced list's table
	external  string
	nullValue string
	nullable  bool
}

type jsonCol struct {
	list   *schema.Node
	column string
	isMap  bool
}

// New maps the schema's tables.
func New(root *schema.Node) (*Mapping, error) {
	m := &Mapping{root: root, byList: map[*schema.Node]*table{}}
	var walk func(s *schema.Node, parent *table) error
	walk = func(s *schema.Node, parent *table) error {
		for _, c := range s.Children {
			if !c.IsDir() || c.State {
				continue
			}
			name, ok := c.Ext["table"]
			if !ok {
				if _, nested := c.Ext["json"]; nested {
					continue
				}
				if _, nested := c.Ext["json-map"]; nested {
					continue
				}
				if err := walk(c, parent); err != nil {
					return err
				}
				continue
			}
			t := &table{s: c, name: name, parent: parent, parentCol: c.Ext["parent-column"], position: c.Ext["position"]}
			if id, ok := c.Ext["singleton"]; ok {
				t.singleton, _ = strconv.ParseInt(id, 10, 64)
			}
			if t.parent != nil && t.parentCol == "" {
				return fmt.Errorf("%s: a table below %s needs px:parent-column", c.Path(), parent.name)
			}
			m.tables = append(m.tables, t)
			m.byList[c] = t
			if err := walk(c, t); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, nil); err != nil {
		return nil, err
	}
	for _, t := range m.tables {
		for _, c := range t.s.Children {
			switch {
			case c.State:
			case c.Kind == schema.Leaf || c.Kind == schema.LeafList:
				cl, err := m.column(c)
				if err != nil {
					return nil, err
				}
				t.cols = append(t.cols, cl)
			case c.Ext["json"] != "":
				t.jsons = append(t.jsons, &jsonCol{list: c, column: c.Ext["json"]})
			case c.Ext["json-map"] != "":
				t.jsons = append(t.jsons, &jsonCol{list: c, column: c.Ext["json-map"], isMap: true})
			}
		}
	}
	return m, nil
}

func (m *Mapping) column(s *schema.Node) (*col, error) {
	c := &col{leaf: s, column: strings.ReplaceAll(s.Name, "-", "_"), nullValue: s.Ext["null-value"]}
	_, c.nullable = s.Ext["nullable"]
	if s.Kind == schema.LeafList {
		c.kind = leafList
	}
	idCol, isID := s.Ext["column"]
	if !isID {
		return c, nil
	}
	c.column = idCol
	if ext, ok := s.Ext["external"]; ok {
		c.kind, c.external = external, ext
		return c, nil
	}
	var path string
	if refs := s.Type.Leafrefs(); len(refs) > 0 {
		path = refs[0]
	}
	tgt := datastore.LeafrefTarget(s, path)
	if tgt == nil || m.byList[tgt.Parent] == nil {
		return nil, fmt.Errorf("%s: px:column without a reference to a table's entry", s.Path())
	}
	c.kind, c.target = ref, m.byList[tgt.Parent]
	return c, nil
}

// Index maps a tree's entries (and the singleton containers) to their
// rows' ids.
type Index map[*datastore.Node]int64

// keyOf is the value a reference leaf takes for the entry tgt: the key
// its path ends at.
func keyOf(tgt *datastore.Node, leaf *schema.Node) string {
	parts := strings.Split(leaf.Type.Leafrefs()[0], "/")
	return tgt.Leaves[parts[len(parts)-1]]
}

func externalNames(db *gorm.DB, cache map[string]map[int64]string, tbl string) (map[int64]string, error) {
	if names, ok := cache[tbl]; ok {
		return names, nil
	}
	var rows []struct {
		ID   int64
		Name string
	}
	if err := db.Table(tbl).Select("id, name").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", tbl, err)
	}
	names := map[int64]string{}
	for _, r := range rows {
		names[r.ID] = r.Name
	}
	cache[tbl] = names
	return names, nil
}

// zero is a leaf's value when absent: its default, or its type's zero.
func zero(s *schema.Node) string {
	if s.HasDefault {
		return s.Default
	}
	switch {
	case s.Type.Kind == "boolean":
		return "false"
	case s.Type.Numeric():
		return "0"
	}
	return ""
}

// leafValue is a column's value as a leaf, and whether the leaf is set:
// a value that is the leaf's default (or zero) is left out, NULL too.
func leafValue(c *col, v any) (string, bool) {
	if v == nil {
		return "", false
	}
	var s string
	switch x := v.(type) {
	case bool:
		s = strconv.FormatBool(x)
	case int64:
		s = strconv.FormatInt(x, 10)
		if c.leaf.Type.Kind == "boolean" {
			s = strconv.FormatBool(x != 0)
		}
	case float64:
		s = strconv.FormatFloat(x, 'f', -1, 64)
	case []byte:
		s = string(x)
	case string:
		s = x
	case time.Time:
		s = x.UTC().Format(time.RFC3339)
	default:
		s = fmt.Sprint(x)
	}
	if c.leaf.Type.Kind == "boolean" {
		switch s {
		case "1":
			s = "true"
		case "0":
			s = "false"
		}
	}
	// An empty column is no value too, also where the leaf has a default:
	// the CRUD stored "" for the default of some.
	if !c.nullable && !c.leaf.IsKey() && !c.leaf.Mandatory && (s == zero(c.leaf) || s == "") {
		return "", false
	}
	return s, true
}

func listValue(v any) []string {
	var text string
	switch x := v.(type) {
	case string:
		text = x
	case []byte:
		text = string(x)
	default:
		return nil
	}
	var out []string
	if json.Unmarshal([]byte(text), &out) != nil {
		return nil
	}
	return out
}

func toInt(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	case bool:
		if x {
			return 1
		}
	case string:
		n, _ := strconv.ParseInt(x, 10, 64)
		return n
	case []byte:
		n, _ := strconv.ParseInt(string(x), 10, 64)
		return n
	}
	return 0
}

func readJSONColumn(n *datastore.Node, j *jsonCol, v any) error {
	var text string
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		text = x
	case []byte:
		text = string(x)
	}
	if j.isMap {
		var obj map[string]string
		if err := json.Unmarshal([]byte(text), &obj); err != nil {
			return err
		}
		for k, val := range obj {
			n.AddEntry(j.list, map[string]string{"name": k, "value": val})
		}
		return nil
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(text), &arr); err != nil {
		return err
	}
	for _, obj := range arr {
		leaves := map[string]string{}
		for _, c := range j.list.Children {
			v, ok := obj[strings.ReplaceAll(c.Name, "-", "_")]
			if !ok || v == nil {
				continue
			}
			s := fmt.Sprint(v)
			if f, isNum := v.(float64); isNum {
				s = strconv.FormatFloat(f, 'f', -1, 64)
			}
			_, nullable := c.Ext["nullable"]
			if !c.IsKey() && !nullable && s == zero(c) {
				continue
			}
			leaves[c.Name] = s
		}
		for _, k := range j.list.Keys {
			if _, ok := leaves[k]; !ok {
				leaves[k] = zero(j.list.Child(k))
			}
		}
		n.AddEntry(j.list, leaves)
	}
	return nil
}

func pathKey(root *schema.Node, n *datastore.Node) string {
	return datastore.PathOf(n).String(root)
}

// columns are the row of entry e (at pos in its list). Its references to
// other entries are 0 or NULL where those have no row yet, unless strict.
func (m *Mapping) columns(t *table, tree *datastore.Tree, e *datastore.Node, pos int, idx Index, ext map[string]map[string]int64, db *gorm.DB, strict bool) (map[string]any, error) {
	out := map[string]any{}
	if t.parent != nil {
		pid, ok := idx[parentEntry(e)]
		if !ok {
			return nil, fmt.Errorf("%s: its parent has no row", pathKey(m.root, e))
		}
		out[t.parentCol] = pid
	}
	if t.position != "" {
		out[t.position] = int64(pos)
	}
	for _, c := range t.cols {
		v, set := e.Leaves[c.leaf.Name]
		switch c.kind {
		case plain:
			out[c.column] = columnValue(c, v, set)
		case leafList:
			vs := e.LeafLists[c.leaf.Name]
			if vs == nil {
				vs = []string{}
			}
			b, _ := json.Marshal(vs)
			out[c.column] = string(b)
		case external:
			if !set {
				out[c.column] = nil
				continue
			}
			id, err := externalID(db, ext, c.external, v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", pathKey(m.root, e), err)
			}
			out[c.column] = id
		}
	}
	for _, j := range t.jsons {
		out[j.column] = jsonColumn(e, j)
	}
	r, err := m.refColumns(t, tree, e, idx, ext, db, strict)
	if err != nil {
		return nil, err
	}
	for k, v := range r {
		out[k] = v
	}
	return out, nil
}

// parentEntry is the entry or singleton above e that has a row.
func parentEntry(e *datastore.Node) *datastore.Node { return e.Parent }

// refColumns are the columns of e's references to other entries. Without
// strict, a reference to an entry without a row yet is NULL (or 0).
func (m *Mapping) refColumns(t *table, tree *datastore.Tree, e *datastore.Node, idx Index, ext map[string]map[string]int64, db *gorm.DB, strict bool) (map[string]any, error) {
	out := map[string]any{}
	for _, c := range t.cols {
		if c.kind != ref {
			continue
		}
		v, set := e.Leaves[c.leaf.Name]
		if !set || (c.nullValue != "" && v == c.nullValue) {
			out[c.column] = nil
			continue
		}
		tgt := tree.Referenced(e, c.leaf, v)
		if tgt == nil {
			return nil, fmt.Errorf("%s: %q doesn't name a %s", pathKey(m.root, e)+"/"+c.leaf.Name, v, c.target.s.Name)
		}
		id, ok := idx[tgt]
		if !ok {
			if strict {
				return nil, fmt.Errorf("%s: %s has no row", pathKey(m.root, e), pathKey(m.root, tgt))
			}
			id = 0
		}
		out[c.column] = id
	}
	return out, nil
}

func externalID(db *gorm.DB, cache map[string]map[string]int64, tbl, name string) (int64, error) {
	ids, ok := cache[tbl]
	if !ok {
		var rows []struct {
			ID   int64
			Name string
		}
		if err := db.Table(tbl).Select("id, name").Find(&rows).Error; err != nil {
			return 0, err
		}
		ids = map[string]int64{}
		for _, r := range rows {
			ids[r.Name] = r.ID
		}
		cache[tbl] = ids
	}
	id, ok := ids[name]
	if !ok {
		return 0, fmt.Errorf("there is no %s %q", strings.TrimSuffix(tbl, "s"), name)
	}
	return id, nil
}

// columnValue is a leaf's value for its column.
func columnValue(c *col, v string, set bool) any {
	if !set {
		if c.nullable {
			return nil
		}
		v = zero(c.leaf)
	}
	return typed(c.leaf, v)
}

func typed(s *schema.Node, v string) any {
	switch {
	case s.Type.Kind == "boolean":
		return v == "true"
	case s.Type.Numeric():
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return v
}

func jsonColumn(e *datastore.Node, j *jsonCol) string {
	es := e.Lists[j.list.Name]
	if j.isMap {
		obj := map[string]string{}
		for _, x := range es {
			obj[x.Leaves["name"]] = x.Leaves["value"]
		}
		b, _ := json.Marshal(obj)
		return string(b)
	}
	arr := make([]ordered, 0, len(es))
	for _, x := range es {
		obj := ordered{}
		for _, c := range j.list.Children {
			v, set := x.Leaves[c.Name]
			_, nullable := c.Ext["nullable"]
			if !set {
				if nullable {
					continue
				}
				v = zero(c)
			}
			obj = append(obj, kv{strings.ReplaceAll(c.Name, "-", "_"), typed(c, v)})
		}
		arr = append(arr, obj)
	}
	b, _ := json.Marshal(arr)
	return string(b)
}

type kv struct {
	k string
	v any
}

// ordered is a JSON object with its members in order.
type ordered []kv

func (o ordered) MarshalJSON() ([]byte, error) {
	var b strings.Builder
	b.WriteByte('{')
	for i, m := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(m.k)
		v, err := json.Marshal(m.v)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}

// Row is a table's row made from an entry: its columns by name.
type Row map[string]any

// Rows makes the rows of t: what the builder and the readers of the
// configuration read (package confview).
// Rows have the ids of ids (a list keyed by id has its own; an entry ids
// doesn't know gets one above them), references the ids of the rows they
// name, and names outside the tree (firewalls, roles) the ids db has for
// them.
func (m *Mapping) Rows(db *gorm.DB, tree *datastore.Tree, ids IDs) (map[string][]Row, Index, error) {
	idx := Index{}
	next := map[string]int64{}
	maps.Copy(next, ids.max)
	ext := map[string]map[string]int64{}
	out := map[string][]Row{}
	type entry struct {
		n   *datastore.Node
		t   *table
		row Row
	}
	var entries []entry
	// Ids first: a list keyed by id keeps its own, others theirs of ids,
	// and new ones count on from the largest of those.
	m.walkEntries(tree.Root, func(e *datastore.Node, t *table) {
		if t.singleton != 0 {
			idx[e] = t.singleton
			return
		}
		if v, ok := e.Leaves["id"]; ok && slices.Contains(t.s.Keys, "id") {
			idx[e] = toInt(v)
			next[t.name] = max(next[t.name], idx[e])
			return
		}
		if r, ok := ids.byPath[pathKey(m.root, e)]; ok && r.tbl == t.name {
			idx[e] = r.id
		}
	})
	var walk func(n *datastore.Node) error
	walk = func(n *datastore.Node) error {
		for _, s := range n.S.Children {
			if s.State {
				continue
			}
			t := m.byList[s]
			if t == nil {
				if c := n.Containers[s.Name]; c != nil && s.Kind == schema.Container {
					if err := walk(c); err != nil {
						return err
					}
				}
				continue
			}
			var nodes []*datastore.Node
			if t.singleton != 0 {
				nodes = []*datastore.Node{n.Containers[s.Name]}
			} else {
				nodes = n.Lists[s.Name]
			}
			for pos, e := range nodes {
				if _, ok := idx[e]; !ok {
					next[t.name]++
					idx[e] = next[t.name]
				}
				row, err := m.columns(t, tree, e, pos, idx, ext, db, false)
				if err != nil {
					return err
				}
				row["id"] = idx[e]
				entries = append(entries, entry{e, t, row})
				if err := walk(e); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(tree.Root); err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		refs, err := m.refColumns(e.t, tree, e.n, idx, ext, db, true)
		if err != nil {
			return nil, nil, err
		}
		for k, v := range refs {
			e.row[k] = v
		}
		out[e.t.name] = append(out[e.t.name], e.row)
	}
	return out, idx, nil
}

// Tables are the tables (lists of rows) the tree maps onto.
func (m *Mapping) Tables() []string {
	out := make([]string, len(m.tables))
	for i, t := range m.tables {
		out[i] = t.name
	}
	return out
}

// TableOf is the table of a list (or singleton container), "" for none.
func (m *Mapping) TableOf(s *schema.Node) string {
	if t := m.byList[s]; t != nil {
		return t.name
	}
	return ""
}

// Columns are the columns of the table's rows: its id, its parent's and
// position's, and those of its leaves and JSON lists; of every list that
// maps onto it (a virtual firewall's DNS templates and the firewall's).
func (m *Mapping) Columns(tbl string) []string {
	var out []string
	add := func(c string) {
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	for _, t := range m.tables {
		if t.name != tbl {
			continue
		}
		add("id")
		if t.parentCol != "" {
			add(t.parentCol)
		}
		if t.position != "" {
			add(t.position)
		}
		for _, c := range t.cols {
			add(c.column)
		}
		for _, j := range t.jsons {
			add(j.column)
		}
	}
	return out
}
