// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package sqlmap reads the configuration tree from portitor-config's
// SQLite tables and writes it back, as the px: extensions of the YANG
// modules map them: a list is a table (px:table), its entries rows under
// their parent's row (px:parent-column), in order (px:position); a leaf
// is a column of its name, or of a row id (px:column) of the entry a
// leafref names; a nested list is a JSON column (px:json). It goes when
// the tables do (dev/design-model-driven.md).
//
// Write keeps row ids: an entry at the same path keeps its row, so rules
// keep the ids their connections are marked with.
package sqlmap

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
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
	ref      // a row id of the entry a leafref or px:global-ref names
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
	path := s.Ext["global-ref"]
	if path == "" {
		if refs := s.Type.Leafrefs(); len(refs) > 0 {
			path = refs[0]
		}
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

// Import reads the configuration from the tables.
func (m *Mapping) Import(db *gorm.DB) (*datastore.Tree, Index, error) {
	tree := datastore.New(m.root)
	idx := Index{}
	byID := map[*table]map[int64]*datastore.Node{}
	ext := map[string]map[int64]string{}
	type pending struct {
		n  *datastore.Node
		c  *col
		id int64
	}
	var deferred []pending
	for _, t := range m.tables {
		byID[t] = map[int64]*datastore.Node{}
		order := "id"
		if t.position != "" {
			order = quote(t.position) + ", id"
		}
		var rows []map[string]any
		if err := db.Table(t.name).Order(order).Find(&rows).Error; err != nil {
			return nil, nil, fmt.Errorf("%s: %w", t.name, err)
		}
		for _, row := range rows {
			id := toInt(row["id"])
			parent := tree.Root
			if t.parent != nil {
				if parent = byID[t.parent][toInt(row[t.parentCol])]; parent == nil {
					continue // an orphan; foreign keys keep there being none
				}
			}
			leaves := map[string]string{}
			var refs []pending
			for _, c := range t.cols {
				v := row[c.column]
				switch c.kind {
				case plain:
					if s, ok := leafValue(c, v); ok {
						leaves[c.leaf.Name] = s
					}
				case external:
					if v == nil {
						continue
					}
					names, err := externalNames(db, ext, c.external)
					if err != nil {
						return nil, nil, err
					}
					if name, ok := names[toInt(v)]; ok {
						leaves[c.leaf.Name] = name
					}
				case ref:
					if v == nil {
						if c.nullValue != "" {
							leaves[c.leaf.Name] = c.nullValue
						}
						continue
					}
					refs = append(refs, pending{c: c, id: toInt(v)})
				}
			}
			// Keys that are references resolve now: their targets'
			// tables come first.
			for _, r := range refs {
				if !r.c.leaf.IsKey() {
					continue
				}
				tgt := byID[r.c.target][r.id]
				if tgt == nil {
					return nil, nil, fmt.Errorf("%s %d: %s names row %d of %s, which is missing", t.name, id, r.c.column, r.id, r.c.target.name)
				}
				leaves[r.c.leaf.Name] = keyOf(tgt, r.c.leaf)
			}
			var n *datastore.Node
			if t.singleton != 0 {
				if id != t.singleton {
					continue
				}
				n = parent.AddContainer(t.s)
				for k, v := range leaves {
					n.Leaves[k] = v
				}
			} else {
				n = parent.AddEntry(t.s, leaves)
			}
			for _, c := range t.cols {
				if c.kind == leafList {
					if vs := listValue(row[c.column]); len(vs) > 0 {
						n.LeafLists[c.leaf.Name] = vs
					}
				}
			}
			for _, j := range t.jsons {
				if err := readJSONColumn(n, j, row[j.column]); err != nil {
					return nil, nil, fmt.Errorf("%s %d: %s: %w", t.name, id, j.column, err)
				}
			}
			for _, r := range refs {
				if !r.c.leaf.IsKey() {
					deferred = append(deferred, pending{n: n, c: r.c, id: r.id})
				}
			}
			idx[n] = id
			byID[t][id] = n
		}
	}
	for _, d := range deferred {
		if tgt := byID[d.c.target][d.id]; tgt != nil {
			d.n.Leaves[d.c.leaf.Name] = keyOf(tgt, d.c.leaf)
		}
	}
	return tree, idx, nil
}

// keyOf is the value a reference leaf takes for the entry tgt: the key
// its path ends at.
func keyOf(tgt *datastore.Node, leaf *schema.Node) string {
	path := leaf.Ext["global-ref"]
	if path == "" {
		path = leaf.Type.Leafrefs()[0]
	}
	parts := strings.Split(path, "/")
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
	if !c.nullable && !c.leaf.IsKey() && !c.leaf.Mandatory && s == zero(c.leaf) {
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

// Write makes the tables hold t: rows updated where their entry's columns
// changed, inserted for new entries and deleted for those gone. Run it in
// a transaction; it defers the foreign keys to its commit.
func (m *Mapping) Write(tx *gorm.DB, tree *datastore.Tree) error {
	if err := tx.Exec("PRAGMA defer_foreign_keys = ON").Error; err != nil {
		return err
	}
	old, oldIdx, err := m.Import(tx)
	if err != nil {
		return err
	}
	oldByPath := map[string]*datastore.Node{}
	for n := range oldIdx {
		oldByPath[pathKey(m.root, n)] = n
	}
	ext := map[string]map[string]int64{}
	newIdx := Index{}
	type entry struct {
		n       *datastore.Node
		t       *table
		written map[string]any
	}
	var entries []entry
	var walk func(n *datastore.Node) error
	walk = func(n *datastore.Node) error {
		for _, s := range n.S.Children {
			t := m.byList[s]
			if t == nil {
				if s.Kind == schema.Container {
					if c := n.Containers[s.Name]; c != nil {
						if err := walk(c); err != nil {
							return err
						}
					}
				}
				continue
			}
			var nodes []*datastore.Node
			if t.singleton != 0 {
				c := n.Containers[s.Name]
				if c == nil {
					c = n.AddContainer(s)
				}
				nodes = []*datastore.Node{c}
			} else {
				nodes = n.Lists[s.Name]
			}
			for pos, e := range nodes {
				cols, err := m.columns(t, tree, e, pos, newIdx, ext, tx, false)
				if err != nil {
					return err
				}
				if oe := oldByPath[pathKey(m.root, e)]; oe != nil {
					id := oldIdx[oe]
					newIdx[e] = id
					prev, err := m.columns(t, old, oe, position(oe), oldIdx, ext, tx, true)
					if err != nil {
						return err
					}
					if err := update(tx, t.name, id, cols, prev); err != nil {
						return err
					}
					delete(oldByPath, pathKey(m.root, e))
				} else {
					if t.singleton != 0 {
						return fmt.Errorf("%s: row %d is missing", t.name, t.singleton)
					}
					id, err := insert(tx, t.name, cols)
					if err != nil {
						return err
					}
					newIdx[e] = id
				}
				entries = append(entries, entry{e, t, cols})
				if err := walk(e); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(tree.Root); err != nil {
		return err
	}
	// The references to entries inserted above, now that they have ids.
	for _, e := range entries {
		refs, err := m.refColumns(e.t, tree, e.n, newIdx, ext, tx, true)
		if err != nil {
			return err
		}
		if err := update(tx, e.t.name, newIdx[e.n], refs, e.written); err != nil {
			return err
		}
	}
	// What is gone, children before parents.
	gone := make([]*datastore.Node, 0, len(oldByPath))
	for _, n := range oldByPath {
		gone = append(gone, n)
	}
	sort.Slice(gone, func(i, j int) bool { return depth(gone[i]) > depth(gone[j]) })
	for _, n := range gone {
		if err := tx.Exec("DELETE FROM "+quote(m.byList[n.S].name)+" WHERE id = ?", oldIdx[n]).Error; err != nil {
			return fmt.Errorf("%s: deleting %s: %w", m.byList[n.S].name, pathKey(m.root, n), err)
		}
	}
	return nil
}

func position(e *datastore.Node) int {
	if e.Parent == nil {
		return 0
	}
	return slices.Index(e.Parent.Lists[e.S.Name], e)
}

func depth(n *datastore.Node) int {
	d := 0
	for x := n; x.Parent != nil; x = x.Parent {
		d++
	}
	return d
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

func quote(ident string) string { return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"` }

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func insert(tx *gorm.DB, tbl string, cols map[string]any) (int64, error) {
	ks := sortedKeys(cols)
	names := make([]string, len(ks))
	args := make([]any, len(ks))
	for i, k := range ks {
		names[i], args[i] = quote(k), cols[k]
	}
	q := "INSERT INTO " + quote(tbl) + " (" + strings.Join(names, ", ") + ") VALUES (" + strings.TrimSuffix(strings.Repeat("?, ", len(ks)), ", ") + ")"
	if err := tx.Exec(q, args...).Error; err != nil {
		return 0, fmt.Errorf("%s: %w", tbl, err)
	}
	if id, ok := cols["id"]; ok {
		return toInt(id), nil
	}
	var id int64
	if err := tx.Raw("SELECT last_insert_rowid()").Scan(&id).Error; err != nil {
		return 0, err
	}
	return id, nil
}

// update writes the columns of cols that differ from prev.
func update(tx *gorm.DB, tbl string, id int64, cols, prev map[string]any) error {
	var sets []string
	var args []any
	for _, k := range sortedKeys(cols) {
		if p, ok := prev[k]; ok && reflect.DeepEqual(p, cols[k]) {
			continue
		}
		sets = append(sets, quote(k)+" = ?")
		args = append(args, cols[k])
	}
	if len(sets) == 0 {
		return nil
	}
	sets = append(sets, `"updated_at" = ?`)
	args = append(args, time.Now().UTC())
	args = append(args, id)
	if err := tx.Exec("UPDATE "+quote(tbl)+" SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...).Error; err != nil {
		return fmt.Errorf("%s %d: %w", tbl, id, err)
	}
	return nil
}

// Row is a table's row made from an entry: its columns by name.
type Row map[string]any

// Rows makes the tables' rows from t, without a database: what the
// builder reads. Rows get ids of their own (a list keyed by id keeps its
// id), references the ids of the rows they name, and names outside the
// tree (firewalls, roles) the ids db has for them.
func (m *Mapping) Rows(db *gorm.DB, tree *datastore.Tree) (map[string][]Row, Index, error) {
	idx := Index{}
	next := map[string]int64{}
	ext := map[string]map[string]int64{}
	out := map[string][]Row{}
	type entry struct {
		n   *datastore.Node
		t   *table
		row Row
	}
	var entries []entry
	// Ids first: a list keyed by id keeps its own, others count on from
	// the largest of those.
	var assign func(n *datastore.Node)
	used := map[string]map[int64]bool{}
	assign = func(n *datastore.Node) {
		for _, s := range n.S.Children {
			if s.State {
				continue
			}
			t := m.byList[s]
			if t == nil {
				if c := n.Containers[s.Name]; c != nil && s.Kind == schema.Container {
					assign(c)
				}
				continue
			}
			if used[t.name] == nil {
				used[t.name] = map[int64]bool{}
			}
			if t.singleton != 0 {
				c := n.Containers[s.Name]
				if c == nil {
					c = n.AddContainer(s)
				}
				idx[c] = t.singleton
				continue
			}
			for _, e := range n.Lists[s.Name] {
				if v, ok := e.Leaves["id"]; ok && slices.Contains(t.s.Keys, "id") {
					id := toInt(v)
					idx[e] = id
					used[t.name][id] = true
					next[t.name] = max(next[t.name], id)
				}
				assign(e)
			}
		}
	}
	assign(tree.Root)
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

// Tables are the tables the tree maps onto.
func (m *Mapping) Tables() []string {
	out := make([]string, len(m.tables))
	for i, t := range m.tables {
		out[i] = t.name
	}
	return out
}
