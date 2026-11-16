// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlmap

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

// IDs are the entries' ids by path (the table config_ids), as the API,
// the GUI and the builder know them: an entry keeps its id across edits
// and renames, and an id is never another entry's. A list keyed by id
// (rules) has its own in its key and is not kept here.
type IDs struct {
	byPath map[string]idRow
	max    map[string]int64 // by table
}

type idRow struct {
	tbl string
	id  int64
}

// NewIDs is no ids kept yet.
func NewIDs() IDs { return IDs{byPath: map[string]idRow{}, max: map[string]int64{}} }

// Set keeps id for the entry at path, of the table tbl.
func (ids IDs) Set(path, tbl string, id int64) {
	ids.byPath[path] = idRow{tbl, id}
	ids.max[tbl] = max(ids.max[tbl], id)
}

// Each calls fn for every path of the ids that starts with prefix, with its
// table and id.
func (ids IDs) Each(prefix string, fn func(path, tbl string, id int64)) {
	for p, r := range ids.byPath {
		if strings.HasPrefix(p, prefix) {
			fn(p, r.tbl, r.id)
		}
	}
}

// Delete forgets the id kept for a path (the highest id each table gave stays).
func (ids IDs) Delete(path string) { delete(ids.byPath, path) }

// KeepHigher raises the highest id each table gave to o's where that is
// higher: ids taken from a copy (a restore) never give an id this
// installation gave since.
func (ids IDs) KeepHigher(o IDs) {
	for tbl, n := range o.max {
		ids.max[tbl] = max(ids.max[tbl], n)
	}
}

// Clone is a copy of the ids, which Set may change.
func (ids IDs) Clone() IDs { return ids.clone() }

func (ids IDs) clone() IDs {
	return IDs{byPath: maps.Clone(ids.byPath), max: maps.Clone(ids.max)}
}

// idsFile is IDs as JSON: the version of the format, and each path's
// table and id.
type idsFile struct {
	Version int               `json:"version"`
	Paths   map[string][2]any `json:"paths"`
}

// MarshalJSON writes the ids in a stable order.
func (ids IDs) MarshalJSON() ([]byte, error) {
	f := idsFile{Version: 1, Paths: make(map[string][2]any, len(ids.byPath))}
	for p, r := range ids.byPath {
		f.Paths[p] = [2]any{r.tbl, r.id}
	}
	return json.Marshal(f)
}

// UnmarshalJSON reads what MarshalJSON wrote.
func (ids *IDs) UnmarshalJSON(b []byte) error {
	var f struct {
		Version int                           `json:"version"`
		Paths   map[string][2]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	if f.Version != 1 {
		return fmt.Errorf("ids: unsupported version %d", f.Version)
	}
	*ids = NewIDs()
	for p, r := range f.Paths {
		var tbl string
		var id int64
		if err := json.Unmarshal(r[0], &tbl); err != nil {
			return fmt.Errorf("ids: %s: %w", p, err)
		}
		if err := json.Unmarshal(r[1], &id); err != nil {
			return fmt.Errorf("ids: %s: %w", p, err)
		}
		ids.Set(p, tbl, id)
	}
	return nil
}

// Equal tells whether both keep the same ids.
func (ids IDs) Equal(o IDs) bool { return maps.Equal(ids.byPath, o.byPath) }

// ID is the id kept for the entry at path.
func (ids IDs) ID(path string) (int64, bool) {
	r, ok := ids.byPath[path]
	return r.id, ok
}

// PlanIDs gives every entry of tree that has none an id, and moves those of
// the entries tree.Renamed lists along with them: the ids afterwards (ids is
// not changed), and the index of the tree's entries by id. It is pure; what
// keeps the ids is the caller's. An entry deleted keeps its id, so one made
// again at the same path gets it back, and no other entry ever gets it.
func (m *Mapping) PlanIDs(ids IDs, tree *datastore.Tree) (IDs, Index) {
	ids = ids.clone()
	for _, r := range tree.Renamed {
		from := r.Path.String(m.root)
		to := slices.Clone(r.Path)
		to[len(to)-1] = datastore.Elem{Name: to[len(to)-1].Name, Keys: r.Keys}
		toKey := to.String(m.root)
		// What was at the new path (deleted since) gives way.
		for k := range ids.byPath {
			if k == toKey || strings.HasPrefix(k, toKey+"/") {
				delete(ids.byPath, k)
			}
		}
		moved := map[string]idRow{}
		for k, row := range ids.byPath {
			if k == from || strings.HasPrefix(k, from+"/") {
				moved[toKey+strings.TrimPrefix(k, from)] = row
				delete(ids.byPath, k)
			}
		}
		maps.Copy(ids.byPath, moved)
	}
	idx := Index{}
	m.walkEntries(tree.Root, func(e *datastore.Node, t *table) {
		if t.singleton != 0 {
			idx[e] = t.singleton
			return
		}
		if v, ok := e.Leaves["id"]; ok && slices.Contains(t.s.Keys, "id") {
			idx[e] = toInt(v)
			return
		}
		p := pathKey(m.root, e)
		if r, ok := ids.byPath[p]; ok && r.tbl == t.name {
			idx[e] = r.id
			return
		}
		ids.max[t.name]++
		r := idRow{t.name, ids.max[t.name]}
		ids.byPath[p] = r
		idx[e] = r.id
	})
	return ids, idx
}

// UndoRenames moves the ids back that PlanIDs moved for the renames: a rename
// made to the candidate that the commit then refused (what is put back is the
// entries, so their ids go back too).
func (m *Mapping) UndoRenames(ids IDs, renamed []datastore.Renamed) {
	for i := len(renamed) - 1; i >= 0; i-- {
		r := renamed[i]
		from := r.Path.String(m.root)
		to := slices.Clone(r.Path)
		to[len(to)-1] = datastore.Elem{Name: to[len(to)-1].Name, Keys: r.Keys}
		toKey := to.String(m.root)
		moved := map[string]idRow{}
		for k, row := range ids.byPath {
			if k == toKey || strings.HasPrefix(k, toKey+"/") {
				moved[from+strings.TrimPrefix(k, toKey)] = row
				delete(ids.byPath, k)
			}
		}
		maps.Copy(ids.byPath, moved)
	}
}

// walkEntries calls fn for every entry of n (and below) that is a row:
// the entries of mapped lists and the singleton containers, parents
// first. State is skipped.
func (m *Mapping) walkEntries(n *datastore.Node, fn func(e *datastore.Node, t *table)) {
	if n.Parent == nil && m.rootTable != nil {
		fn(n, m.rootTable)
	}
	for _, s := range n.S.Children {
		if s.State {
			continue
		}
		t := m.byList[s]
		if t == nil {
			if c := n.Containers[s.Name]; c != nil && s.Kind == schema.Container {
				m.walkEntries(c, fn)
			}
			continue
		}
		if t.singleton != 0 {
			c := n.Containers[s.Name]
			if c == nil {
				c = n.AddContainer(s)
			}
			fn(c, t)
			m.walkEntries(c, fn)
			continue
		}
		for _, e := range n.Lists[s.Name] {
			fn(e, t)
			m.walkEntries(e, fn)
		}
	}
}
