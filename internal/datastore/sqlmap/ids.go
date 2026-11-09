// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlmap

import (
	"maps"
	"slices"
	"strings"

	"gorm.io/gorm"

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

// LoadIDs reads the ids kept in db; none when it has no table for them.
func LoadIDs(db *gorm.DB) (IDs, error) {
	ids := IDs{byPath: map[string]idRow{}, max: map[string]int64{}}
	if db == nil || !db.Migrator().HasTable("config_ids") {
		return ids, nil
	}
	var rows []struct {
		Path string
		Tbl  string
		ID   int64
	}
	if err := db.Table("config_ids").Select("path, tbl, id").Find(&rows).Error; err != nil {
		return ids, err
	}
	for _, r := range rows {
		ids.byPath[r.Path] = idRow{r.Tbl, r.ID}
		ids.max[r.Tbl] = max(ids.max[r.Tbl], r.ID)
	}
	return ids, nil
}

// ID is the id kept for the entry at path.
func (ids IDs) ID(path string) (int64, bool) {
	r, ok := ids.byPath[path]
	return r.id, ok
}

// AssignIDs gives every entry of tree that has none an id, moves those of
// the entries tree.Renamed lists along with them, and keeps them in db (a
// transaction). An entry deleted keeps its row, so one made again at the
// same path gets its id back, and no other entry ever gets it.
func (m *Mapping) AssignIDs(tx *gorm.DB, tree *datastore.Tree) (Index, error) {
	ids, err := LoadIDs(tx)
	if err != nil {
		return nil, err
	}
	changed := map[string]idRow{}
	var gone []string
	for _, r := range tree.Renamed {
		from := r.Path.String(m.root)
		to := slices.Clone(r.Path)
		to[len(to)-1] = datastore.Elem{Name: to[len(to)-1].Name, Keys: r.Keys}
		toKey := to.String(m.root)
		// What was at the new path (deleted since) gives way.
		for k := range ids.byPath {
			if k == toKey || strings.HasPrefix(k, toKey+"/") {
				delete(ids.byPath, k)
				gone = append(gone, k)
			}
		}
		moved := map[string]idRow{}
		for k, row := range ids.byPath {
			if k == from || strings.HasPrefix(k, from+"/") {
				moved[toKey+strings.TrimPrefix(k, from)] = row
				delete(ids.byPath, k)
				gone = append(gone, k)
			}
		}
		maps.Copy(ids.byPath, moved)
		maps.Copy(changed, moved)
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
		changed[p] = r
		idx[e] = r.id
	})
	if len(gone) > 0 {
		for chunk := range slices.Chunk(gone, 500) {
			if err := tx.Exec("DELETE FROM config_ids WHERE path IN ?", chunk).Error; err != nil {
				return nil, err
			}
		}
	}
	for _, p := range slices.Sorted(maps.Keys(changed)) {
		r := changed[p]
		if err := tx.Exec("INSERT INTO config_ids (path, tbl, id) VALUES (?, ?, ?) ON CONFLICT (path) DO UPDATE SET tbl = excluded.tbl, id = excluded.id", p, r.tbl, r.id).Error; err != nil {
			return nil, err
		}
	}
	return idx, nil
}

// walkEntries calls fn for every entry of n (and below) that is a row:
// the entries of mapped lists and the singleton containers, parents
// first. State is skipped.
func (m *Mapping) walkEntries(n *datastore.Node, fn func(e *datastore.Node, t *table)) {
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

// RenameExternal makes the leaves of tree that name the row old of table
// (px:external: a firewall, a role) name new; it reports whether any did.
func (m *Mapping) RenameExternal(tree *datastore.Tree, tbl, old, new string) bool {
	changed := false
	m.walkEntries(tree.Root, func(e *datastore.Node, t *table) {
		for _, c := range t.cols {
			if c.kind == external && c.external == tbl && e.Leaves[c.leaf.Name] == old {
				e.Leaves[c.leaf.Name] = new
				changed = true
			}
		}
	})
	return changed
}

// NamesExternal reports whether a leaf of tree names the row name of
// table (px:external), and where: the path of the first.
func (m *Mapping) NamesExternal(tree *datastore.Tree, tbl, name string) (string, bool) {
	where := ""
	m.walkEntries(tree.Root, func(e *datastore.Node, t *table) {
		for _, c := range t.cols {
			if where == "" && c.kind == external && c.external == tbl && e.Leaves[c.leaf.Name] == name {
				where = pathKey(m.root, e)
			}
		}
	})
	return where, where != ""
}
