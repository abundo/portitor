// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlmap

import (
	"fmt"
	"slices"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/datastore"
)

// The tables are gone (migration 94), but a database made by a release
// before them still has its configuration in them: migration 94 reads it
// with Import before it drops them, and SeedIDs keeps the entries' ids.

// quote is ident as a quoted SQL identifier.
func quote(ident string) string { return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"` }

// Import reads the configuration from the tables.
func (m *Mapping) Import(db *gorm.DB) (*datastore.Tree, Index, error) {
	tree := datastore.New(m.root)
	idx := Index{}
	// By table name: a top-level list and one below an instance may share
	// a table, and a reference names either.
	byID := map[string]map[int64]*datastore.Node{}
	ext := map[string]map[int64]string{}
	type pending struct {
		n  *datastore.Node
		c  *col
		id int64
	}
	var deferred []pending
	// A table that a top-level list and a list below an instance share (the
	// DNS templates) holds the firewall's templates, which every instance
	// may use, in the top-level list: the rows an instance marked global,
	// or that no instance owns; the other rows are the instances' own.
	twin := map[*table]string{} // top-level list -> the other's parent column
	nested := map[*table]bool{}
	for _, t := range m.tables {
		for _, u := range m.tables {
			if t.parent == nil && u.parent != nil && t.name == u.name {
				twin[t] = u.parentCol
				nested[u] = true
			}
		}
	}
	for _, t := range m.tables {
		if byID[t.name] == nil {
			byID[t.name] = map[int64]*datastore.Node{}
		}
		order := "id"
		if t.position != "" {
			order = quote(t.position) + ", id"
		}
		var rows []map[string]any
		q := db.Table(t.name)
		global := db.Migrator().HasColumn(t.name, "global")
		if col, ok := twin[t]; ok {
			cond := quote(col) + " = 0 OR " + quote(col) + " IS NULL"
			if global {
				cond += " OR global"
			}
			q = q.Where(cond)
		} else if nested[t] && global {
			q = q.Where("NOT global")
		}
		if err := q.Order(order).Find(&rows).Error; err != nil {
			return nil, nil, fmt.Errorf("%s: %w", t.name, err)
		}
		for _, row := range rows {
			id := toInt(row["id"])
			parent := tree.Root
			if t.parent != nil {
				if parent = byID[t.parent.name][toInt(row[t.parentCol])]; parent == nil {
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
				tgt := byID[r.c.target.name][r.id]
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
			byID[t.name][id] = n
		}
	}
	for _, d := range deferred {
		if tgt := byID[d.c.target.name][d.id]; tgt != nil {
			d.n.Leaves[d.c.leaf.Name] = keyOf(tgt, d.c.leaf)
		}
	}
	return tree, idx, nil
}

// SeedIDs keeps the row ids of idx (what Import returned for tree) as the
// entries' ids in config_ids, the way AssignIDs would have: by path, for
// every entry that has no id of its own in its key. tx is the database
// that has the table.
func (m *Mapping) SeedIDs(tx *gorm.DB, tree *datastore.Tree, idx Index) error {
	var err error
	m.walkEntries(tree.Root, func(e *datastore.Node, t *table) {
		if err != nil || t.singleton != 0 {
			return
		}
		id, ok := idx[e]
		if !ok {
			return
		}
		if _, own := e.Leaves["id"]; own && slices.Contains(t.s.Keys, "id") {
			return
		}
		if xerr := tx.Exec("INSERT INTO config_ids (path, tbl, id) VALUES (?, ?, ?) ON CONFLICT (path) DO UPDATE SET tbl = excluded.tbl, id = excluded.id",
			pathKey(m.root, e), t.name, id).Error; xerr != nil {
			err = fmt.Errorf("config_ids: %w", xerr)
		}
	})
	return err
}

// HighWater is the highest id each list keyed by a numeric id (rules, NAT
// rules, routes, ...) has had in db, by the list's path: the marks of
// ids.json, so an id a deleted entry had is not given again (a rule's id
// marks its connections). Lists without such a table are left out.
func (m *Mapping) HighWater(db *gorm.DB) (map[string]uint64, error) {
	marks := map[string]uint64{}
	if !db.Migrator().HasTable("sqlite_sequence") {
		return marks, nil
	}
	for _, t := range m.tables {
		if t.singleton != 0 || len(t.s.Keys) != 1 || t.s.Keys[0] != "id" {
			continue
		}
		var seq uint64
		if err := db.Raw("SELECT COALESCE(MAX(seq), 0) FROM sqlite_sequence WHERE name = ?", t.name).Scan(&seq).Error; err != nil {
			return nil, err
		}
		if seq > 0 {
			marks[t.s.Path()] = seq
		}
	}
	return marks, nil
}
