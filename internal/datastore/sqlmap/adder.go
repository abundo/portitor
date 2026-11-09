// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlmap

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

// Adder adds entries to a tree from rows, as the models give them
// (confview.RowOf): what code that makes configuration as rows (an
// import) writes the tree with.
type Adder struct {
	m    *Mapping
	db   *gorm.DB
	tree *datastore.Tree
	byID map[*table]map[int64]*datastore.Node
	idx  Index
	ext  map[string]map[int64]string
}

// NewAdder adds to tree, whose entries have the ids of idx (confview).
func (m *Mapping) NewAdder(db *gorm.DB, tree *datastore.Tree, idx Index) *Adder {
	a := &Adder{m: m, db: db, tree: tree, byID: map[*table]map[int64]*datastore.Node{}, idx: Index{}, ext: map[string]map[int64]string{}}
	for n, id := range idx {
		a.index(n, id)
	}
	return a
}

func (a *Adder) index(n *datastore.Node, id int64) {
	t := a.m.byList[n.S]
	if t == nil {
		return
	}
	if a.byID[t] == nil {
		a.byID[t] = map[int64]*datastore.Node{}
	}
	a.byID[t][id] = n
	a.idx[n] = id
}

// Node is the entry of the table's row id, nil when there is none.
func (a *Adder) Node(tbl string, id int64) *datastore.Node {
	for t, ids := range a.byID {
		if t.name == tbl {
			return ids[id]
		}
	}
	return nil
}

// Add adds the entry of row, a row of the table tbl: under the entry its
// parent column names, its references the entries of the ids they hold,
// its names outside the tree (firewalls, roles) by db's ids. A row with
// an id (one made up, for a new entry) can be named by the rows added
// after it. An entry that is there already is an error.
func (a *Adder) Add(tbl string, row Row) (*datastore.Node, error) {
	var t *table
	for _, x := range a.m.tables {
		if x.name == tbl {
			t = x
		}
	}
	if t == nil {
		return nil, fmt.Errorf("%s is not a table of the configuration", tbl)
	}
	parent := a.tree.Root
	if t.parent != nil {
		pid := toInt(row[t.parentCol])
		if parent = a.byID[t.parent][pid]; parent == nil {
			return nil, fmt.Errorf("%s: %s %d is not there", tbl, t.parentCol, pid)
		}
	}
	leaves := map[string]string{}
	for _, c := range t.cols {
		v := row[c.column]
		switch c.kind {
		case plain:
			if s, ok := leafValue(c, v); ok {
				leaves[c.leaf.Name] = s
			}
		case external:
			if v == nil || toInt(v) == 0 {
				continue
			}
			names, err := externalNames(a.db, a.ext, c.external)
			if err != nil {
				return nil, err
			}
			name, ok := names[toInt(v)]
			if !ok {
				return nil, fmt.Errorf("%s: no %s %d", tbl, c.external, toInt(v))
			}
			leaves[c.leaf.Name] = name
		case ref:
			if v == nil || toInt(v) == 0 {
				if c.nullValue != "" {
					leaves[c.leaf.Name] = c.nullValue
				}
				continue
			}
			tgt := a.byID[c.target][toInt(v)]
			if tgt == nil {
				return nil, fmt.Errorf("%s: %s names %s %d, which is not there", tbl, c.column, c.target.name, toInt(v))
			}
			leaves[c.leaf.Name] = keyOf(tgt, c.leaf)
		}
	}
	var n *datastore.Node
	if t.singleton != 0 {
		if n = parent.Containers[t.s.Name]; n == nil {
			n = parent.AddContainer(t.s)
		}
		for k, v := range leaves {
			n.Leaves[k] = v
		}
	} else {
		keys := make([]string, len(t.s.Keys))
		for i, k := range t.s.Keys {
			keys[i] = leaves[k]
		}
		if parent.Entry(t.s.Name, keys) != nil {
			return nil, &datastore.Error{Path: datastore.PathOf(parent).String(a.m.root) + "/" + t.s.Name, Msg: fmt.Sprintf("%v exists", keys)}
		}
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
			return nil, fmt.Errorf("%s: %s: %w", tbl, j.column, err)
		}
	}
	if id := toInt(row["id"]); id != 0 {
		a.index(n, id)
	}
	return n, nil
}

// List is the list whose entries are the table's rows, nil for none.
func (a *Adder) List(tbl string) *schema.Node {
	for _, t := range a.m.tables {
		if t.name == tbl && t.singleton == 0 {
			return t.s
		}
	}
	return nil
}
