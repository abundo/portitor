// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlmap

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

// Adder adds entries to a tree from rows, as the models give them
// (confview.RowOf): what code that makes configuration as rows (an
// import) writes the tree with.
type Adder struct {
	m    *Mapping
	tree *datastore.Tree
	byID map[*table]map[int64]*datastore.Node
	idx  Index
	pos  map[*datastore.Node]int64 // the position column of the entries added
}

// NewAdder adds to tree, whose entries have the ids of idx (confview).
func (m *Mapping) NewAdder(tree *datastore.Tree, idx Index) *Adder {
	a := &Adder{m: m, tree: tree, byID: map[*table]map[int64]*datastore.Node{}, idx: Index{}, pos: map[*datastore.Node]int64{}}
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

// Node is the entry of the table's row id, nil when there is none (of
// any list the table's rows are: ids are unique per table).
func (a *Adder) Node(tbl string, id int64) *datastore.Node {
	for t, ids := range a.byID {
		if n := ids[id]; t.name == tbl && n != nil {
			return n
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
	// Lists may share a table (the host's interfaces at the top level and
	// a virtual firewall's; a virtual firewall's DNS templates and the
	// firewall's): the one whose parent has the row's parent id, or, for
	// a row without one (0), the list of no parent.
	if rt := a.m.rootTable; rt != nil && rt.name == tbl && row["is_default"] == true {
		// The top level's row (confview gives it is_default): its leaves.
		if err := a.Update(a.tree.Root, row); err != nil {
			return nil, err
		}
		if id := toInt(row["id"]); id != 0 {
			a.index(a.tree.Root, id)
		}
		return a.tree.Root, nil
	}
	t := a.tableFor(tbl, row)
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
	leaves, err := a.leavesOf(t, tbl, row)
	if err != nil {
		return nil, err
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
		// In an ordered list, after the entries of a lower or the same
		// position (those there before count as lower).
		if t.position != "" {
			a.pos[n] = toInt(row[t.position])
			list := parent.Lists[t.s.Name]
			slices.SortStableFunc(list, func(x, y *datastore.Node) int {
				px, okx := a.pos[x]
				py, oky := a.pos[y]
				switch {
				case !okx && !oky:
					return 0
				case !okx:
					return -1
				case !oky:
					return 1
				}
				return cmp.Compare(px, py)
			})
		}
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

// leavesOf are the leaves of the entry a row of the table t makes.
func (a *Adder) leavesOf(t *table, tbl string, row Row) (map[string]string, error) {
	leaves := map[string]string{}
	for _, c := range t.cols {
		v := row[c.column]
		switch c.kind {
		case plain:
			if s, ok := leafValue(c, v); ok {
				leaves[c.leaf.Name] = s
			}
		case ref:
			if v == nil || toInt(v) == 0 {
				if c.nullValue != "" {
					leaves[c.leaf.Name] = c.nullValue
				}
				continue
			}
			tgt := a.Node(c.target.name, toInt(v))
			if tgt == nil {
				return nil, fmt.Errorf("%s: %s names %s %d, which is not there", tbl, c.column, c.target.name, toInt(v))
			}
			leaves[c.leaf.Name] = keyOf(tgt, c.leaf)
		}
	}
	return leaves, nil
}

// Update makes the leaves and leaf-lists of the existing entry n those of
// row (of n's table), keys included: rename the entry first (Tree.Rename,
// which rewrites what names it).
func (a *Adder) Update(n *datastore.Node, row Row) error {
	t := a.m.byList[n.S]
	if t == nil {
		return fmt.Errorf("%s is not a list of the configuration", n.S.Name)
	}
	leaves, err := a.leavesOf(t, t.name, row)
	if err != nil {
		return err
	}
	n.Leaves = leaves
	for _, c := range t.cols {
		if c.kind == leafList {
			delete(n.LeafLists, c.leaf.Name)
			if vs := listValue(row[c.column]); len(vs) > 0 {
				n.LeafLists[c.leaf.Name] = vs
			}
		}
	}
	for _, j := range t.jsons {
		if _, ok := row[j.column]; !ok {
			continue
		}
		delete(n.Lists, j.list.Name)
		if err := readJSONColumn(n, j, row[j.column]); err != nil {
			return fmt.Errorf("%s: %s: %w", t.name, j.column, err)
		}
	}
	return nil
}

// Table is the name of the table whose row the entry n is.
func (a *Adder) Table(n *datastore.Node) string {
	if t := a.m.byList[n.S]; t != nil {
		return t.name
	}
	return ""
}

// Index is the id of every entry the adder knows: those it was given and
// those it added with an id.
func (a *Adder) Index() Index { return a.idx }

// List is the list whose entries are the table's rows, nil for none.
func (a *Adder) List(tbl string) *schema.Node {
	for _, t := range a.m.tables {
		if t.name == tbl && t.singleton == 0 && t != a.m.rootTable {
			return t.s
		}
	}
	return nil
}

// tableFor is the table of tbl a row is of (see Add).
func (a *Adder) tableFor(tbl string, row Row) *table {
	var fallback *table
	for _, x := range a.m.tables {
		if x.name != tbl || x == a.m.rootTable {
			continue
		}
		if fallback == nil {
			fallback = x
		}
		if x.parent == nil {
			if toInt(row[x.parentCol]) == 0 || x.parentCol == "" {
				fallback = x
			}
			continue
		}
		if pid := toInt(row[x.parentCol]); pid != 0 && a.byID[x.parent][pid] != nil {
			return x
		}
	}
	return fallback
}
