// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/confview"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
)

// treeResource is the REST CRUD of resource for a global list of the tree
// (globals.go): the same routes and rows, the entries are the candidate's,
// and each write is committed alone at once (a scoped commit), so it takes
// effect as the old CRUD's did. A write the commit refuses is taken out of
// the candidate again.
//
//	GET    /api/<name>          list
//	GET    /api/<name>/:id
//	POST   /api/<name>
//	PUT    /api/<name>/:id      body is merged onto the stored row
//	DELETE /api/<name>/:id
type treeResource[T any, PT model[T]] struct {
	s     *Server
	list  string // the YANG list
	table string // its px:table
	rows  func(*confview.View) []T
	// named is an entry's name, its key.
	named func(PT) string
	// prepare validates and normalises item before it is written, old nil
	// on create. v is the candidate's rows.
	prepare func(v *confview.View, item, old PT) error
	// present adjusts rows before they are returned (derived fields).
	present func(item PT)
	// onWrite makes more changes to the candidate in the same edit as an
	// entry's creation (old nil) or change; onDelete does before its removal
	// (and may refuse it). restore are the lists they change besides the
	// entry's own, put back with it when the commit is refused.
	onWrite  func(c *echo.Context, work *datastore.Tree, item, old PT) error
	onDelete func(c *echo.Context, work *datastore.Tree, v *confview.View, item PT) error
	restore  []string
}

func (r *treeResource[T, PT]) register(g *echo.Group, path string) {
	g.GET(path, r.listAll)
	g.GET(path+"/:id", r.get)
	g.POST(path, r.create)
	g.PUT(path+"/:id", r.update)
	g.DELETE(path+"/:id", r.remove)
}

func (r *treeResource[T, PT]) find(v *confview.View, id uint) PT {
	rows := r.rows(v)
	for i := range rows {
		if PT(&rows[i]).GetID() == id {
			return &rows[i]
		}
	}
	return nil
}

func (r *treeResource[T, PT]) byName(v *confview.View, name string) PT {
	rows := r.rows(v)
	for i := range rows {
		if r.named(&rows[i]) == name {
			return &rows[i]
		}
	}
	return nil
}

func (r *treeResource[T, PT]) listAll(c *echo.Context) error {
	v, err := r.s.view(c.Request().Context())
	if err != nil {
		return err
	}
	rows := r.rows(v)
	items := make([]T, len(rows))
	copy(items, rows)
	if r.present != nil {
		for i := range items {
			r.present(PT(&items[i]))
		}
	}
	return c.JSON(http.StatusOK, items)
}

func (r *treeResource[T, PT]) load(c *echo.Context) (*confview.View, PT, error) {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return nil, nil, errJSON(c, http.StatusNotFound, "not found")
	}
	v, err := r.s.view(c.Request().Context())
	if err != nil {
		return nil, nil, err
	}
	item := r.find(v, id)
	if item == nil {
		return nil, nil, errJSON(c, http.StatusNotFound, "not found")
	}
	return v, item, nil
}

func (r *treeResource[T, PT]) get(c *echo.Context) error {
	_, item, err := r.load(c)
	if item == nil {
		return err
	}
	cp := *item
	if r.present != nil {
		r.present(&cp)
	}
	return c.JSON(http.StatusOK, cp)
}

func (r *treeResource[T, PT]) create(c *echo.Context) error {
	item := PT(new(T))
	if err := json.NewDecoder(c.Request().Body).Decode(item); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid JSON: "+err.Error())
	}
	item.SetID(0)
	v, err := r.s.view(c.Request().Context())
	if err != nil {
		return err
	}
	if err := r.prepare(v, item, nil); err != nil {
		return writeError(c, err)
	}
	if ok, err := r.write(c, func(work *datastore.Tree, w *rowWriter) error {
		if _, err := w.create(item); err != nil {
			return err
		}
		if r.onWrite != nil {
			return r.onWrite(c, work, item, nil)
		}
		return nil
	}); !ok {
		return err
	}
	return r.answer(c, http.StatusCreated, r.named(item))
}

func (r *treeResource[T, PT]) update(c *echo.Context) error {
	v, old, err := r.load(c)
	if old == nil {
		return err
	}
	item := PT(new(T))
	*item = *old
	id := old.GetID()
	// Merge: fields absent from the body keep their stored value, and
	// json:"-" fields (secrets) can't be set through the API at all.
	if err := json.NewDecoder(c.Request().Body).Decode(item); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid JSON: "+err.Error())
	}
	item.SetID(id)
	if err := r.prepare(v, item, old); err != nil {
		return writeError(c, err)
	}
	oldName := r.named(old)
	if ok, err := r.write(c, func(work *datastore.Tree, w *rowWriter) error {
		n := w.add.Node(r.table, int64(id))
		if n == nil {
			return bad("not found")
		}
		if name := r.named(item); name != oldName {
			if err := work.Rename(datastore.PathOf(n), []string{name}); err != nil {
				return err
			}
		}
		tbl, row, err := confview.RowOf(item)
		if err != nil {
			return err
		}
		_ = tbl
		if err := w.add.Update(n, row); err != nil {
			return err
		}
		if r.onWrite != nil {
			return r.onWrite(c, work, item, old)
		}
		return nil
	}); !ok {
		return err
	}
	return r.answer(c, http.StatusOK, r.named(item))
}

func (r *treeResource[T, PT]) remove(c *echo.Context) error {
	v, item, err := r.load(c)
	if item == nil {
		return err
	}
	id := item.GetID()
	if ok, err := r.write(c, func(work *datastore.Tree, w *rowWriter) error {
		n := w.add.Node(r.table, int64(id))
		if n == nil {
			return bad("not found")
		}
		if r.onDelete != nil {
			if err := r.onDelete(c, work, v, item); err != nil {
				return err
			}
		}
		return work.Delete(datastore.PathOf(n))
	}); !ok {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// answer is the entry as the tree has it now, with its id.
func (r *treeResource[T, PT]) answer(c *echo.Context, status int, name string) error {
	v, err := r.s.view(c.Request().Context())
	if err != nil {
		return err
	}
	item := r.byName(v, name)
	if item == nil {
		return c.NoContent(status)
	}
	cp := *item
	if r.present != nil {
		r.present(&cp)
	}
	return c.JSON(status, cp)
}

// write changes the candidate with edit as the request's user, and commits
// the list alone; when the commit is refused the candidate's list is put
// back. When it is not ok the request has been answered, and err is what the
// handler returns.
func (r *treeResource[T, PT]) write(c *echo.Context, edit func(work *datastore.Tree, w *rowWriter) error) (ok bool, err error) {
	ctx := c.Request().Context()
	t, err := r.s.tree()
	if err != nil {
		return false, err
	}
	before, err := t.store.Candidate(ctx)
	if err != nil {
		return false, err
	}
	// A rename here is the one made to what runs too (by the commit below).
	r.s.bothTrees.Add(1)
	defer r.s.bothTrees.Add(-1)
	var renamed []datastore.Renamed
	warnings, err := r.s.userEdit(c, func(work *datastore.Tree) error {
		w, err := r.s.rowWriter(work)
		if err != nil {
			return err
		}
		if err := edit(work, w); err != nil {
			return err
		}
		renamed = append(renamed, work.Renamed...)
		return nil
	})
	if err != nil {
		return false, editError(c, err)
	}
	if _, err := t.store.Commit(ctx, datastore.CommitOptions{User: currentUser(c).Username, Scope: []string{r.list}, NoDeploy: true}); err != nil {
		if rerr := t.store.EditRaw(ctx, func(work *datastore.Tree) error {
			work.CopyLists(before, append([]string{r.list}, r.restore...)...)
			return nil
		}); rerr != nil {
			return false, rerr
		}
		// The entries are back at their names, so are their ids.
		if len(renamed) > 0 {
			_ = r.s.rec.UpdateIDs(func(ids sqlmap.IDs) { t.mapping.UndoRenames(ids, renamed) })
		}
		return false, editError(c, err)
	}
	warn(c, warnings)
	return true, nil
}
