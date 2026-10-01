// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"
)

// model is a pointer to a struct embedding models.Base.
type model[T any] interface {
	*T
	GetID() uint
	SetID(uint)
}

// resource is REST CRUD for one table:
//
//	GET    /api/<name>          list, filtered by ?<column>=<uint>
//	GET    /api/<name>/:id
//	POST   /api/<name>
//	PUT    /api/<name>/:id      body is merged onto the stored row
//	DELETE /api/<name>/:id
type resource[T any, PT model[T]] struct {
	db      *gorm.DB
	filters []string // columns usable as ?column=id filters
	order   string
	// prepare validates and normalises a row before it is saved, inside
	// the save transaction. old is nil on create.
	prepare func(tx *gorm.DB, item, old PT) error
	// afterCreate runs after a new row is inserted (it has its id), inside
	// the save transaction.
	afterCreate func(tx *gorm.DB, item PT) error
	// present adjusts rows before they are returned (derived fields).
	present func(item PT)
	// beforeDelete may refuse a delete, inside the delete transaction.
	beforeDelete func(tx *gorm.DB, item PT) error
	// scope ties rows to instances, which decides who reads them. Without
	// one the rows are shared: everyone reads them, global admins change
	// them.
	scope *scope
	// tenantWrites are the methods (POST, PUT, DELETE) an admin of the
	// row's instances may use too.
	tenantWrites []string
	// tenantCheck refuses changes only a global admin may make.
	tenantCheck func(item, old PT) error
}

// badRequest is a validation failure shown to the user as-is.
type badRequest struct{ msg string }

func (e *badRequest) Error() string { return e.msg }

func bad(msg string) error { return &badRequest{msg} }

// errForbidden refuses a change the user may not make.
var errForbidden = errors.New("forbidden")

func (r *resource[T, PT]) register(s *Server, g *echo.Group, path string) {
	for _, m := range r.tenantWrites {
		p := path
		if m != http.MethodPost {
			p += "/:id"
		}
		s.tenantWrites[m+" /api"+p] = true
	}
	g.GET(path, r.list)
	g.GET(path+"/:id", r.get)
	g.POST(path, r.create)
	g.PUT(path+"/:id", r.update)
	g.DELETE(path+"/:id", r.remove)
}

func (r *resource[T, PT]) list(c *echo.Context) error {
	q := r.db
	if a := currentAccess(c); r.scope != nil && !a.readsAll() {
		q = r.scope.list(q, a.readable())
	}
	for _, f := range r.filters {
		if v := c.QueryParam(f); v != "" {
			id, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return errJSON(c, http.StatusBadRequest, "invalid filter "+f)
			}
			q = q.Where(f+" = ?", id) // f is from the fixed allow-list
		}
	}
	if r.order != "" {
		q = q.Order(r.order)
	}
	items := []T{}
	if err := q.Find(&items).Error; err != nil {
		return err
	}
	if r.present != nil {
		for i := range items {
			r.present(PT(&items[i]))
		}
	}
	return c.JSON(http.StatusOK, items)
}

func (r *resource[T, PT]) load(c *echo.Context) (PT, error) {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return nil, errJSON(c, http.StatusNotFound, "not found")
	}
	item := PT(new(T))
	if err := r.db.First(item, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errJSON(c, http.StatusNotFound, "not found")
		}
		return nil, err
	}
	if a := currentAccess(c); r.scope != nil && !a.readsAll() {
		ids, err := r.scope.of(r.db, item)
		if err != nil {
			return nil, err
		}
		if !a.canReadAny(ids) {
			return nil, errJSON(c, http.StatusNotFound, "not found")
		}
	}
	return item, nil
}

// checkWrite tells whether the user may make this change: a global admin
// any, an instance admin one of tenantWrites on rows of their instances
// (before and after the change).
func (r *resource[T, PT]) checkWrite(c *echo.Context, tx *gorm.DB, item, old PT) error {
	a := currentAccess(c)
	if a.isAdmin() {
		return nil
	}
	if r.scope == nil || !slices.Contains(r.tenantWrites, c.Request().Method) {
		return errForbidden
	}
	for _, row := range []PT{item, old} {
		if row == nil {
			continue
		}
		ids, err := r.scope.of(tx, row)
		if err != nil {
			return err
		}
		if !a.canWriteAll(ids) {
			return errForbidden
		}
	}
	if r.tenantCheck != nil {
		return r.tenantCheck(item, old)
	}
	return nil
}

func (r *resource[T, PT]) get(c *echo.Context) error {
	item, err := r.load(c)
	if item == nil {
		return err
	}
	if r.present != nil {
		r.present(item)
	}
	return c.JSON(http.StatusOK, item)
}

func (r *resource[T, PT]) create(c *echo.Context) error {
	item := PT(new(T))
	if err := json.NewDecoder(c.Request().Body).Decode(item); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid JSON: "+err.Error())
	}
	item.SetID(0) // the database assigns ids
	return r.save(c, item, nil, http.StatusCreated)
}

func (r *resource[T, PT]) update(c *echo.Context) error {
	item, err := r.load(c)
	if item == nil {
		return err
	}
	old := PT(new(T))
	*old = *item
	id := item.GetID()
	// Merge: fields absent from the body keep their stored value, and
	// json:"-" fields (secrets) can't be set through the API at all.
	if err := json.NewDecoder(c.Request().Body).Decode(item); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid JSON: "+err.Error())
	}
	item.SetID(id)
	return r.save(c, item, old, http.StatusOK)
}

func (r *resource[T, PT]) save(c *echo.Context, item, old PT, status int) error {
	err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := r.checkWrite(c, tx, item, old); err != nil {
			return err
		}
		if r.prepare != nil {
			if err := r.prepare(tx, item, old); err != nil {
				return err
			}
		}
		if old == nil {
			if err := tx.Create(item).Error; err != nil {
				return err
			}
			if r.afterCreate != nil {
				return r.afterCreate(tx, item)
			}
			return nil
		}
		return tx.Save(item).Error
	})
	if err != nil {
		return dbError(c, err)
	}
	if r.present != nil {
		r.present(item)
	}
	return c.JSON(status, item)
}

func (r *resource[T, PT]) remove(c *echo.Context) error {
	item, err := r.load(c)
	if item == nil {
		return err
	}
	err = r.db.Transaction(func(tx *gorm.DB) error {
		if err := r.checkWrite(c, tx, item, nil); err != nil {
			return err
		}
		if r.beforeDelete != nil {
			if err := r.beforeDelete(tx, item); err != nil {
				return err
			}
		}
		return tx.Delete(item).Error
	})
	if err != nil {
		return dbError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

// dbError maps validation and constraint errors to 4xx answers.
func dbError(c *echo.Context, err error) error {
	var br *badRequest
	if errors.As(err, &br) {
		return errJSON(c, http.StatusBadRequest, br.msg)
	}
	if errors.Is(err, errForbidden) {
		return errJSON(c, http.StatusForbidden, "you can't change this")
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "UNIQUE constraint"):
		return errJSON(c, http.StatusConflict, "an entry with that name/value already exists")
	case strings.Contains(msg, "FOREIGN KEY constraint"):
		return errJSON(c, http.StatusConflict, "referenced by, or referring to, another entry")
	}
	return err
}

func errJSON(c *echo.Context, status int, msg string) error {
	return c.JSON(status, map[string]any{"error": msg})
}
