// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
)

// The CRUD's writes of configuration, through the tree: until every page
// of the GUI is on /api/config, a write of a row is made by the CRUD's
// handler (its checks and normalizing) in a transaction on the tables, the
// candidate's cache; the tables as it leaves them are read into a tree,
// the transaction rolled back, and that tree checked as an /api/config
// change is (checkEdit) and made the candidate, which writes the tables
// (Store.OnChange). No request writes the tables otherwise.

// errAnswered ends an Edit whose handler refused the change itself.
var errAnswered = errors.New("answered")

// handlerError carries a handler's own error out of the Edit.
type handlerError struct{ err error }

func (e *handlerError) Error() string { return e.err.Error() }

// throughTree runs h, a CRUD write given a transaction to work in, as a
// change of the candidate.
func (s *Server) throughTree(h func(tx *gorm.DB, c *echo.Context) error) echo.HandlerFunc {
	return func(c *echo.Context) error {
		t, err := s.tree()
		if err != nil {
			return err
		}
		acc := s.treeAccessOf(c)
		scope, err := s.deployScope(currentAccess(c))
		if err != nil {
			return err
		}
		rec := httptest.NewRecorder()
		var denied string
		var warnings []error
		err = t.store.Edit(c.Request().Context(), "", func(work *datastore.Tree) error {
			before := work.Clone()
			_, beforeIdx, err := t.mapping.Import(s.db)
			if err != nil {
				return err
			}
			tx := s.db.Begin()
			defer tx.Rollback()
			orig := c.Response()
			c.SetResponse(rec)
			c.Set(ctxTx, tx)
			herr := h(tx, c)
			c.Set(ctxTx, nil)
			c.SetResponse(orig)
			if herr != nil {
				return &handlerError{herr}
			}
			if rec.Code >= 300 {
				return errAnswered
			}
			after, afterIdx, err := t.mapping.Import(tx)
			if err != nil {
				return err
			}
			work.Root = after.Root
			work.Renamed = renamedInstances(beforeIdx, afterIdx, before)
			warnings, denied, err = s.checkEdit(acc, scope, before, work)
			return err
		})
		var he *handlerError
		switch {
		case errors.As(err, &he):
			return he.err
		case errors.Is(err, errAnswered):
			return copyRecorded(c, rec, nil)
		case errors.Is(err, errForbidden):
			if acc.readOnly {
				return errJSON(c, http.StatusForbidden, "this is the HA secondary: its configuration is a read-only copy of the primary's")
			}
			return errJSON(c, http.StatusForbidden, "you may not change "+denied)
		case err != nil:
			return configError(c, err)
		}
		return copyRecorded(c, rec, warnings)
	}
}

// renamedInstances are the virtual firewalls whose row has another name
// after: a rename through the CRUD, which the tree sees as a delete and a
// new entry (their roles follow a rename).
func renamedInstances(before, after sqlmap.Index, tree *datastore.Tree) []datastore.Renamed {
	byID := map[int64]string{}
	for n, id := range before {
		if n.S.Name == "instance" && n.Parent != nil && n.Parent.Parent == nil {
			byID[id] = n.Leaf("name")
		}
	}
	var out []datastore.Renamed
	for n, id := range after {
		if n.S.Name != "instance" || n.Parent == nil || n.Parent.Parent != nil {
			continue
		}
		if old, ok := byID[id]; ok && old != n.Leaf("name") {
			out = append(out, datastore.Renamed{Path: datastore.Path{{Name: "instance", Keys: []string{old}}}, Keys: []string{n.Leaf("name")}})
		}
	}
	return out
}

// copyRecorded answers what the handler answered.
func copyRecorded(c *echo.Context, rec *httptest.ResponseRecorder, warnings []error) error {
	h := c.Response().Header()
	maps.Copy(h, rec.Header())
	if len(warnings) > 0 {
		h.Set("X-Portitor-Warnings", joinErrors(warnings))
	}
	c.Response().WriteHeader(rec.Code)
	if rec.Body.Len() == 0 {
		return nil // a 204 has none
	}
	_, err := c.Response().Write(rec.Body.Bytes())
	return err
}

func joinErrors(errs []error) string {
	out := ""
	for i, e := range errs {
		if i > 0 {
			out += "; "
		}
		out += e.Error()
	}
	return out
}

// viaTables runs fn, code of the CRUD's time that writes configuration into
// the tables (bootstrap), as one change of the candidate: in a transaction
// rolled back after, the tables it leaves read into the candidate, which
// the store normalizes and checks and OnChange writes back. What fn writes
// that is not configuration is lost with the transaction.
func (s *Server) viaTables(ctx context.Context, fn func(tx *gorm.DB) error) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	return t.store.Edit(ctx, "", func(work *datastore.Tree) error {
		before := work.Clone()
		_, beforeIdx, err := t.mapping.Import(s.db)
		if err != nil {
			return err
		}
		tx := s.db.Begin()
		defer tx.Rollback()
		if err := fn(tx); err != nil {
			return err
		}
		after, afterIdx, err := t.mapping.Import(tx)
		if err != nil {
			return err
		}
		work.Root = after.Root
		work.Renamed = renamedInstances(beforeIdx, afterIdx, before)
		return nil
	})
}

// ctxTx holds the transaction a handler run by throughTree works in.
const ctxTx = "tx"

// dbOf is the database a handler works in: throughTree's transaction, or
// the database.
func (s *Server) dbOf(c *echo.Context) *gorm.DB {
	if tx, ok := c.Get(ctxTx).(*gorm.DB); ok && tx != nil {
		return tx
	}
	return s.db
}

// legacyWrite is a handler of the CRUD's time that writes configuration,
// with dbOf, made a change of the candidate.
func (s *Server) legacyWrite(h echo.HandlerFunc) echo.HandlerFunc {
	return s.throughTree(func(_ *gorm.DB, c *echo.Context) error { return h(c) })
}
