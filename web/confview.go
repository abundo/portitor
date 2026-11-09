// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/abundo/portitor/internal/confcheck"
	"github.com/abundo/portitor/internal/confview"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/models"
	"github.com/labstack/echo/v5"
)

// The configuration as rows (confview), for the code that reads it that
// way: made from the candidate, cached until it changes.

type viewCache struct {
	mu   sync.Mutex
	gen  uint64
	view *confview.View
}

// view is the candidate as rows: a copy whose slices the caller may
// change.
func (s *Server) view(ctx context.Context) (*confview.View, error) {
	t, err := s.tree()
	if err != nil {
		return nil, err
	}
	c := &s.viewCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.view != nil && c.gen == t.store.Gen() {
		return c.view.Copy(), nil
	}
	cand, gen, err := t.store.CandidateGen(ctx)
	if err != nil {
		return nil, err
	}
	v, err := confview.Load(s.db, cand)
	if err != nil {
		return nil, err
	}
	c.view, c.gen = v, gen
	return v.Copy(), nil
}

// viewOf is tree's rows, with the ids kept for its entries.
func (s *Server) viewOf(tree *datastore.Tree) (*confview.View, error) {
	return confview.Load(s.db, tree)
}

// entryID is the id of the candidate's entry at p (sqlmap.IDs): what
// the handlers that take a row id know it by.
func (s *Server) entryID(ctx context.Context, p datastore.Path) (uint, bool, error) {
	v, err := s.view(ctx)
	if err != nil {
		return 0, false, err
	}
	id, ok := v.ID(p)
	return id, ok, nil
}

// editConfig changes the candidate with fn as portitor-config itself
// (bootstrap, the firewalls, an import): no user's access applies, the
// store normalizes it.
func (s *Server) editConfig(ctx context.Context, fn func(*datastore.Tree) error) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	return t.store.Edit(ctx, "", fn)
}

// renameExternal makes the configuration's names of a firewall or role
// (px:external) follow its rename.
func (s *Server) renameExternal(ctx context.Context, table, old, new string) error {
	if old == new {
		return nil
	}
	t, err := s.tree()
	if err != nil {
		return err
	}
	return s.editConfig(ctx, func(work *datastore.Tree) error {
		t.mapping.RenameExternal(work, table, old, new)
		return nil
	})
}

// certificateByID is the candidate's certificate with the id, nil when
// there is none.
func (s *Server) certificateByID(ctx context.Context, id uint) (*models.Certificate, error) {
	v, err := s.view(ctx)
	if err != nil {
		return nil, err
	}
	for i := range v.Certificates {
		if v.Certificates[i].ID == id {
			return &v.Certificates[i], nil
		}
	}
	return nil, nil
}

// userEdit changes the candidate with fn for the request's user, checked
// as every edit is (checkEdit): their access, the schema, confcheck and
// what a commit would refuse. warnings are the problems it didn't add.
// editError answers its error.
func (s *Server) userEdit(c *echo.Context, fn func(work *datastore.Tree) error) (warnings []error, err error) {
	t, err := s.tree()
	if err != nil {
		return nil, err
	}
	acc := s.treeAccessOf(c)
	scope, err := s.deployScope(currentAccess(c))
	if err != nil {
		return nil, err
	}
	err = t.store.Edit(c.Request().Context(), "", func(work *datastore.Tree) error {
		before := work.Clone()
		if err := fn(work); err != nil {
			return err
		}
		var denied string
		var err error
		warnings, denied, err = s.checkEdit(acc, scope, before, work)
		if errors.Is(err, errForbidden) {
			if acc.readOnly {
				return &forbiddenError{"this is the HA secondary: its configuration is a read-only copy of the primary's"}
			}
			return &forbiddenError{"you may not change " + denied}
		}
		return err
	})
	return warnings, err
}

// forbiddenError is an edit the user may not make.
type forbiddenError struct{ msg string }

func (e *forbiddenError) Error() string { return e.msg }

// editError answers the error of userEdit or editConfig.
func editError(c *echo.Context, err error) error {
	var fe *forbiddenError
	var br *badRequest
	switch {
	case errors.As(err, &fe):
		return errJSON(c, http.StatusForbidden, fe.msg)
	case errors.As(err, &br):
		return errJSON(c, http.StatusBadRequest, br.msg)
	}
	return configError(c, err)
}

// warn puts warnings in the answer's header (X-Portitor-Warnings), which
// the GUI shows.
func warn(c *echo.Context, warnings []error) {
	if len(warnings) > 0 {
		c.Response().Header().Set("X-Portitor-Warnings", joinErrors(warnings))
	}
}

// rowWriter adds models (package models' structs) to a working copy of
// the candidate, as rows: an import's, which makes its configuration
// that way.
type rowWriter struct {
	s    *Server
	work *datastore.Tree
	add  *sqlmap.Adder
	tmp  uint
}

func (s *Server) rowWriter(work *datastore.Tree) (*rowWriter, error) {
	t, err := s.tree()
	if err != nil {
		return nil, err
	}
	v, err := s.viewOf(work)
	if err != nil {
		return nil, err
	}
	return &rowWriter{s: s, work: work, add: t.mapping.NewAdder(s.db, work, v.Index), tmp: 1 << 40}, nil
}

// create adds model as a new entry, and sets its ID: a list keyed by id
// gets the next one (nextID), others one made up for the rows added after
// it to name, which the entry doesn't keep.
func (w *rowWriter) create(model any) (*datastore.Node, error) {
	tbl, row, err := confview.RowOf(model)
	if err != nil {
		return nil, err
	}
	if toUint(row["id"]) == 0 {
		var id uint
		if list := w.add.List(tbl); list != nil && slices.Equal(list.Keys, []string{"id"}) {
			n, err := w.s.nextID(w.work, list, "id")
			if err != nil {
				return nil, err
			}
			id = uint(n)
		} else {
			w.tmp++
			id = w.tmp
		}
		row["id"] = int64(id)
		if m, ok := model.(interface{ SetID(uint) }); ok {
			m.SetID(id)
		}
	}
	return w.add.Add(tbl, row)
}

func toUint(v any) uint {
	switch x := v.(type) {
	case int64:
		return uint(x)
	case uint:
		return x
	}
	return 0
}

// instanceByID is the candidate's instance with the id, nil when there is
// none.
func (s *Server) instanceByID(ctx context.Context, id uint) (*models.Instance, error) {
	v, err := s.view(ctx)
	if err != nil {
		return nil, err
	}
	for i := range v.Instances {
		if v.Instances[i].ID == id {
			return &v.Instances[i], nil
		}
	}
	return nil, nil
}

// addChecked adds model to w's tree, and takes it out again with the
// first problem the schema or confcheck finds with it.
func addChecked(w *rowWriter, model any) error {
	n, err := w.create(model)
	if err != nil {
		return err
	}
	if problems := entryProblems(w.work, n); len(problems) > 0 {
		if err := w.work.Delete(datastore.PathOf(n)); err != nil {
			return err
		}
		return problems[0]
	}
	return nil
}

// entryProblems are the problems of the entry n of work and below it:
// the schema's (datastore.Tree.Validate) and confcheck's.
func entryProblems(work *datastore.Tree, n *datastore.Node) []error {
	var out []error
	prefix := datastore.PathOf(n).String(work.Root.S)
	for _, e := range work.Validate() {
		var de *datastore.Error
		if errors.As(e, &de) && (de.Path == prefix || strings.HasPrefix(de.Path, prefix+"/")) {
			out = append(out, e)
		}
	}
	return append(out, confcheck.CheckEntries(work, []*datastore.Node{n})...)
}

// ifaceNamesIn are the interface names of an instance: its interfaces and
// the ends of links in it.
func ifaceNamesIn(v *confview.View, instanceID uint) map[string]bool {
	names := map[string]bool{}
	for _, i := range v.Interfaces {
		if i.InstanceID == instanceID {
			names[i.Name] = true
		}
	}
	for _, l := range v.Links {
		if l.InstanceAID == instanceID {
			names[l.InterfaceA] = true
		}
		if l.InstanceBID == instanceID {
			names[l.InterfaceB] = true
		}
	}
	return names
}

// instanceNamed is the candidate's instance of the name, nil when there
// is none.
func (s *Server) instanceNamed(ctx context.Context, name string) (*models.Instance, error) {
	v, err := s.view(ctx)
	if err != nil {
		return nil, err
	}
	for i := range v.Instances {
		if v.Instances[i].Name == name {
			return &v.Instances[i], nil
		}
	}
	return nil, nil
}
