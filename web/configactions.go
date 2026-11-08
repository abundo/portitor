// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/wgkeys"
)

// Actions on the configuration's entries: what is generated or done
// rather than set (a WireGuard interface's new keys, a certificate made or
// renewed, a peer's client config, a download started), by the entry's
// path:
//
//	GET  /api/config/<ds>/<path>?action=<view>      a view (a client config, the next free address)
//	POST /api/config/candidate/<path>?action=<do>  a change or an operation
//
// An action is registered by the list's schema path; rename and move are
// every entry's (configapi.go).

// configAction is one action of a list's entries.
type configAction struct {
	// view: a GET, of the datastore asked for; else a POST, of the
	// candidate.
	view bool
	// op: a POST that changes no configuration (the agent renews a
	// certificate, downloads an IP list): run on a copy of the candidate,
	// not under its lock.
	op bool
	// write: the user must be allowed to change the entry (else to read
	// it).
	write bool
	run   func(s *Server, c *echo.Context, a *actionCtx) error
}

// actionCtx is what an action gets: the tree it acts on (a copy for a
// view, the candidate's working copy for a change), the entry and its
// path.
type actionCtx struct {
	tree  *datastore.Tree
	path  datastore.Path
	entry *datastore.Node
	body  []byte
	// changed, set by a change, makes it the new candidate.
	changed bool
}

var configActions = map[string]map[string]configAction{}

func registerAction(listPath, name string, a configAction) {
	if configActions[listPath] == nil {
		configActions[listPath] = map[string]configAction{}
	}
	configActions[listPath][name] = a
}

// lookupAction is the action named on the entry at p, if there is one.
func lookupAction(t *datastore.Tree, p datastore.Path, name string) (configAction, bool) {
	ss, err := datastore.Resolve(t.Root.S, p)
	if err != nil || len(ss) == 0 {
		return configAction{}, false
	}
	a, ok := configActions[ss[len(ss)-1].Path()][name]
	return a, ok
}

// entryModel decodes the entry at p of tree into dst, a pointer to the
// model of its table, as the code that took a table's row expects it.
func (s *Server) entryModel(tree *datastore.Tree, p datastore.Path, dst any) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	n, _, err := tree.Find(p)
	if err != nil {
		return err
	}
	if n == nil {
		return &notFound{p.String(tree.Root.S)}
	}
	table := t.mapping.TableOf(n.S)
	if table == "" {
		return fmt.Errorf("%s is not a row of a table", p.String(tree.Root.S))
	}
	rows, idx, err := t.mapping.Rows(s.db, tree)
	if err != nil {
		return err
	}
	id := idx[n]
	for _, r := range rows[table] {
		if fmt.Sprint(r["id"]) == fmt.Sprint(id) {
			slice := reflect.New(reflect.SliceOf(reflect.TypeOf(dst).Elem()))
			if err := builder.DecodeRows([]sqlmap.Row{r}, slice.Interface()); err != nil {
				return err
			}
			reflect.ValueOf(dst).Elem().Set(slice.Elem().Index(0))
			return nil
		}
	}
	return errors.New("no row for " + p.String(tree.Root.S))
}

// runAction runs the action named on the entry of the request's path.
func (s *Server) runAction(c *echo.Context, ds string, p datastore.Path, name string, body []byte) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	ctx := c.Request().Context()
	acc := s.treeAccessOf(c)
	var tree *datastore.Tree
	if ds == "running" {
		tree, err = t.store.Running(ctx)
	} else {
		tree, err = t.store.Candidate(ctx)
	}
	if err != nil {
		return err
	}
	a, ok := lookupAction(tree, p, name)
	if !ok {
		return errJSON(c, http.StatusBadRequest, "no action "+name+" here")
	}
	if a.view != (c.Request().Method == http.MethodGet) {
		return errJSON(c, http.StatusMethodNotAllowed, "action "+name+": the wrong method")
	}
	if len(p) > 0 && !acc.CanRead(p[:1]) {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	if a.write && !acc.CanWrite(p) {
		return errJSON(c, http.StatusForbidden, "you may not change "+p.String(tree.Root.S))
	}
	if a.view || a.op {
		n, _, err := tree.Find(p)
		if err != nil || n == nil {
			return errJSON(c, http.StatusNotFound, "not found")
		}
		return a.run(s, c, &actionCtx{tree: tree, path: p, entry: n, body: body})
	}
	if ds != "candidate" {
		return errJSON(c, http.StatusMethodNotAllowed, "only the candidate can be changed")
	}
	// A change: on the candidate's working copy, under its lock. The
	// action answers; the copy becomes the candidate if it changed it.
	var answered error
	err = t.store.Edit(ctx, "", func(work *datastore.Tree) error {
		n, _, err := work.Find(p)
		if err != nil || n == nil {
			return &notFound{p.String(work.Root.S)}
		}
		ac := &actionCtx{tree: work, path: p, entry: n, body: body}
		answered = a.run(s, c, ac)
		if !ac.changed {
			return errNoChange
		}
		return nil
	})
	var nf *notFound
	switch {
	case errors.Is(err, errNoChange), err == nil:
		return answered
	case errors.As(err, &nf):
		return errJSON(c, http.StatusNotFound, nf.Error())
	}
	return configError(c, err)
}

// errNoChange ends an Edit that changed nothing.
var errNoChange = errors.New("no change")


// delegate is an action done by a handler of the CRUD's time, which takes
// the entry's row id as its :id: the tables hold the candidate (they are
// kept in step with it until the API is all on the tree).
func delegate(h echo.HandlerFunc) func(s *Server, c *echo.Context, a *actionCtx) error {
	return func(s *Server, c *echo.Context, a *actionCtx) error {
		t, err := s.tree()
		if err != nil {
			return err
		}
		tables, idx, err := t.mapping.Import(s.db)
		if err != nil {
			return err
		}
		n, _, err := tables.Find(a.path)
		if err != nil || n == nil {
			return errJSON(c, http.StatusNotFound, "not found")
		}
		c.SetPathValues(echo.PathValues{{Name: "id", Value: fmt.Sprint(idx[n])}})
		return h(c)
	}
}

func init() {
	registerAction("/instance/interface/wireguard-peer", "client-config", configAction{view: true, write: true, run: delegateM((*Server).handleWgClientConfig)})
	registerAction("/instance/interface", "wg-next-free", configAction{view: true, run: delegateM((*Server).handleWgNextFree)})
	registerAction("/instance/interface", "openvpn-client", configAction{view: true, write: true, run: delegateM((*Server).handleOpenVPNClientConfig)})
	registerAction("/instance/interface", "wg-rekey", configAction{write: true, run: wgRekey})
	registerAction("/instance/certificate", "download", configAction{view: true, write: true, run: delegateM((*Server).handleCertificateDownload)})
	registerAction("/instance/certificate", "renew", configAction{op: true, write: true, run: delegateM((*Server).handleCertificateRenew)})
	registerAction("/instance/ipam-prefix", "next-free", configAction{view: true, run: delegateM((*Server).handleNextFree)})
	registerAction("/ip-list", "refresh", configAction{op: true, run: delegateM((*Server).handleIPListRefresh)})
	registerAction("/instance/dns-blocklist", "refresh", configAction{op: true, write: true, run: delegateM((*Server).handleDNSBlocklistRefresh)})
	registerAction("/task", "run", configAction{op: true, write: true, run: delegateM((*Server).handleTaskRun)})
	registerAction("/instance", "bundle", configAction{view: true, write: true, run: delegateM((*Server).handleExportBundle)})
}

// delegateM is delegate for a method of the server.
func delegateM(m func(*Server, *echo.Context) error) func(s *Server, c *echo.Context, a *actionCtx) error {
	return func(s *Server, c *echo.Context, a *actionCtx) error {
		return delegate(func(c *echo.Context) error { return m(s, c) })(s, c, a)
	}
}

// wgRekey gives a WireGuard interface new keys; its peers need the new
// public key.
func wgRekey(s *Server, c *echo.Context, a *actionCtx) error {
	if a.entry.Leaf("kind") != fwconfig.KindWireGuard {
		return errJSON(c, http.StatusBadRequest, "not a WireGuard interface")
	}
	priv, pub, err := wgkeys.Generate()
	if err != nil {
		return err
	}
	a.entry.Leaves["wg-private-key"], a.entry.Leaves["wg-public-key"] = priv, pub
	a.changed = true
	return c.JSON(http.StatusOK, map[string]string{"wg-public-key": pub})
}
