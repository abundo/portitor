// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/confview"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/models"
)

// Helpers for tests that set up the configuration through the tree
// (/api/config), as the GUI, the CLI and NETCONF do.

// cfg changes the candidate: method on path, below /api/config/candidate/.
func (env *testEnv) cfg(method, path string, body any) *httptest.ResponseRecorder {
	env.t.Helper()
	return env.do(method, "/api/config/candidate/"+path, body)
}

// mustCfg is cfg that fails the test unless the change is made.
func (env *testEnv) mustCfg(method, path string, body any) *httptest.ResponseRecorder {
	env.t.Helper()
	rec := env.cfg(method, path, body)
	if rec.Code/100 != 2 {
		env.t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body)
	}
	return rec
}

// put is mustCfg's PUT (make or replace the entry at path).
func (env *testEnv) put(path string, body any) { env.t.Helper(); env.mustCfg("PUT", path, body) }

// patch is mustCfg's PATCH (merge into the entry at path).
func (env *testEnv) patch(path string, body any) { env.t.Helper(); env.mustCfg("PATCH", path, body) }

// read reads the JSON at path of ds (candidate, running, state) into v,
// and returns the status.
func (env *testEnv) read(ds, path string, v any) int {
	env.t.Helper()
	rec := env.do("GET", "/api/config/"+ds+"/"+path, nil)
	if v != nil && rec.Code == 200 {
		if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
			env.t.Fatalf("%s %s: %v", ds, path, err)
		}
	}
	return rec.Code
}

// node is the candidate's entry (or container) at a RESTCONF path, nil
// when it isn't there.
func (env *testEnv) node(path string) *datastore.Node {
	env.t.Helper()
	p, err := parseConfigPath(path)
	if err != nil {
		env.t.Fatal(err)
	}
	t, err := env.srv.tree()
	if err != nil {
		env.t.Fatal(err)
	}
	cand, err := t.store.Candidate(env.t.Context())
	if err != nil {
		env.t.Fatal(err)
	}
	n, _, _ := cand.Find(p)
	return n
}

// host makes the default virtual firewall, the first firewall's host, as
// an installation starts with; name is its name.
func (env *testEnv) host(name string) {
	env.t.Helper()
	fw := firstFirewall(env.t, env)
	env.mustCfg("POST", "instance", map[string]any{"name": name, "firewall": fw.Name, "is-default": true})
}

// vf makes a virtual firewall on the first firewall.
func (env *testEnv) vf(name string) {
	env.t.Helper()
	fw := firstFirewall(env.t, env)
	env.mustCfg("POST", "instance", map[string]any{"name": name, "firewall": fw.Name})
}

// commit commits the candidate and fails the test unless it is applied.
func (env *testEnv) commit() {
	env.t.Helper()
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != 200 {
		env.t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
}

// input is the builder's input of the candidate.
func (env *testEnv) input() builder.Input {
	env.t.Helper()
	in, err := env.srv.candidateInput(env.t.Context())
	if err != nil {
		env.t.Fatal(err)
	}
	return in
}

// post makes an entry of the list at path and returns its key (keys
// joined by ","): a rule's id, say, given by the server.
func (env *testEnv) post(path string, body any) string {
	env.t.Helper()
	rec := env.mustCfg("POST", path, body)
	var out struct {
		Keys []string `json:"keys"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return strings.Join(out.Keys, ",")
}

// on reports whether the boolean leaf of n is true (its default too).
func on(n *datastore.Node, leaf string) bool { return n != nil && n.Leaf(leaf) == "true" }

// view is the candidate as rows (confview).
func (env *testEnv) view() *confview.View {
	env.t.Helper()
	v, err := env.srv.view(env.t.Context())
	if err != nil {
		env.t.Fatal(err)
	}
	return v
}

// rowID is the id of the entry of the table named name (its row's in
// confview), for what takes ids.
func (env *testEnv) rowID(table, name string) uint {
	env.t.Helper()
	rv := reflect.ValueOf(env.view()).Elem()
	for i := range rv.NumField() {
		f := rv.Field(i)
		if f.Kind() != reflect.Slice || f.Len() == 0 || f.Type().Elem().Kind() != reflect.Struct {
			continue
		}
		if tbl, _, _ := confview.RowOf(f.Index(0).Addr().Interface()); tbl != table {
			continue
		}
		for j := range f.Len() {
			if row := f.Index(j); row.FieldByName("Name").String() == name {
				return uint(row.FieldByName("ID").Uint())
			}
		}
	}
	env.t.Fatalf("no %s %s", table, name)
	return 0
}

// rows are the rows of a list of the candidate that keep keeps (nil: all).
func rows[T any](env *testEnv, of func(*confview.View) []T, keep func(*T) bool) []T {
	env.t.Helper()
	all := of(env.view())
	if keep == nil {
		return all
	}
	return confview.Where(all, keep)
}

// instanceRow is the candidate's instance of the name; the default one
// for "".
func (env *testEnv) instanceRow(name string) models.Instance {
	env.t.Helper()
	for _, in := range env.view().Instances {
		if in.Name == name || (name == "" && in.IsDefault) {
			return in
		}
	}
	env.t.Fatalf("no instance %q", name)
	return models.Instance{}
}

// ifaceRow is the candidate's (first) interface of the name.
func (env *testEnv) ifaceRow(name string) models.Interface {
	env.t.Helper()
	for _, i := range env.view().Interfaces {
		if i.Name == name {
			return i
		}
	}
	env.t.Fatalf("no interface %q", name)
	return models.Interface{}
}

// rowIDOf is the row id of an entry keyed by its id (a rule's is its row's).
func (env *testEnv) rowIDOf(table, id string) uint {
	env.t.Helper()
	var n uint
	if _, err := fmt.Sscan(id, &n); err != nil {
		env.t.Fatal(err)
	}
	return n
}
