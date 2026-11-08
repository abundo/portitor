// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http/httptest"
	"strings"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/datastore"
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

// rowID is the id of the table's row of the entry named name (in the
// tables, the candidate's cache), for what still takes row ids.
func (env *testEnv) rowID(table, name string) uint {
	env.t.Helper()
	var id uint
	if err := env.srv.db.Table(table).Select("id").Where("name = ?", name).Scan(&id).Error; err != nil || id == 0 {
		env.t.Fatalf("no %s %s: %v", table, name, err)
	}
	return id
}
