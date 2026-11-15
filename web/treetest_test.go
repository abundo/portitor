// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

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

// lastDeployment is the newest deployment of any firewall.
func (env *testEnv) lastDeployment() models.Deployment {
	env.t.Helper()
	deps, err := env.srv.rec.RecentDeployments(1)
	if err != nil || len(deps) == 0 {
		env.t.Fatalf("no deployment: %v", err)
	}
	return deps[0]
}

// deploymentOf is the firewall's newest deployment.
func (env *testEnv) deploymentOf(firewallID uint) models.Deployment {
	env.t.Helper()
	dep, err := env.srv.rec.LatestDeployment(firewallID)
	if err != nil || dep == nil {
		env.t.Fatalf("firewall %d has no deployment: %v", firewallID, err)
	}
	return *dep
}

// userNamed is the user running of that name.
func (env *testEnv) userNamed(name string) models.User {
	env.t.Helper()
	u, err := env.srv.rec.UserNamed(name)
	if err != nil {
		env.t.Fatalf("user %s: %v", name, err)
	}
	return *u
}

// userID is the user running with the id.
func (env *testEnv) userID(id uint) models.User {
	env.t.Helper()
	u, err := env.srv.rec.User(id)
	if err != nil {
		env.t.Fatalf("user %d: %v", id, err)
	}
	return *u
}

// member is the user's membership of the role, if there is one.
func (env *testEnv) member(user, role uint) (models.RoleMember, bool) {
	env.t.Helper()
	ms, err := env.srv.rec.RoleMembers()
	if err != nil {
		env.t.Fatal(err)
	}
	for _, m := range ms {
		if m.UserID == user && m.RoleID == role {
			return m, true
		}
	}
	return models.RoleMember{}, false
}

// addMember makes the user a member of the role, as an admin of it would.
func (env *testEnv) addMember(role, user uint, level string) {
	env.t.Helper()
	roles, err := env.srv.rec.Roles()
	if err != nil {
		env.t.Fatal(err)
	}
	for _, r := range roles {
		if r.ID == role {
			r.Members = append(r.Members, models.RoleMember{UserID: user, Level: level})
			if err := env.srv.rec.SaveRole(&r, r.Members, r.Instances); err != nil {
				env.t.Fatal(err)
			}
			return
		}
	}
	env.t.Fatalf("no role %d", role)
}

// firewall is the firewall running with the id.
func (env *testEnv) firewall(id uint) models.Firewall {
	env.t.Helper()
	return firewallOf(env.t, env.srv, id)
}

func firewallOf(t *testing.T, s *Server, id uint) models.Firewall {
	t.Helper()
	f, err := s.rec.Firewall(id)
	if err != nil {
		t.Fatalf("firewall %d: %v", id, err)
	}
	return *f
}

// firstFirewall is the first firewall.
func (env *testEnv) firstFirewall() models.Firewall {
	env.t.Helper()
	fws, err := env.srv.rec.Firewalls()
	if err != nil || len(fws) == 0 {
		env.t.Fatalf("no firewall: %v", err)
	}
	return fws[0]
}

// setFirewall sets leaves of a firewall's entry and commits the list, as an
// admin's write would.
func (env *testEnv) setFirewall(name string, leaves map[string]any) {
	env.t.Helper()
	env.patch("firewall="+name, leaves)
	tr, err := env.srv.tree()
	if err != nil {
		env.t.Fatal(err)
	}
	if _, err := tr.store.Commit(context.Background(), datastore.CommitOptions{User: "test", Scope: []string{"firewall"}, NoDeploy: true}); err != nil {
		env.t.Fatal(err)
	}
}
