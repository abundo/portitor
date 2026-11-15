// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/datastore"
)

// globalsEnv is twoFirewalls with the syslog servers (which change the
// documents) and the certificate authorities (which don't) as global lists.
func globalsEnv(t *testing.T) (*testEnv, map[uint]*fleetAgent) {
	t.Helper()
	old := globalLists
	globalLists = append([]string{"syslog-server", "certificate-authority"}, old...)
	t.Cleanup(func() { globalLists = old })
	env, agents, _ := twoFirewalls(t)
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("first commit: %d %s", rec.Code, rec.Body)
	}
	return env, agents
}

func (env *testEnv) commitScope(scope ...string) string {
	env.t.Helper()
	tr, err := env.srv.tree()
	if err != nil {
		env.t.Fatal(err)
	}
	msg, err := tr.store.Commit(context.Background(), datastore.CommitOptions{User: "test", Scope: scope})
	if err != nil {
		env.t.Fatalf("scoped commit: %v", err)
	}
	return msg
}

func (env *testEnv) running() *datastore.Tree {
	env.t.Helper()
	run, err := treeBackend{env.srv}.Running(context.Background())
	if err != nil {
		env.t.Fatal(err)
	}
	return run
}

// ruleCount is the rules of every instance in tree.
func ruleCount(tree *datastore.Tree) int {
	n := 0
	for _, in := range tree.Root.Lists["instance"] {
		n += len(in.Lists["rule"])
	}
	return n
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// A scoped commit runs the lists it names and nothing else of the
// candidate: what else the candidate has stays pending, and a document it
// changes is deployed.
func TestScopedCommitDeploys(t *testing.T) {
	env, agents := globalsEnv(t)
	before := len(agents[1].applied)
	rules := ruleCount(env.running())
	env.post("syslog-server", map[string]any{"address": "192.0.2.50", "enabled": true})
	env.post("instance=main/rule", map[string]any{"chain": "input", "action": "drop", "enabled": true})

	msg := env.commitScope("syslog-server")
	if !strings.Contains(msg, "applied") {
		t.Errorf("message %q", msg)
	}
	run := env.running()
	if len(run.Root.Lists["syslog-server"]) != 1 {
		t.Errorf("the syslog server does not run")
	}
	if len(run.Root.Lists["instance"]) == 0 {
		t.Fatal("running lost its instances")
	}
	if ruleCount(run) != rules {
		t.Errorf("the pending rule is in running")
	}
	if len(agents[1].applied) != before+1 || !strings.Contains(string(mustJSON(agents[1].last())), "192.0.2.50") {
		t.Errorf("the syslog server was not deployed")
	}
	// The candidate still has its rule, and only that differs from running.
	if rec := env.do("GET", "/api/config/changes", nil); !strings.Contains(rec.Body.String(), "rule") || strings.Contains(rec.Body.String(), "syslog") {
		t.Errorf("changes: %s", rec.Body)
	}
	// A full commit after it deploys the rule and keeps the syslog server.
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	if len(env.running().Root.Lists["syslog-server"]) != 1 {
		t.Error("the full commit lost the syslog server")
	}
}

// A list that no document has is committed with nothing applied and no
// commit number.
func TestScopedCommitNothingToDeploy(t *testing.T) {
	env, agents := globalsEnv(t)
	st, _ := env.srv.settings()
	applied := len(agents[1].applied)
	env.mustCfg("POST", "certificate-authority=ca?action=generate", map[string]any{"common-name": "Example CA", "days": 30})
	msg := env.commitScope("certificate-authority")
	if !strings.Contains(msg, "nothing to deploy") {
		t.Errorf("message %q", msg)
	}
	if len(env.running().Root.Lists["certificate-authority"]) != 1 {
		t.Error("the CA does not run")
	}
	if now, _ := env.srv.settings(); now.LastCommit != st.LastCommit || len(agents[1].applied) != applied {
		t.Errorf("a commit was numbered or applied: %d %d", now.LastCommit, len(agents[1].applied))
	}
	// Only the named lists: an unknown one is refused.
	tr, _ := env.srv.tree()
	if _, err := tr.store.Commit(context.Background(), datastore.CommitOptions{Scope: []string{"host"}}); err == nil {
		t.Error("a list that is not global was committed alone")
	}
}

// A commit waits for confirmation; a global list committed meanwhile is
// kept when that commit is rolled back: what runs of them does not follow
// the deployed commits.
func TestScopedCommitDuringAPendingCommit(t *testing.T) {
	env, agents := globalsEnv(t)
	rules := ruleCount(env.running())
	env.do("PUT", "/api/settings", map[string]any{"confirm_timeout": 60})
	env.post("instance=main/rule", map[string]any{"chain": "input", "action": "drop", "enabled": true})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"pending"`) {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	env.post("syslog-server", map[string]any{"address": "192.0.2.50", "enabled": true})
	msg := env.commitScope("syslog-server")
	if !strings.Contains(msg, "not deployed") {
		t.Errorf("a change of the documents during a pending commit: %q", msg)
	}
	if len(env.running().Root.Lists["syslog-server"]) != 1 {
		t.Error("the syslog server does not run")
	}
	if rec := env.do("POST", "/api/deploy/rollback", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("rollback: %d %s", rec.Code, rec.Body)
	}
	_ = agents
	run := env.running()
	if ruleCount(run) != rules {
		t.Error("the rolled back rule runs")
	}
	if len(run.Root.Lists["syslog-server"]) != 1 {
		t.Error("the rollback took the syslog server with it")
	}
}

// A role an OpenVPN server of the live commit requires is renamed (it runs at
// once, the commit's file still names the old one): reading what runs, the
// users' writes and the next commit all work.
func TestRenamingARoleTheLiveCommitNames(t *testing.T) {
	env, agents, _ := twoFirewalls(t)
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "enabled": true, "ipv4-mode": "dhcp"})
	env.mustCfg("POST", "instance=main/certificate=vpn?action=generate", map[string]any{"domains": []string{"vpn.example.com"}, "key-type": "ec256", "days": 30})
	ann := env.create("/api/users", map[string]string{"username": "ann", "password": "a long password", "role": "none"})
	role := env.create("/api/roles", map[string]any{"name": "vpn", "members": []map[string]any{{"user_id": ann, "level": "viewer"}}})
	env.put("instance=main/interface=ovpn0", map[string]any{"kind": "openvpn", "enabled": true, "ipv4-mode": "static",
		"addresses": []string{"10.8.0.1/24"}, "ovpn-tcp-addresses": []string{"10.9.0.1/24"}, "ovpn-listen": "eth0",
		"ovpn-certificate": "vpn", "ovpn-role": "vpn", "ovpn-require-role": true})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}

	if rec := env.do("PUT", "/api/roles/"+itoa(role), map[string]any{"name": "vpn2"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	// Reading and writing what runs still works.
	if rec := env.do("GET", "/api/me", nil); rec.Code != http.StatusOK {
		t.Errorf("me: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/users/"+itoa(ann), map[string]any{"role": "none", "full_name": "Ann"}); rec.Code != http.StatusOK {
		t.Errorf("a user's write after the rename: %d %s", rec.Code, rec.Body)
	}
	for _, p := range []string{"/api/deploy/changes", "/api/config/changes"} {
		if rec := env.do("GET", p, nil); rec.Code != http.StatusOK {
			t.Errorf("%s: %d %s", p, rec.Code, rec.Body)
		}
	}
	// The next commit names the new one.
	before := len(agents[1].applied)
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("second commit: %d %s", rec.Code, rec.Body)
	}
	if len(agents[1].applied) != before+1 {
		t.Errorf("the rename was not deployed")
	}
	if got := env.node("instance=main/interface=ovpn0").Leaf("ovpn-role"); got != "vpn2" {
		t.Errorf("ovpn-role %q", got)
	}
}

// A full commit is prepared, a password is changed, and the prepared tree is
// deployed: the new password stays (what a commit makes run of the global
// lists is the candidate as it is then).
func TestPreparedCommitDoesNotUndoAPasswordChange(t *testing.T) {
	env, _, _ := twoFirewalls(t)
	env.create("/api/users", map[string]string{"username": "ann", "password": "a long password", "role": "viewer"})
	tr, _ := env.srv.tree()
	prepared, err := tr.store.Prepare(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	ann := env.userNamed("ann")
	if rec := env.do("POST", "/api/users/"+itoa(ann.ID)+"/password", map[string]string{"password": "another long password"}); rec.Code != http.StatusNoContent {
		t.Fatalf("password: %d %s", rec.Code, rec.Body)
	}
	changed := env.userNamed("ann")
	if _, err := env.srv.deploy(context.Background(), "test", nil, nil, prepared); err != nil {
		t.Fatal(err)
	}
	if got := env.userNamed("ann"); got.PasswordHash != changed.PasswordHash || got.TokenVersion != changed.TokenVersion {
		t.Error("the commit put the old password back")
	}
}
