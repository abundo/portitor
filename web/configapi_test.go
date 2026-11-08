// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/models"
)

func TestConfigAPI(t *testing.T) {
	env := newEnv(t)
	env.srv.newAgent = func(*models.Firewall) (agentAPI, error) { return &neighboursAgent{}, nil }
	env.create("/api/instances", map[string]any{"name": "main"})
	var fw models.Firewall
	env.srv.db.First(&fw)
	want := func(rec interface {
		Result() *http.Response
	}, code int, what string) {
		t.Helper()
		if got := rec.Result().StatusCode; got != code {
			t.Fatalf("%s: %d, want %d", what, got, code)
		}
	}

	// The schema.
	rec := env.do("GET", "/api/schema", nil)
	want(rec, http.StatusOK, "schema")
	var sch struct {
		Name     string `json:"name"`
		Children []struct {
			Name string   `json:"name"`
			Kind string   `json:"kind"`
			Keys []string `json:"keys"`
		} `json:"children"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sch)
	found := false
	for _, c := range sch.Children {
		if c.Name == "instance" && c.Kind == "list" && len(c.Keys) == 1 && c.Keys[0] == "name" {
			found = true
		}
	}
	if !found {
		t.Fatalf("schema has no instance list: %s", rec.Body.String()[:200])
	}

	// A virtual firewall with an interface and a rule, made through the tree.
	rec = env.do("POST", "/api/config/candidate/instance", map[string]any{"name": "lab", "firewall": fw.Name})
	want(rec, http.StatusCreated, "create lab")
	want(env.do("POST", "/api/config/candidate/instance", map[string]any{"name": "lab", "firewall": fw.Name}), http.StatusBadRequest, "create lab twice")
	want(env.do("PUT", "/api/config/candidate/instance=lab/interface=eth1", map[string]any{
		"kind": "physical", "enabled": true, "addresses": []string{"10.1.0.1/24"}, "wg-private-key": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}), http.StatusOK, "put eth1")
	want(env.do("PATCH", "/api/config/candidate/instance=lab/interface=eth1", map[string]any{"mtu": 1400}), http.StatusOK, "patch mtu")
	want(env.do("PATCH", "/api/config/candidate/instance=lab/interface=eth1", map[string]any{"mtu": "big"}), http.StatusBadRequest, "patch a bad mtu")

	rec = env.do("GET", "/api/config/candidate/instance=lab/interface=eth1", nil)
	want(rec, http.StatusOK, "get eth1")
	if body := rec.Body.String(); !strings.Contains(body, `"mtu":1400`) || strings.Contains(body, "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=") {
		t.Errorf("eth1: %s", body)
	}
	rec = env.do("GET", "/api/config/candidate/instance=lab/interface=eth1/mtu", nil)
	if rec.Body.String() != "1400" {
		t.Errorf("mtu: %s", rec.Body)
	}
	want(env.do("GET", "/api/config/candidate/instance=lab/interface=eth1/wg-private-key", nil), http.StatusNotFound, "a secret")
	want(env.do("GET", "/api/config/candidate/instance=lab/interface=eth9", nil), http.StatusNotFound, "a missing entry")
	want(env.do("GET", "/api/config/candidate/instance=lab/colour", nil), http.StatusBadRequest, "an unknown name")
	rec = env.do("GET", "/api/config/candidate/instance=lab/interface", nil)
	if !strings.HasPrefix(rec.Body.String(), `[{"name":"eth1"`) {
		t.Errorf("interfaces: %s", rec.Body)
	}

	// A replace keeps the secret; a rename follows into the rules.
	want(env.do("PUT", "/api/config/candidate/instance=lab/interface=eth1", map[string]any{"kind": "physical", "enabled": true, "addresses": []string{"10.1.0.1/24"}}), http.StatusOK, "replace eth1")
	cand, _ := env.srv.treeState.store.Candidate(t.Context())
	if cand.Root.Entry("instance", []string{"lab"}).Entry("interface", []string{"eth1"}).Leaves["wg-private-key"] != "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" {
		t.Error("the replace lost the secret")
	}
	want(env.do("POST", "/api/config/candidate/instance=lab/rule", map[string]any{"id": 900, "chain": "input", "action": "accept", "in-interfaces": []string{"eth1"}}), http.StatusCreated, "rule 900")
	want(env.do("POST", "/api/config/candidate/instance=lab/rule", map[string]any{"id": 901, "chain": "input", "action": "drop"}), http.StatusCreated, "rule 901")
	// A new rule without an id gets one never used before.
	want(env.do("POST", "/api/config/candidate/instance=lab/rule", map[string]any{"chain": "input", "action": "drop"}), http.StatusCreated, "a rule without an id")
	rec = env.do("GET", "/api/config/candidate/instance=lab/rule=902", nil)
	want(rec, http.StatusOK, "rule 902")
	want(env.do("DELETE", "/api/config/candidate/instance=lab/rule=902", nil), http.StatusNoContent, "delete 902")
	want(env.do("POST", "/api/config/candidate/instance=lab/rule", map[string]any{"chain": "input", "action": "drop"}), http.StatusCreated, "another rule")
	want(env.do("GET", "/api/config/candidate/instance=lab/rule=903", nil), http.StatusOK, "rule 903, not 902 again")
	want(env.do("DELETE", "/api/config/candidate/instance=lab/rule=903", nil), http.StatusNoContent, "delete 903")
	want(env.do("POST", "/api/config/candidate/instance=lab/interface=eth1?action=rename", map[string]any{"keys": []string{"lan"}}), http.StatusOK, "rename")
	rec = env.do("GET", "/api/config/candidate/instance=lab/rule=900/in-interfaces", nil)
	if rec.Body.String() != `["lan"]` {
		t.Errorf("the rule after the rename: %s", rec.Body)
	}
	want(env.do("POST", "/api/config/candidate/instance=lab/rule=901?action=move", map[string]any{"where": "first"}), http.StatusOK, "move")
	rec = env.do("GET", "/api/config/candidate/instance=lab/rule", nil)
	if i, j := strings.Index(rec.Body.String(), `"id":901`), strings.Index(rec.Body.String(), `"id":900`); i < 0 || j < i {
		t.Errorf("rules after the move: %s", rec.Body)
	}
	want(env.do("POST", "/api/config/candidate/instance=lab/rule=901?action=spin", map[string]any{}), http.StatusBadRequest, "an unknown action")
	want(env.do("DELETE", "/api/config/candidate/instance=lab/rule=901", nil), http.StatusNoContent, "delete 901")
	want(env.do("DELETE", "/api/config/candidate/instance=lab/rule=901", nil), http.StatusBadRequest, "delete 901 twice")
	want(env.do("PUT", "/api/config/running/instance=lab/description", "x"), http.StatusMethodNotAllowed, "a change of running")
	want(env.do("PATCH", "/api/config/candidate/instance=lab/state", map[string]any{}), http.StatusBadRequest, "a change of state")

	// A save the commit would refuse is refused, with the reason.
	rec = env.do("PUT", "/api/config/candidate/instance=lab/interface=vl9", map[string]any{"kind": "vlan", "enabled": true, "vlan-id": 9, "parent": "nope"})
	want(rec, http.StatusBadRequest, "a VLAN of no parent")
	if !strings.Contains(rec.Body.String(), "vl9") {
		t.Errorf("no reason: %s", rec.Body)
	}

	// Actions: new keys, a peer's client config, the next free address.
	want(env.do("PUT", "/api/config/candidate/instance=lab/interface=wg0", map[string]any{"kind": "wireguard", "enabled": true, "addresses": []string{"10.99.0.1/24"}, "wg-listen-port": 51820}), http.StatusOK, "wg0")
	before := env.do("GET", "/api/config/candidate/instance=lab/interface=wg0/wg-public-key", nil).Body.String()
	want(env.do("POST", "/api/config/candidate/instance=lab/interface=wg0?action=wg-rekey", map[string]any{}), http.StatusOK, "rekey")
	if after := env.do("GET", "/api/config/candidate/instance=lab/interface=wg0/wg-public-key", nil).Body.String(); after == before || len(after) < 40 {
		t.Errorf("the public key %s, then %s", before, after)
	}
	want(env.do("POST", "/api/config/candidate/instance=lab/interface=lan?action=wg-rekey", map[string]any{}), http.StatusBadRequest, "rekey a NIC")
	rec = env.do("POST", "/api/config/candidate/instance=lab/interface=wg0/wireguard-peer", map[string]any{"name": "phone", "allowed-ips": []string{"10.99.0.2/32"}})
	want(rec, http.StatusCreated, "a peer")
	rec = env.do("GET", "/api/config/candidate/instance=lab/interface=wg0/wireguard-peer=phone?action=client-config", nil)
	want(rec, http.StatusOK, "client config")
	if !strings.Contains(rec.Body.String(), "PrivateKey") || !strings.Contains(rec.Body.String(), "10.99.0.2/32") {
		t.Errorf("client config: %s", rec.Body)
	}
	want(env.do("GET", "/api/config/candidate/instance=lab/interface=wg0?action=spin", nil), http.StatusBadRequest, "an unknown view")
	want(env.do("DELETE", "/api/config/candidate/instance=lab/interface=wg0", nil), http.StatusNoContent, "delete wg0")

	// Changes, a commit, running.
	rec = env.do("GET", "/api/config/changes", nil)
	if !strings.Contains(rec.Body.String(), `"changed":true`) || !strings.Contains(rec.Body.String(), "lab") {
		t.Errorf("changes: %s", rec.Body)
	}
	want(env.do("POST", "/api/deploy/apply", map[string]any{}), http.StatusOK, "commit")
	rec = env.do("GET", "/api/config/running/instance=lab/interface=lan/addresses", nil)
	if rec.Body.String() != `["10.1.0.1/24"]` {
		t.Errorf("running: %s", rec.Body)
	}
	if rec := env.do("GET", "/api/config/changes", nil); !strings.Contains(rec.Body.String(), `"changed":false`) {
		t.Errorf("changes after the commit: %s", rec.Body)
	}

	// An admin of lab changes lab, not where it runs, nor the host; a
	// global viewer changes nothing; someone with no role sees no lab.
	tina := env.create("/api/users", map[string]string{"username": "tina", "password": "a long password", "role": "none"})
	env.create("/api/users", map[string]string{"username": "vic", "password": "a long password", "role": "viewer"})
	env.create("/api/users", map[string]string{"username": "nobody", "password": "a long password", "role": "none"})
	r := env.roles()["vf-lab"]
	want(env.do("PUT", "/api/roles/"+itoa(r.ID), map[string]any{"members": []map[string]any{{"user_id": tina, "level": "admin"}}}), http.StatusOK, "role")

	env.login("tina", "a long password")
	want(env.do("PATCH", "/api/config/candidate/instance=lab/interface=lan", map[string]any{"description": "tina's"}), http.StatusOK, "tina changes lab")
	want(env.do("PATCH", "/api/config/candidate/instance=lab", map[string]any{"firewall": "elsewhere"}), http.StatusForbidden, "tina moves lab")
	want(env.do("PUT", "/api/config/candidate/instance=lab/interface=eth5", map[string]any{"kind": "physical"}), http.StatusBadRequest, "tina adds a NIC")
	want(env.do("DELETE", "/api/config/candidate/instance=lab/interface=lan", nil), http.StatusBadRequest, "tina removes a NIC")
	want(env.do("POST", "/api/config/candidate/instance=lab/interface=lan?action=rename", map[string]any{"keys": []string{"lan9"}}), http.StatusBadRequest, "tina renames a NIC")
	want(env.do("PUT", "/api/config/candidate/instance=lab/interface=lo5", map[string]any{"kind": "loopback", "addresses": []string{"10.5.0.1/32"}}), http.StatusOK, "tina adds a loopback")
	want(env.do("PATCH", "/api/config/candidate/instance=main", map[string]any{"description": "x"}), http.StatusForbidden, "tina changes the host")
	want(env.do("GET", "/api/config/candidate/instance=main", nil), http.StatusNotFound, "tina reads the host")
	rec = env.do("GET", "/api/config/candidate/instance", nil)
	if strings.Contains(rec.Body.String(), `"name":"main"`) || !strings.Contains(rec.Body.String(), `"name":"lab"`) {
		t.Errorf("tina's instances: %s", rec.Body)
	}
	want(env.do("POST", "/api/config/discard", nil), http.StatusForbidden, "tina discards")

	env.login("vic", "a long password")
	want(env.do("GET", "/api/config/candidate/instance=main", nil), http.StatusOK, "vic reads")
	want(env.do("PATCH", "/api/config/candidate/instance=lab", map[string]any{"description": "x"}), http.StatusForbidden, "vic writes")

	env.login("nobody", "a long password")
	want(env.do("GET", "/api/config/candidate/instance=lab", nil), http.StatusNotFound, "nobody reads lab")

	env.login("admin", "correct horse battery")
	want(env.do("POST", "/api/config/discard", nil), http.StatusNoContent, "discard")
	rec = env.do("GET", "/api/config/candidate/instance=lab/interface=lan/description", nil)
	want(rec, http.StatusNotFound, "tina's change after the discard")
}
