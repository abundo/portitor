// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"slices"
	"net/http"
	"testing"
)

// The GUI's writes of rows go through the tree: the candidate has them,
// the tree's checks apply, and the tables follow the candidate.
func TestCRUDThroughTree(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.vf("lab")
	inst := env.rowID("instances", "lab")
	rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "kind": "physical", "enabled": true, "addresses": []string{" 10.0.0.1/24 "}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if n := env.node("instance=lab/interface=eth1"); n == nil || n.LeafLists["addresses"][0] != "10.0.0.1/24" {
		t.Fatalf("the candidate: %+v", n)
	}
	id := env.rowID("interfaces", "eth1")
	// The CRUD's own check refuses; nothing changes.
	if rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": inst, "name": "a b", "kind": "physical"}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad name: %d %s", rec.Code, rec.Body)
	}
	// The tree's refuses too: a rule naming no interface.
	if rec := env.do("POST", "/api/rules", map[string]any{"instance_id": inst, "chain": "input", "action": "accept", "in_interfaces": []string{"eth9"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown interface: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", fmt.Sprintf("/api/interfaces/%d", id), map[string]any{"description": "lan"}); rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	if d := env.node("instance=lab/interface=eth1").Leaf("description"); d != "lan" {
		t.Errorf("description %q", d)
	}
	// A rename keeps the virtual firewall's role.
	r := env.roles()["vf-lab"]
	if rec := env.do("PUT", fmt.Sprintf("/api/instances/%d", inst), map[string]any{"name": "lab2"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	if got := env.roles()["vf-lab2"]; got.ID != r.ID {
		t.Errorf("role after the rename: %+v", env.roles())
	}
	// The rules' order, the GUI's drag and drop.
	a := env.post("instance=lab2/rule", map[string]any{"chain": "input", "action": "drop", "description": "a"})
	b := env.post("instance=lab2/rule", map[string]any{"chain": "input", "action": "drop", "description": "b"})
	var ids []uint
	for _, r := range env.node("instance=lab2").Lists["rule"] {
		ids = append(ids, env.rowIDOf("rules", r.Leaf("id")))
	}
	slices.Reverse(ids)
	if rec := env.do("POST", "/api/rules/reorder", map[string]any{"ids": ids}); rec.Code/100 != 2 {
		t.Fatalf("reorder: %d %s", rec.Code, rec.Body)
	}
	if rs := env.node("instance=lab2").Lists["rule"]; rs[0].Leaf("id") != b || rs[1].Leaf("id") != a {
		t.Errorf("order after reorder: %s %s", rs[0].Leaf("id"), rs[1].Leaf("id"))
	}
	if rec := env.do("DELETE", fmt.Sprintf("/api/interfaces/%d", id), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if env.node("instance=lab2/interface=eth1") != nil {
		t.Error("deleted interface in the candidate")
	}
}
