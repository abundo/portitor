// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/models"
)

// TestTenancy checks that a user with no global role reaches only the
// instances their roles grant, and deploys only those.
func TestTenancy(t *testing.T) {
	env := newEnv(t)
	fake := &neighboursAgent{}
	env.srv.newAgent = func(*models.Firewall) (agentAPI, error) { return fake, nil }
	env.host("main") // the default, with no role
	env.vf("a")
	env.vf("b")
	tina := env.create("/api/users", map[string]string{"username": "tina", "password": "a long password", "role": "none"})
	roleA := env.roles()["vf-a"].ID
	if rec := env.do("PUT", fmt.Sprintf("/api/roles/%d", roleA), map[string]any{
		"members": []map[string]any{{"user_id": tina, "level": "admin"}},
	}); rec.Code != http.StatusOK {
		t.Fatalf("role: %d %s", rec.Code, rec.Body)
	}
	rule := func(desc string) map[string]any {
		return map[string]any{"chain": "input", "action": "accept", "enabled": true, "description": desc}
	}
	ruleB := env.post("instance=b/rule", rule("b's"))
	env.commit()

	env.login("tina", "a long password")
	var me struct {
		Access map[string]string `json:"access"`
	}
	_ = json.Unmarshal(env.do("GET", "/api/me", nil).Body.Bytes(), &me)
	if len(me.Access) != 1 || me.Access["a"] != "admin" {
		t.Errorf("access: %v", me.Access)
	}
	var insts []map[string]any
	env.read("candidate", "instance", &insts)
	if len(insts) != 1 || insts[0]["name"] != "a" {
		t.Errorf("instances: %+v", insts)
	}
	for _, tc := range []struct {
		method, path string
		body         any
		want         int
	}{
		{"GET", "/api/config/candidate/instance=b/rule=" + ruleB, nil, http.StatusNotFound},
		{"PATCH", "/api/config/candidate/instance=b/rule=" + ruleB, map[string]any{"description": "mine"}, http.StatusForbidden},
		{"DELETE", "/api/config/candidate/instance=b/rule=" + ruleB, nil, http.StatusForbidden},
		{"POST", "/api/config/candidate/instance=b/rule", rule("x"), http.StatusForbidden},
		{"POST", "/api/config/candidate/host", map[string]any{"name": "h", "addresses": []string{"10.0.0.1"}}, http.StatusForbidden},
		{"GET", "/api/config/candidate/host", nil, http.StatusOK},
		{"GET", "/api/users", nil, http.StatusForbidden},
		{"GET", "/api/settings", nil, http.StatusForbidden},
		{"POST", "/api/config/candidate/instance", map[string]any{"name": "c"}, http.StatusForbidden},
		{"DELETE", "/api/config/candidate/instance=a", nil, http.StatusForbidden},
		{"POST", "/api/config/candidate/instance=a?action=rename", map[string]any{"keys": []string{"a2"}}, http.StatusForbidden},
		{"PATCH", "/api/config/candidate/instance=a", map[string]any{"description": "tina's"}, http.StatusOK},
		{"PUT", "/api/config/candidate/instance=a/interface=eth7", map[string]any{"kind": "physical", "enabled": true}, http.StatusBadRequest},
		{"POST", "/api/deploy/revert", map[string]any{}, http.StatusForbidden},
	} {
		if rec := env.do(tc.method, tc.path, tc.body); rec.Code != tc.want {
			t.Errorf("%s %s: %d %s, want %d", tc.method, tc.path, rec.Code, rec.Body, tc.want)
		}
	}
	var nb agentapi.NeighboursResponse
	_ = json.Unmarshal(env.do("GET", "/api/agent/neighbours", nil).Body.Bytes(), &nb)
	if len(nb.IP) != 1 || nb.IP[0].Instance != "a" || len(nb.LLDP) != 1 || nb.LLDP[0].Instance != "a" ||
		len(nb.LLDPPorts) != 1 || nb.LLDPPorts[0].Instance != "a" {
		t.Errorf("neighbours: %+v", nb)
	}
	var rl agentapi.RateLimitsResponse
	_ = json.Unmarshal(env.do("GET", "/api/agent/rate-limits", nil).Body.Bytes(), &rl)
	if len(rl.Instances) != 1 || rl.Instances["a"]["ssh"].DropPackets != 3 {
		t.Errorf("rate limits: %+v", rl)
	}
	ruleA := env.post("instance=a/rule", rule("tina's"))

	// The admin changes b meanwhile; tina's deploy keeps b as deployed.
	env.login("admin", "correct horse battery")
	env.post("instance=b/rule", rule("pending"))
	env.login("tina", "a long password")
	env.commit()
	descs := func(name string) []string {
		var out []string
		for _, r := range fake.applied.Instance(name).Rules {
			out = append(out, r.Description)
		}
		return out
	}
	if !slices.Contains(descs("a"), "tina's") {
		t.Errorf("a: %v", descs("a"))
	}
	if slices.Contains(descs("b"), "pending") || !slices.Contains(descs("b"), "b's") {
		t.Errorf("b: %v", descs("b"))
	}
	var dep models.Deployment
	env.srv.db.Order("id desc").First(&dep)
	if !slices.Equal(dep.Instances, models.StringList{"a"}) {
		t.Errorf("deployment instances: %v", dep.Instances)
	}

	// A role made by hand grants its instances at the member's level.
	env.login("admin", "correct horse battery")
	env.create("/api/roles", map[string]any{"name": "both", "instances": []string{"a", "b"},
		"members": []map[string]any{{"user_id": tina, "level": "viewer"}}})
	env.login("tina", "a long password")
	if rec := env.do("GET", "/api/config/candidate/instance=b/rule="+ruleB, nil); rec.Code != http.StatusOK {
		t.Errorf("read b: %d", rec.Code)
	}
	if rec := env.cfg("PATCH", "instance=b/rule="+ruleB, map[string]any{"description": "mine"}); rec.Code != http.StatusForbidden {
		t.Errorf("write b as viewer: %d", rec.Code)
	}
	if rec := env.cfg("PATCH", "instance=a/rule="+ruleA, map[string]any{"description": "still mine"}); rec.Code != http.StatusOK {
		t.Errorf("write a (admin wins): %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{"instances": []string{"b"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("tina deploys b: %d %s", rec.Code, rec.Body)
	}

	// A global admin may deploy chosen instances too: b's pending rule
	// stays out while a is deployed.
	env.login("admin", "correct horse battery")
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{"instances": []string{"a"}}); rec.Code != http.StatusOK {
		t.Fatalf("admin deploys a: %d %s", rec.Code, rec.Body)
	}
	if slices.Contains(descs("b"), "pending") || !slices.Contains(descs("a"), "still mine") {
		t.Errorf("admin's deploy of a: a %v, b %v", descs("a"), descs("b"))
	}
	if rec := env.do("GET", "/api/deploy/check?instances=nope", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("check unknown instance: %d", rec.Code)
	}
}

// neighboursAgent has neighbours in instances a and b.
type neighboursAgent struct{ applyAgent }

func (*neighboursAgent) Neighbours(context.Context) (*agentapi.NeighboursResponse, error) {
	n := &agentapi.NeighboursResponse{}
	for _, inst := range []string{"a", "b"} {
		n.IP = append(n.IP, agentapi.IPNeighbour{Instance: inst, Interface: "eth0", Address: "192.0.2.1"})
		n.LLDP = append(n.LLDP, agentapi.LLDPNeighbour{Instance: inst, Interface: "eth0", SystemName: "sw"})
		n.LLDPPorts = append(n.LLDPPorts, agentapi.LLDPPort{Instance: inst, Interface: "eth0"})
	}
	return n, nil
}

func (*neighboursAgent) RateLimits(context.Context) (*agentapi.RateLimitsResponse, error) {
	r := &agentapi.RateLimitsResponse{Instances: map[string]map[string]agentapi.RateLimitStats{}}
	for _, inst := range []string{"a", "b"} {
		r.Instances[inst] = map[string]agentapi.RateLimitStats{"ssh": {DropPackets: 3}}
	}
	return r, nil
}
