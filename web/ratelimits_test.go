// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

func TestRateLimits(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	other := env.create("/api/instances", map[string]any{"name": "guest"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "enabled": true, "shape_egress": 40, "shape_ingress": 400})
	if rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": inst, "name": "ifb-eth0"}); rec.Code != http.StatusBadRequest {
		t.Errorf("ifb- interface name accepted: %d", rec.Code)
	}
	ssh := env.create("/api/rate-limits", map[string]any{"instance_id": inst, "name": " ssh ", "rate": 4, "per": "minute", "burst": 2, "per_source": true})
	sshURL := fmt.Sprint("/api/rate-limits/", ssh)
	env.create("/api/rate-limits", map[string]any{"instance_id": other, "name": "theirs", "rate": 1, "per": "second"})
	for _, body := range []map[string]any{
		{"instance_id": inst, "name": "zero", "rate": 0, "per": "second"},
		{"instance_id": inst, "name": "bytes", "rate": 1, "unit": "mbytes", "per": "second", "connections": true},
		{"instance_id": inst, "name": "burst", "rate": 1, "per": "second", "burst": -1},
		{"instance_id": inst, "name": "ssh", "rate": 1, "per": "second"},
		{"instance_id": inst, "name": "bytes", "rate": 1, "unit": "mbytes", "per": "second"},
		{"instance_id": inst, "name": "bits", "rate": 1, "unit": "mbits", "per": "second", "connections": true},
	} {
		if rec := env.do("POST", "/api/rate-limits", body); rec.Code < 400 {
			t.Errorf("%v accepted: %d", body, rec.Code)
		}
	}

	rule := env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "input", "action": "accept", "in_interfaces": []string{"eth0"}, "rate_limit": "ssh", "enabled": true})
	if rec := env.do("POST", "/api/rules", map[string]any{"instance_id": inst, "chain": "input", "action": "accept", "rate_limit": "theirs"}); rec.Code != http.StatusBadRequest {
		t.Errorf("other instance's rate limit accepted: %d", rec.Code)
	}

	// A limit that polices connections needs accept rules.
	env.create("/api/rate-limits", map[string]any{"instance_id": inst, "name": "host", "rate": 2, "unit": "mbit", "connections": true, "per_source": true})
	if rec := env.do("POST", "/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "drop", "rate_limit": "host"}); rec.Code != http.StatusBadRequest {
		t.Errorf("drop rule with a connection limit accepted: %d", rec.Code)
	}
	env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "accept", "rate_limit": "host", "enabled": true})
	drop := env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "input", "action": "drop", "rate_limit": "ssh"})
	if rec := env.do("PUT", sshURL, map[string]any{"connections": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("connections on a limit a drop rule names: %d", rec.Code)
	}
	env.do("DELETE", fmt.Sprint("/api/rules/", drop), nil)

	if rec := env.do("PUT", sshURL, map[string]any{"name": "admin"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	var r models.Rule
	env.srv.db.First(&r, rule)
	if r.RateLimit != "admin" {
		t.Errorf("rule after rename: %q", r.RateLimit)
	}
	rec := env.do("DELETE", sshURL, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "input rule") {
		t.Errorf("delete in use: %d %s", rec.Code, rec.Body)
	}

	// Shaping: accept rules only; a rate per second in bytes or bits.
	if rec := env.do("POST", "/api/rate-limits", map[string]any{"instance_id": inst, "name": "pk", "rate": 5, "unit": "mbytes", "shape": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("shaping in mbytes accepted: %d", rec.Code)
	}
	var dm models.RateLimit
	env.srv.db.First(&dm, env.create("/api/rate-limits", map[string]any{"instance_id": inst, "name": "dflt", "rate": 5, "shape": true}))
	if dm.Unit != "mbit" {
		t.Errorf("shaping unit defaults to %q", dm.Unit)
	}
	env.do("DELETE", fmt.Sprint("/api/rate-limits/", dm.ID), nil)
	bulk := env.create("/api/rate-limits", map[string]any{"instance_id": inst, "name": "bulk", "rate": 50, "unit": "mbit", "per": "minute", "burst": 3, "per_source": true, "shape": true})
	var bl models.RateLimit
	env.srv.db.First(&bl, bulk)
	if bl.Per != "second" || bl.Burst != 0 || bl.PerSource {
		t.Errorf("shaping kept limit fields: %+v", bl)
	}
	if rec := env.do("POST", "/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "reject", "rate_limit": "bulk"}); rec.Code != http.StatusBadRequest {
		t.Errorf("reject rule that shapes accepted: %d", rec.Code)
	}
	env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "accept", "rate_limit": "bulk", "enabled": true})

	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	main := doc.Instances[0]
	want := []fwconfig.RateLimit{
		{Name: "admin", Rate: 4, Per: "second", Burst: 2, PerSource: true},
		{Name: "bulk", Rate: 50, Unit: "mbit", Per: "second", Shape: true},
		{Name: "host", Rate: 2, Unit: "mbit", Per: "second", PerSource: true, Connections: true},
	}
	if len(main.RateLimits) != 3 || main.RateLimits[0] != want[0] || main.RateLimits[1] != want[1] || main.RateLimits[2] != want[2] {
		t.Errorf("rate limits: %+v", main.RateLimits)
	}
	if sh := main.Shapers(); len(sh) != 1 || sh[0].Name != "bulk" || sh[0].Bits() != 50000000 {
		t.Errorf("shapers: %+v", sh)
	}
	if ifc := main.Interfaces[0]; ifc.ShapeEgress != 40 || ifc.ShapeIngress != 400 {
		t.Errorf("shaping: %+v", ifc)
	}
}
