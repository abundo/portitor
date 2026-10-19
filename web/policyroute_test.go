// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

func TestPolicyRoutes(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	other := env.create("/api/instances", map[string]any{"name": "guest"})
	wan2 := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth2", "kind": "physical", "enabled": true, "ipv4_mode": "static", "addresses": []string{"192.0.2.2/24", "2001:db8::2/64"}})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "kind": "physical", "enabled": true, "ipv4_mode": "static", "addresses": []string{"10.0.0.1/24"}})
	foreign := env.create("/api/interfaces", map[string]any{"instance_id": other, "name": "eth5", "kind": "physical", "enabled": true, "ipv4_mode": "static", "addresses": []string{"10.5.0.1/24"}})
	zone := env.create("/api/interface-zones", map[string]any{"instance_id": inst, "name": "lan", "interfaces": []string{"eth1"}})
	gw := env.create("/api/objects", map[string]any{"name": "isp2", "addresses": []string{"192.0.2.1", "2001:db8::1"}})
	env.create("/api/objects", map[string]any{"name": "office", "addresses": []string{"10.50.0.0/16"}})

	routed := env.create("/api/policy-routes", map[string]any{"instance_id": inst, "in_interfaces": []string{"lan", "lan"}, "src_addrs": []string{"10.0.0.0/25"},
		"services": []string{"https"}, "gateway": "isp2", "interface_id": wan2, "enabled": true, "description": " second ISP "})
	except := env.create("/api/policy-routes", map[string]any{"instance_id": inst, "dst_addrs": []string{"office"}, "enabled": true})
	env.create("/api/policy-routes", map[string]any{"instance_id": inst, "gateway": "192.0.2.9", "enabled": false})
	for what, body := range map[string]map[string]any{
		"unknown interface": {"instance_id": inst, "in_interfaces": []string{"eth9"}},
		"bad gateway":       {"instance_id": inst, "gateway": "192.0.2.300"},
		"unknown host":      {"instance_id": inst, "gateway": "nope"},
		"unknown service":   {"instance_id": inst, "services": []string{"nope"}},
		"foreign interface": {"instance_id": inst, "interface_id": foreign},
		"bad family":        {"instance_id": inst, "family": "ipv5"},
	} {
		if rec := env.do("POST", "/api/policy-routes", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}

	// Renames follow; a zone in use stays.
	if rec := env.do("PUT", "/api/objects/"+itoa(gw), map[string]any{"name": "isp-b"}); rec.Code != http.StatusOK {
		t.Fatalf("rename host: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/interface-zones/"+itoa(zone), map[string]any{"name": "inside"}); rec.Code != http.StatusOK {
		t.Fatalf("rename zone: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/interface-zones/"+itoa(zone), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("zone in use deleted: %d %s", rec.Code, rec.Body)
	}
	var p models.PolicyRoute
	env.srv.db.First(&p, routed)
	if p.Gateway != "isp-b" || len(p.InInterfaces) != 1 || p.InInterfaces[0] != "inside" || p.Description != "second ISP" {
		t.Errorf("not kept up: %+v", p)
	}

	// The exception first.
	if rec := env.do("POST", "/api/policy-routes/reorder", map[string]any{"ids": []uint{except, routed}}); rec.Code != http.StatusNoContent {
		t.Fatalf("reorder: %d %s", rec.Code, rec.Body)
	}
	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	var in *fwconfig.Instance
	for i := range doc.Instances {
		if doc.Instances[i].Name == "main" {
			in = &doc.Instances[i]
		}
	}
	got, _ := json.Marshal(in.PolicyRoutes)
	if string(got) != `[{"dst_addrs":["10.50.0.0/16"]},`+
		`{"in_interfaces":["inside"],"src_addrs":["10.0.0.0/25"],"services":[{"protocol":"tcp","dst_ports":"443"},{"protocol":"udp","dst_ports":"443"}],"gateways":["192.0.2.1","2001:db8::1"],"interface":"eth2","description":"second ISP"}]` {
		t.Errorf("document: %s", got)
	}
	if err := doc.Validate(); err != nil {
		t.Error(err)
	}
}
