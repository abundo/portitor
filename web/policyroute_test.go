// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
)

func TestPolicyRoutes(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.vf("guest")
	env.put("instance=main/interface=eth2", map[string]any{"kind": "physical", "enabled": true, "ipv4-mode": "static", "addresses": []string{"192.0.2.2/24", "2001:db8::2/64"}})
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "enabled": true, "ipv4-mode": "static", "addresses": []string{"10.0.0.1/24"}})
	env.put("instance=guest/interface=eth5", map[string]any{"kind": "physical", "enabled": true, "ipv4-mode": "static", "addresses": []string{"10.5.0.1/24"}})
	env.put("instance=main/interface-zone=lan", map[string]any{"interfaces": []string{"eth1"}})
	env.put("host=isp2", map[string]any{"addresses": []string{"192.0.2.1", "2001:db8::1"}})
	env.put("host=office", map[string]any{"addresses": []string{"10.50.0.0/16"}})

	routed := env.post("instance=main/policy-route", map[string]any{"in-interfaces": []string{"lan"}, "src-addrs": []string{"10.0.0.0/25"}, "services": []string{"https"}, "gateway": "isp2", "interface": "eth2", "enabled": true, "description": " second ISP "})
	except := env.post("instance=main/policy-route", map[string]any{"dst-addrs": []string{"office"}, "enabled": true})
	env.post("instance=main/policy-route", map[string]any{"gateway": "192.0.2.9", "enabled": false})
	for what, body := range map[string]map[string]any{
		"unknown interface": {"in-interfaces": []string{"eth9"}},
		"bad gateway":       {"gateway": "192.0.2.300"},
		"unknown host":      {"gateway": "nope"},
		"unknown service":   {"services": []string{"nope"}},
		"foreign interface": {"interface": "eth5"},
		"bad family":        {"family": "ipv5"},
	} {
		if rec := env.cfg("POST", "instance=main/policy-route", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}

	// Renames follow; a zone in use stays.
	env.mustCfg("POST", "host=isp2?action=rename", map[string]any{"keys": []string{"isp-b"}})
	env.mustCfg("POST", "instance=main/interface-zone=lan?action=rename", map[string]any{"keys": []string{"inside"}})
	if rec := env.cfg("DELETE", "instance=main/interface-zone=inside", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("zone in use deleted: %d %s", rec.Code, rec.Body)
	}
	if p := env.node("instance=main/policy-route=" + routed); p.Leaf("gateway") != "isp-b" || strings.Join(p.LeafLists["in-interfaces"], ",") != "inside" || p.Leaf("description") != "second ISP" {
		t.Errorf("not kept up: %+v %v", p.Leaves, p.LeafLists)
	}

	// The exception first.
	env.mustCfg("POST", "instance=main/policy-route="+except+"?action=move", map[string]any{"where": "first"})
	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(doc.Instance("main").PolicyRoutes)
	if string(got) != `[{"dst_addrs":["10.50.0.0/16"]},`+
		`{"in_interfaces":["inside"],"src_addrs":["10.0.0.0/25"],"services":[{"protocol":"tcp","dst_ports":"443"},{"protocol":"udp","dst_ports":"443"}],"gateways":["192.0.2.1","2001:db8::1"],"interface":"eth2","description":"second ISP"}]` {
		t.Errorf("document: %s", got)
	}
	if err := doc.Validate(); err != nil {
		t.Error(err)
	}
}
