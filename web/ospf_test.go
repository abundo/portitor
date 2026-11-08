// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
)

func TestOSPF(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth1", map[string]any{"kind": "bridge", "enabled": true, "ipv4-mode": "static", "addresses": []string{"10.0.0.1/24", "fd00::1/64"}})
	env.post("instance=main/route-map", map[string]any{"name": "out"})
	v2, v3 := "instance=main/ospf=2,main", "instance=main/ospf=3,main"

	// Areas as numbers are stored dotted, prefixes masked.
	env.put(v2, map[string]any{"enabled": true, "router-id": "10.0.0.1", "area": []map[string]any{{"id": "1", "type": "stub", "no-summary": true}}, "range": []map[string]any{{"area": "1", "prefix": "10.1.0.1/16"}}, "redistribute": []map[string]any{{"source": "connected", "route-map": "out"}, {"source": "bgp"}}})
	cfg := env.node(v2)
	if cfg.Lists["area"][0].Leaf("id") != "0.0.0.1" || cfg.Lists["range"][0].Leaf("area") != "0.0.0.1" || cfg.Lists["range"][0].Leaf("prefix") != "10.1.0.0/16" {
		t.Errorf("not normalised: %+v %+v", cfg.Lists["area"][0].Leaves, cfg.Lists["range"][0].Leaves)
	}
	for what, body := range map[string]map[string]any{
		"v4 range in v3": {"range": []map[string]any{{"area": "0", "prefix": "10.0.0.0/8"}}},
		"v3 networks":    {"network": []map[string]any{{"area": "0", "prefix": "fd00::/64"}}},
		"unknown map":    {"redistribute": []map[string]any{{"source": "static", "route-map": "nope"}}},
		"backbone stub":  {"area": []map[string]any{{"id": "0", "type": "stub"}}},
	} {
		if rec := env.cfg("PUT", v3, body); rec.Code < 400 {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	if rec := env.cfg("PUT", "instance=main/ospf=4,main", map[string]any{}); rec.Code < 400 {
		t.Errorf("version 4 accepted: %d", rec.Code)
	}
	env.put(v3, map[string]any{"enabled": true})

	// Interfaces: of the instance, with a secret MD5 key (OSPFv2).
	const key = "s3cretk"
	for what, body := range map[string]map[string]any{
		"unknown interface": {"version": 2, "name": "eth9", "area": "0"},
		"bad area":          {"version": 2, "name": "eth1", "area": "backbone"},
		"v3 without area":   {"version": 3, "name": "eth1"},
		"dead below hello":  {"version": 2, "name": "eth1", "area": "0", "hello-interval": 10, "dead-interval": 5},
		"long key":          {"version": 2, "name": "eth1", "area": "0", "auth-key": strings.Repeat("k", 17)},
	} {
		if rec := env.cfg("POST", "instance=main/ospf-interface", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	env.post("instance=main/ospf-interface", map[string]any{"version": 2, "name": "eth1", "area": "0", "priority": 0, "auth-key": key})
	if i := env.node("instance=main/ospf-interface=2,eth1"); i.Leaf("area") != "0.0.0.0" || i.Leaf("auth-key-id") != "1" || i.Leaf("priority") != "0" {
		t.Errorf("%+v", i.Leaves)
	}
	if rec := env.cfg("POST", "instance=main/ospf-interface", map[string]any{"version": 2, "name": "eth1", "area": "0"}); rec.Code != http.StatusBadRequest {
		t.Errorf("interface twice: %d %s", rec.Code, rec.Body)
	}
	// An OSPFv3 interface gets no key.
	env.post("instance=main/ospf-interface", map[string]any{"version": 3, "name": "eth1", "area": "0.0.0.0", "auth-key": key})
	if i := env.node("instance=main/ospf-interface=3,eth1"); i.Leaf("auth-key") != "" {
		t.Errorf("v3 key kept")
	}
	env.patch("instance=main/ospf-interface=2,eth1", map[string]any{"cost": 5})
	if i := env.node("instance=main/ospf-interface=2,eth1"); i.Leaf("auth-key") != key || i.Leaf("cost") != "5" {
		t.Errorf("stored %+v", i.Leaves)
	}
	if rec := env.do("GET", "/api/config/candidate/instance=main/ospf-interface", nil); strings.Contains(rec.Body.String(), key) {
		t.Errorf("key leaked: %s", rec.Body)
	}

	// Network statements and interface areas don't mix.
	if rec := env.cfg("PATCH", v2, map[string]any{"network": []map[string]any{{"prefix": "10.0.0.0/24", "area": "0"}}}); rec.Code != http.StatusBadRequest {
		t.Errorf("networks with interface areas: %d %s", rec.Code, rec.Body)
	}

	// Renaming the interface and the route map rewrites them; deleting
	// either is refused while OSPF uses it.
	env.mustCfg("POST", "instance=main/interface=eth1?action=rename", map[string]any{"keys": []string{"lan"}})
	env.mustCfg("POST", "instance=main/route-map=out?action=rename", map[string]any{"keys": []string{"export"}})
	if env.node("instance=main/ospf-interface=2,lan") == nil || env.node("instance=main/ospf-interface=3,lan") == nil ||
		env.node(v2+"/redistribute=connected").Leaf("route-map") != "export" {
		t.Error("not rewritten")
	}
	if rec := env.cfg("DELETE", "instance=main/interface=lan", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete interface: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("DELETE", "instance=main/route-map=export", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete route map: %d %s", rec.Code, rec.Body)
	}

	// BGP redistributes OSPF.
	env.put("instance=main/bgp=main", map[string]any{"enabled": true, "asn": 65000, "redist-ospf-v4": true, "redist-ospf-v4-map": "export", "redist-ospf-v6": true})

	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	in := doc.Instance("main")
	if in.OSPF == nil || in.OSPF6 == nil || len(in.OSPF.Interfaces) != 1 || in.OSPF.Interfaces[0].AuthKey != key || in.OSPF.Interfaces[0].Name != "lan" ||
		len(in.OSPF6.Interfaces) != 1 || len(in.RoutingPolicy.RouteMaps) != 1 || len(in.BGP.Redistribute) != 2 || in.BGP.Redistribute[0].RouteMap != "export" {
		t.Errorf("document: %+v %+v %+v", in.OSPF, in.OSPF6, in.BGP)
	}

	// With BGP off, OSPF keeps the routing policy in the document; with
	// both off, neither is there.
	env.patch("instance=main/bgp=main", map[string]any{"enabled": false})
	doc, _ = builder.Build(env.input(), 2)
	if in := doc.Instance("main"); in.BGP != nil || in.OSPF == nil || in.RoutingPolicy.Empty() {
		t.Errorf("OSPF only: %+v", in)
	}
	env.patch(v2, map[string]any{"enabled": false})
	env.patch(v3, map[string]any{"enabled": false})
	doc, _ = builder.Build(env.input(), 3)
	if in := doc.Instance("main"); in.OSPF != nil || in.OSPF6 != nil || !in.RoutingPolicy.Empty() {
		t.Errorf("all off: %+v", in)
	}
}
