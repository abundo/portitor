// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/models"
)

func TestOSPF(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	eth := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "kind": "bridge", "enabled": true, "ipv4_mode": "static", "addresses": []string{"10.0.0.1/24", "fd00::1/64"}})
	env.create("/api/routing/route-maps", map[string]any{"instance_id": inst, "name": "out"})

	// Areas as numbers are stored dotted, prefixes masked.
	rec := env.do("POST", "/api/ospf/config", map[string]any{
		"instance_id": inst, "version": 2, "enabled": true, "router_id": "10.0.0.1",
		"areas":        []map[string]any{{"id": "1", "type": "stub", "no_summary": true}},
		"ranges":       []map[string]any{{"area": "1", "prefix": "10.1.0.1/16"}},
		"redistribute": []map[string]any{{"source": "connected", "route_map": "out"}, {"source": "bgp"}},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var cfg models.OspfConfig
	_ = json.Unmarshal(rec.Body.Bytes(), &cfg)
	if cfg.Areas[0].ID != "0.0.0.1" || cfg.Ranges[0].Area != "0.0.0.1" || cfg.Ranges[0].Prefix != "10.1.0.0/16" {
		t.Errorf("not normalised: %+v %+v", cfg.Areas, cfg.Ranges)
	}
	for what, body := range map[string]map[string]any{
		"second v2":      {"instance_id": inst, "version": 2},
		"bad version":    {"instance_id": inst, "version": 4},
		"v6 range in v2": {"instance_id": inst, "version": 3, "ranges": []map[string]any{{"area": "0", "prefix": "10.0.0.0/8"}}},
		"v3 networks":    {"instance_id": inst, "version": 3, "networks": []map[string]any{{"area": "0", "prefix": "fd00::/64"}}},
		"unknown map":    {"instance_id": inst, "version": 3, "redistribute": []map[string]any{{"source": "static", "route_map": "nope"}}},
		"backbone stub":  {"instance_id": inst, "version": 3, "areas": []map[string]any{{"id": "0", "type": "stub"}}},
	} {
		if rec := env.do("POST", "/api/ospf/config", body); rec.Code < 400 {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	env.create("/api/ospf/config", map[string]any{"instance_id": inst, "version": 3, "enabled": true})

	// Interfaces: of the instance, with a write-only MD5 key (OSPFv2).
	const key = "s3cretk"
	for what, body := range map[string]map[string]any{
		"unknown interface": {"instance_id": inst, "version": 2, "name": "eth9", "area": "0"},
		"bad area":          {"instance_id": inst, "version": 2, "name": "eth1", "area": "backbone"},
		"v3 without area":   {"instance_id": inst, "version": 3, "name": "eth1"},
		"dead below hello":  {"instance_id": inst, "version": 2, "name": "eth1", "area": "0", "hello_interval": 10, "dead_interval": 5},
		"long key":          {"instance_id": inst, "version": 2, "name": "eth1", "area": "0", "new_auth_key": strings.Repeat("k", 17)},
	} {
		if rec := env.do("POST", "/api/ospf/interfaces", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	rec = env.do("POST", "/api/ospf/interfaces", map[string]any{"instance_id": inst, "version": 2, "name": "eth1", "area": "0", "priority": 0, "new_auth_key": key})
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), key) || !strings.Contains(rec.Body.String(), `"has_auth_key":true`) {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var v2if models.OspfInterface
	_ = json.Unmarshal(rec.Body.Bytes(), &v2if)
	if v2if.Area != "0.0.0.0" || v2if.AuthKeyID != 1 || v2if.Priority == nil || *v2if.Priority != 0 {
		t.Errorf("%+v", v2if)
	}
	if rec := env.do("POST", "/api/ospf/interfaces", map[string]any{"instance_id": inst, "version": 2, "name": "eth1", "area": "0"}); rec.Code != http.StatusConflict {
		t.Errorf("interface twice: %d %s", rec.Code, rec.Body)
	}
	// An OSPFv3 interface gets no key.
	rec = env.do("POST", "/api/ospf/interfaces", map[string]any{"instance_id": inst, "version": 3, "name": "eth1", "area": "0.0.0.0", "new_auth_key": key})
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"has_auth_key":false`) {
		t.Fatalf("v3: %d %s", rec.Code, rec.Body)
	}
	// Saving without a key keeps it.
	if rec := env.do("PUT", "/api/ospf/interfaces/"+itoa(v2if.ID), map[string]any{"cost": 5}); rec.Code != http.StatusOK {
		t.Fatal(rec.Body)
	}
	var stored models.OspfInterface
	env.srv.db.First(&stored, v2if.ID)
	if stored.AuthKey != key || stored.Cost != 5 {
		t.Errorf("stored %+v", stored)
	}
	if rec := env.do("GET", "/api/ospf/interfaces?instance_id="+itoa(inst), nil); strings.Contains(rec.Body.String(), key) {
		t.Errorf("key leaked: %s", rec.Body)
	}

	// Network statements and interface areas don't mix.
	if rec := env.do("PUT", "/api/ospf/config/"+itoa(cfg.ID), map[string]any{"networks": []map[string]any{{"prefix": "10.0.0.0/24", "area": "0"}}}); rec.Code != http.StatusBadRequest {
		t.Errorf("networks with interface areas: %d %s", rec.Code, rec.Body)
	}

	// Renaming the interface and the route map rewrites them; deleting
	// either is refused while OSPF uses it.
	if rec := env.do("PUT", "/api/interfaces/"+itoa(eth), map[string]any{"name": "lan"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	var rm models.RouteMap
	env.srv.db.Where("instance_id = ? AND name = ?", inst, "out").First(&rm)
	if rec := env.do("PUT", "/api/routing/route-maps/"+itoa(rm.ID), map[string]any{"name": "export"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	var names []string
	env.srv.db.Model(&models.OspfInterface{}).Pluck("name", &names)
	env.srv.db.First(&cfg, cfg.ID)
	if strings.Join(names, ",") != "lan,lan" || cfg.Redistribute[0].RouteMap != "export" {
		t.Errorf("not rewritten: %v %+v", names, cfg.Redistribute)
	}
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(eth), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "OSPFv2, OSPFv3") {
		t.Errorf("delete interface: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/routing/route-maps/"+itoa(rm.ID), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "OSPFv2 redistribute connected") {
		t.Errorf("delete route map: %d %s", rec.Code, rec.Body)
	}

	// BGP redistributes OSPF.
	env.create("/api/bgp/config", map[string]any{"instance_id": inst, "enabled": true, "asn": 65000, "redist_ospf_v4": true, "redist_ospf_v4_map": "export", "redist_ospf_v6": true})

	doc, err := builder.Build(env.srv.db, 1)
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
	var bgp models.BgpConfig
	env.srv.db.Where("instance_id = ?", inst).First(&bgp)
	env.do("PUT", "/api/bgp/config/"+itoa(bgp.ID), map[string]any{"enabled": false})
	doc, _ = builder.Build(env.srv.db, 2)
	if in := doc.Instance("main"); in.BGP != nil || in.OSPF == nil || in.RoutingPolicy.Empty() {
		t.Errorf("OSPF only: %+v", in)
	}
	var v3 models.OspfConfig
	env.srv.db.Where("instance_id = ? AND version = 3", inst).First(&v3)
	env.do("PUT", "/api/ospf/config/"+itoa(cfg.ID), map[string]any{"enabled": false})
	env.do("PUT", "/api/ospf/config/"+itoa(v3.ID), map[string]any{"enabled": false})
	doc, _ = builder.Build(env.srv.db, 3)
	if in := doc.Instance("main"); in.OSPF != nil || in.OSPF6 != nil || !in.RoutingPolicy.Empty() {
		t.Errorf("all off: %+v", in)
	}
}
