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

func TestISIS(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	eth := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "kind": "bridge", "enabled": true, "ipv4_mode": "static", "addresses": []string{"10.0.0.1/24", "fd00::1/64"}})
	env.create("/api/routing/route-maps", map[string]any{"instance_id": inst, "name": "out"})

	for what, body := range map[string]map[string]any{
		"no net":       {"instance_id": inst, "enabled": true},
		"bad net":      {"instance_id": inst, "net": "49.0001.1921.6800.1001"},
		"bad level":    {"instance_id": inst, "level": "level-2"},
		"unknown map":  {"instance_id": inst, "redistribute": []map[string]any{{"family": "ipv4", "source": "static", "level": "level-2", "route_map": "nope"}}},
		"bad source":   {"instance_id": inst, "redistribute": []map[string]any{{"family": "ipv4", "source": "rip", "level": "level-2"}}},
		"narrow+topo":  {"instance_id": inst, "metric_style": "narrow", "ipv6_topology": true},
		"default twic": {"instance_id": inst, "default_originate": []map[string]any{{"family": "ipv4", "level": "level-2"}, {"family": "ipv4", "level": "level-2"}}},
	} {
		if rec := env.do("POST", "/api/isis/config", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	// The NET is stored in lower case.
	rec := env.do("POST", "/api/isis/config", map[string]any{
		"instance_id": inst, "enabled": true, "net": " 49.0001.0A00.0000.0001.00 ", "level": "level-2-only",
		"redistribute": []map[string]any{{"family": "ipv4", "source": "connected", "level": "level-2", "route_map": "out"}},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var cfg models.IsisConfig
	_ = json.Unmarshal(rec.Body.Bytes(), &cfg)
	if cfg.Net != "49.0001.0a00.0000.0001.00" {
		t.Errorf("net %q", cfg.Net)
	}
	if rec := env.do("POST", "/api/isis/config", map[string]any{"instance_id": inst}); rec.Code < 400 {
		t.Errorf("second config: %d", rec.Code)
	}

	for what, body := range map[string]map[string]any{
		"unknown interface": {"instance_id": inst, "name": "eth9", "ipv4": true},
		"no family":         {"instance_id": inst, "name": "eth1"},
		"priority":          {"instance_id": inst, "name": "eth1", "ipv4": true, "priority": 200},
	} {
		if rec := env.do("POST", "/api/isis/interfaces", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	env.create("/api/isis/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "ipv4": true, "ipv6": true, "metric": 100})
	// Narrow metrics go up to 63.
	if rec := env.do("PUT", "/api/isis/config/"+itoa(cfg.ID), map[string]any{"metric_style": "narrow"}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "eth1") {
		t.Errorf("narrow: %d %s", rec.Code, rec.Body)
	}

	// Renaming the interface and the route map rewrites them; deleting
	// either is refused while IS-IS uses it.
	if rec := env.do("PUT", "/api/interfaces/"+itoa(eth), map[string]any{"name": "lan"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	var rm models.RouteMap
	env.srv.db.Where("instance_id = ? AND name = ?", inst, "out").First(&rm)
	if rec := env.do("PUT", "/api/routing/route-maps/"+itoa(rm.ID), map[string]any{"name": "export"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	var names []string
	env.srv.db.Model(&models.IsisInterface{}).Pluck("name", &names)
	env.srv.db.First(&cfg, cfg.ID)
	if strings.Join(names, ",") != "lan" || cfg.Redistribute[0].RouteMap != "export" {
		t.Errorf("not rewritten: %v %+v", names, cfg.Redistribute)
	}
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(eth), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "IS-IS") {
		t.Errorf("delete interface: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/routing/route-maps/"+itoa(rm.ID), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "IS-IS redistribute") {
		t.Errorf("delete route map: %d %s", rec.Code, rec.Body)
	}

	// Passwords are write-only: never answered, kept on a save without one.
	const areaPw, helloPw = "ar3aPw", "h3lloPw"
	if rec := env.do("PUT", "/api/isis/config/"+itoa(cfg.ID), map[string]any{"new_area_password": "two words"}); rec.Code != http.StatusBadRequest {
		t.Errorf("password with space: %d %s", rec.Code, rec.Body)
	}
	rec = env.do("PUT", "/api/isis/config/"+itoa(cfg.ID), map[string]any{"new_area_password": areaPw, "area_password_type": "clear"})
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), areaPw) || !strings.Contains(rec.Body.String(), `"has_area_password":true`) {
		t.Fatalf("area password: %d %s", rec.Code, rec.Body)
	}
	env.do("PUT", "/api/isis/config/"+itoa(cfg.ID), map[string]any{"overload": true})
	var ifs []models.IsisInterface
	env.srv.db.Find(&ifs)
	rec = env.do("PUT", "/api/isis/interfaces/"+itoa(ifs[0].ID), map[string]any{"new_password": helloPw})
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), helloPw) || !strings.Contains(rec.Body.String(), `"has_password":true`) {
		t.Fatalf("hello password: %d %s", rec.Code, rec.Body)
	}
	env.do("PUT", "/api/isis/interfaces/"+itoa(ifs[0].ID), map[string]any{"metric": 20})
	for _, path := range []string{"/api/isis/config?instance_id=" + itoa(inst), "/api/isis/interfaces?instance_id=" + itoa(inst)} {
		if rec := env.do("GET", path, nil); strings.Contains(rec.Body.String(), areaPw) || strings.Contains(rec.Body.String(), helloPw) {
			t.Errorf("password leaked: %s", rec.Body)
		}
	}

	// BGP and OSPF redistribute IS-IS.
	env.create("/api/bgp/config", map[string]any{"instance_id": inst, "enabled": true, "asn": 65000, "redist_isis_v4": true, "redist_isis_v4_map": "export"})
	env.create("/api/ospf/config", map[string]any{"instance_id": inst, "version": 2, "enabled": true, "redistribute": []map[string]any{{"source": "isis"}}})

	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	in := doc.Instance("main")
	if in.ISIS == nil || len(in.ISIS.Interfaces) != 1 || in.ISIS.Interfaces[0].Name != "lan" || len(in.RoutingPolicy.RouteMaps) != 1 ||
		in.ISIS.AreaPassword != areaPw || in.ISIS.AreaPasswordType != "clear" || in.ISIS.Interfaces[0].Password != helloPw || in.ISIS.Interfaces[0].Metric != 20 {
		t.Errorf("document: %+v", in.ISIS)
	}
	if len(in.BGP.Redistribute) != 1 || in.BGP.Redistribute[0].Source != "isis" || in.BGP.Redistribute[0].RouteMap != "export" ||
		in.OSPF == nil || in.OSPF.Redistribute[0].Source != "isis" {
		t.Errorf("redistribute: %+v %+v", in.BGP, in.OSPF)
	}
	if rec := env.do("DELETE", "/api/routing/route-maps/"+itoa(rm.ID), nil); !strings.Contains(rec.Body.String(), "BGP redistribute") {
		t.Errorf("BGP's reference not kept: %d %s", rec.Code, rec.Body)
	}
	var bgp models.BgpConfig
	env.srv.db.Where("instance_id = ?", inst).First(&bgp)
	env.do("PUT", "/api/bgp/config/"+itoa(bgp.ID), map[string]any{"enabled": false})
	var ospf models.OspfConfig
	env.srv.db.Where("instance_id = ?", inst).First(&ospf)
	env.do("PUT", "/api/ospf/config/"+itoa(ospf.ID), map[string]any{"enabled": false})
	env.do("PUT", "/api/isis/config/"+itoa(cfg.ID), map[string]any{"enabled": false})
	doc, _ = builder.Build(env.srv.db, 2)
	if in := doc.Instance("main"); in.ISIS != nil || !in.RoutingPolicy.Empty() {
		t.Errorf("off: %+v", in)
	}
}
