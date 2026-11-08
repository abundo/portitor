// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
)

func TestISIS(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth1", map[string]any{"kind": "bridge", "enabled": true, "ipv4-mode": "static", "addresses": []string{"10.0.0.1/24", "fd00::1/64"}})
	env.post("instance=main/route-map", map[string]any{"name": "out"})
	isis := "instance=main/isis=main"

	for what, body := range map[string]map[string]any{
		"no net":      {"enabled": true},
		"bad net":     {"net": "49.0001.1921.6800.1001"},
		"bad level":   {"level": "level-2"},
		"unknown map": {"redistribute": []map[string]any{{"family": "ipv4", "source": "static", "level": "level-2", "route-map": "nope"}}},
		"bad source":  {"redistribute": []map[string]any{{"family": "ipv4", "source": "rip", "level": "level-2"}}},
		"narrow+topo": {"metric-style": "narrow", "ipv6-topology": true},
	} {
		if rec := env.cfg("PUT", isis, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	// The NET is stored in lower case.
	env.put(isis, map[string]any{"enabled": true, "net": " 49.0001.0A00.0000.0001.00 ", "level": "level-2-only", "redistribute": []map[string]any{{"family": "ipv4", "source": "connected", "level": "level-2", "route-map": "out"}}})
	if net := env.node(isis).Leaf("net"); net != "49.0001.0a00.0000.0001.00" {
		t.Errorf("net %q", net)
	}
	// The NET made from an interface's IPv4 address.
	if rec := env.cfg("PATCH", isis, map[string]any{"net-interface": "eth9", "net-area": "49.0002"}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown NET interface: %d", rec.Code)
	}
	if rec := env.cfg("PATCH", isis, map[string]any{"net-interface": "eth1", "net-area": "49.2"}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad area: %d", rec.Code)
	}
	env.patch(isis, map[string]any{"net-interface": "eth1", "net-area": "49.0002"})
	if net := env.node(isis).Leaf("net"); net != "49.0002.0100.0000.0001.00" {
		t.Errorf("NET from eth1: %q", net)
	}
	env.patch(isis, map[string]any{"net-interface": nil, "net": "49.0001.0a00.0000.0001.00"})

	for what, body := range map[string]map[string]any{
		"unknown interface": {"name": "eth9", "ipv4": true},
		"no family":         {"name": "eth1", "ipv4": false, "ipv6": false},
		"priority":          {"name": "eth1", "ipv4": true, "priority": 200},
	} {
		if rec := env.cfg("POST", "instance=main/isis-interface", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	env.post("instance=main/isis-interface", map[string]any{"name": "eth1", "ipv4": true, "ipv6": true, "metric": 100})
	// Narrow metrics go up to 63.
	if rec := env.cfg("PATCH", isis, map[string]any{"metric-style": "narrow"}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "eth1") {
		t.Errorf("narrow: %d %s", rec.Code, rec.Body)
	}

	// Renaming the interface and the route map rewrites them; deleting
	// either is refused while IS-IS uses it.
	env.mustCfg("POST", "instance=main/interface=eth1?action=rename", map[string]any{"keys": []string{"lan"}})
	env.mustCfg("POST", "instance=main/route-map=out?action=rename", map[string]any{"keys": []string{"export"}})
	if env.node("instance=main/isis-interface=lan") == nil || env.node(isis).Lists["redistribute"][0].Leaf("route-map") != "export" {
		t.Errorf("not rewritten")
	}
	if rec := env.cfg("DELETE", "instance=main/interface=lan", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete interface: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("DELETE", "instance=main/route-map=export", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete route map: %d %s", rec.Code, rec.Body)
	}

	// Passwords are secrets: never answered, kept by a replace without.
	const areaPw, helloPw = "ar3aPw", "h3lloPw"
	if rec := env.cfg("PATCH", isis, map[string]any{"area-password": "two words"}); rec.Code != http.StatusBadRequest {
		t.Errorf("password with space: %d %s", rec.Code, rec.Body)
	}
	env.patch(isis, map[string]any{"area-password": areaPw, "area-password-type": "clear"})
	env.patch(isis, map[string]any{"overload": true})
	env.patch("instance=main/isis-interface=lan", map[string]any{"password": helloPw})
	env.patch("instance=main/isis-interface=lan", map[string]any{"metric": 20})
	for _, path := range []string{isis, "instance=main/isis-interface"} {
		if rec := env.do("GET", "/api/config/candidate/"+path, nil); strings.Contains(rec.Body.String(), areaPw) || strings.Contains(rec.Body.String(), helloPw) {
			t.Errorf("password leaked: %s", rec.Body)
		}
	}

	// BGP and OSPF redistribute IS-IS.
	env.put("instance=main/bgp=main", map[string]any{"enabled": true, "asn": 65000, "redist-isis-v4": true, "redist-isis-v4-map": "export"})
	env.put("instance=main/ospf=2,main", map[string]any{"enabled": true, "redistribute": []map[string]any{{"source": "isis"}}})

	doc, err := builder.Build(env.input(), 1)
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
	env.patch("instance=main/bgp=main", map[string]any{"enabled": false})
	env.patch("instance=main/ospf=2,main", map[string]any{"enabled": false})
	env.patch(isis, map[string]any{"enabled": false})
	doc, _ = builder.Build(env.input(), 2)
	if in := doc.Instance("main"); in.ISIS != nil || !in.RoutingPolicy.Empty() {
		t.Errorf("off: %+v", in)
	}
}
