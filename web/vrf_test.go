// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"slices"
	"testing"

	"github.com/abundo/portitor/internal/builder"
)

func TestVRF(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.vf("other")
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "addresses": []string{"192.0.2.1/24"}, "enabled": true})
	env.put("instance=main/interface=eth2", map[string]any{"kind": "physical", "addresses": []string{"198.51.100.1/24"}, "enabled": true})

	for what, c := range map[string]struct {
		name  string
		table int
	}{
		"table 0":          {"blue", 0},
		"main table":       {"blue", 254},
		"interface's name": {"eth1", 10},
		"bad name":         {"a%20b", 10},
	} {
		if rec := env.cfg("PUT", "instance=main/vrf="+c.name, map[string]any{"route-table": c.table}); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	env.put("instance=main/vrf=blue", map[string]any{"route-table": 10})
	// The same name and table in another virtual firewall.
	env.put("instance=other/vrf=blue", map[string]any{"route-table": 10})
	if rec := env.cfg("PUT", "instance=main/vrf=red", map[string]any{"route-table": 10}); rec.Code != http.StatusBadRequest {
		t.Errorf("duplicate table accepted: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("POST", "instance=main/vrf", map[string]any{"name": "blue", "route-table": 11}); rec.Code != http.StatusBadRequest {
		t.Errorf("duplicate name accepted: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("PUT", "instance=main/interface=blue", map[string]any{"kind": "physical", "enabled": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("interface named as a VRF accepted: %d %s", rec.Code, rec.Body)
	}

	// Interfaces join a VRF by name, of their own virtual firewall only.
	if rec := env.cfg("PATCH", "instance=main/interface=eth1", map[string]any{"vrf": "green"}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown VRF accepted: %d %s", rec.Code, rec.Body)
	}
	env.patch("instance=main/interface=eth1", map[string]any{"vrf": "blue"})
	env.patch("instance=main/interface=eth2", map[string]any{"vrf": "blue"})
	env.patch("instance=main/interface=eth2", map[string]any{"vrf": nil})
	env.post("instance=main/route", map[string]any{"destination": "default", "gateway": "192.0.2.254", "vrf": "blue", "enabled": true})

	// Renaming the VRF rewrites its interfaces; deleting it in use is refused.
	env.mustCfg("POST", "instance=main/vrf=blue?action=rename", map[string]any{"keys": []string{"cust1"}})
	if rec := env.cfg("DELETE", "instance=main/vrf=cust1", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete in use: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	in := doc.Instance("main")
	if len(in.VRFs) != 1 || in.VRFs[0].Name != "cust1" || in.VRFs[0].Table != 10 {
		t.Errorf("vrfs: %+v", in.VRFs)
	}
	if in.Interface("eth1").VRF != "cust1" || in.Interface("eth2").VRF != "" {
		t.Errorf("interfaces: %+v", in.Interfaces)
	}
	if len(in.Routes) != 1 || in.Routes[0].VRF != "cust1" || in.RouteTable(in.Routes[0]) != "10" {
		t.Errorf("routes: %+v", in.Routes)
	}
	exp := doc.Expand()
	if dev := exp.Instance("main").Interface("cust1"); dev == nil || !slices.Equal(dev.Members, []string{"eth1"}) {
		t.Errorf("vrf device: %+v", dev)
	}
	if v := doc.Instance("other").VRFs; len(v) != 1 || v[0].Name != "blue" {
		t.Errorf("other's vrfs: %+v", v)
	}
}

// BGP, OSPF and IS-IS of a VRF: their own configs and neighbours, which
// refer to its interfaces and peer groups only, and keep the VRF from
// being deleted while they run.
func TestVRFRouting(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/vrf=blue", map[string]any{"route-table": 10})
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "addresses": []string{"192.0.2.1/24"}, "enabled": true})
	env.put("instance=main/interface=eth2", map[string]any{"kind": "physical", "addresses": []string{"10.2.0.1/24"}, "enabled": true, "vrf": "blue"})

	env.put("instance=main/bgp=main", map[string]any{"enabled": true, "asn": 65000})
	env.put("instance=main/bgp=blue", map[string]any{"enabled": true, "asn": 65000})
	if rec := env.cfg("POST", "instance=main/bgp", map[string]any{"vrf": "blue", "asn": 65001}); rec.Code != http.StatusBadRequest {
		t.Errorf("second BGP config of the VRF: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("PATCH", "instance=main/bgp=blue", map[string]any{"evpn": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("EVPN in a VRF accepted: %d %s", rec.Code, rec.Body)
	}
	env.put("instance=main/bgp-peer-group=up", map[string]any{"remote-as": "65001", "vrf": "main"})
	env.put("instance=main/bgp-peer-group=ce", map[string]any{"vrf": "blue", "remote-as": "65002", "bfd": true})
	env.post("instance=main/bgp-neighbor", map[string]any{"address": "10.2.0.2", "enabled": true, "remote-as": "65002", "vrf": "main"})
	// The same address in the VRF is another neighbour.
	env.post("instance=main/bgp-neighbor", map[string]any{"vrf": "blue", "address": "10.2.0.2", "enabled": true, "peer-group": "ce", "v4-activate": true})
	for what, body := range map[string]map[string]any{
		"another VRF's peer group":        {"vrf": "blue", "address": "10.2.0.3", "enabled": true, "peer-group": "up"},
		"update source out of the VRF":    {"vrf": "blue", "address": "10.2.0.4", "enabled": true, "remote-as": "65002", "update-source": "eth1"},
		"link-local on another VRF's":     {"vrf": "blue", "address": "fe80::2", "interface": "eth1", "enabled": true, "remote-as": "65002"},
		"main neighbour, VRF's interface": {"vrf": "main", "address": "10.2.0.5", "enabled": true, "remote-as": "65002", "update-source": "eth2"},
	} {
		if rec := env.cfg("POST", "instance=main/bgp-neighbor", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}

	env.put("instance=main/ospf=2,main", map[string]any{"enabled": true})
	env.put("instance=main/ospf=2,blue", map[string]any{"enabled": true})
	env.post("instance=main/ospf-interface", map[string]any{"version": 2, "name": "eth1", "area": "0.0.0.0"})
	env.post("instance=main/ospf-interface", map[string]any{"version": 2, "name": "eth2", "area": "0.0.0.0"})
	if rec := env.cfg("PUT", "instance=main/isis=blue", map[string]any{"enabled": true, "net-interface": "eth1", "net-area": "49.0001"}); rec.Code != http.StatusBadRequest {
		t.Errorf("IS-IS NET from another VRF's interface accepted: %d %s", rec.Code, rec.Body)
	}
	env.put("instance=main/isis=blue", map[string]any{"enabled": true, "net-interface": "eth2", "net-area": "49.0001"})

	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	in := doc.Instance("main")
	v := in.VRFs[0]
	if v.BGP == nil || len(v.BGP.Neighbors) != 1 || v.BGP.Neighbors[0].PeerGroup != "ce" || len(v.BGP.PeerGroups) != 1 ||
		v.OSPF == nil || len(v.OSPF.Interfaces) != 1 || v.OSPF.Interfaces[0].Name != "eth2" || v.ISIS == nil || v.ISIS.NET != "49.0001.0100.0200.0001.00" {
		t.Errorf("vrf routing: %+v", v)
	}
	if len(in.BGP.Neighbors) != 1 || len(in.BGP.PeerGroups) != 1 || len(in.OSPF.Interfaces) != 1 || in.OSPF.Interfaces[0].Name != "eth1" {
		t.Errorf("main routing: %+v %+v", in.BGP, in.OSPF)
	}
	if rec := env.cfg("DELETE", "instance=main/vrf=blue", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete with routing: %d %s", rec.Code, rec.Body)
	}
}
