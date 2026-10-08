// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/models"
)

func TestVRF(t *testing.T) {
	env := newEnv(t)
	a := env.create("/api/instances", map[string]any{"name": "main"})
	b := env.create("/api/instances", map[string]any{"name": "other"})
	env.create("/api/interfaces", map[string]any{"instance_id": a, "name": "eth1", "addresses": []string{"192.0.2.1/24"}, "enabled": true})
	eth2 := env.create("/api/interfaces", map[string]any{"instance_id": a, "name": "eth2", "addresses": []string{"198.51.100.1/24"}, "enabled": true})

	vrf := func(inst uint, name string, table int) map[string]any {
		return map[string]any{"instance_id": inst, "name": name, "route_table": table}
	}
	for what, body := range map[string]map[string]any{
		"table 0":          vrf(a, "blue", 0),
		"main table":       vrf(a, "blue", 254),
		"interface's name": vrf(a, "eth1", 10),
		"bad name":         vrf(a, "a b", 10),
	} {
		if rec := env.do("POST", "/api/vrfs", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	blue := env.create("/api/vrfs", vrf(a, "blue", 10))
	// The same name and table in another virtual firewall.
	otherBlue := env.create("/api/vrfs", vrf(b, "blue", 10))
	for what, body := range map[string]map[string]any{
		"duplicate table": vrf(a, "red", 10),
		"duplicate name":  vrf(a, "blue", 11),
	} {
		if rec := env.do("POST", "/api/vrfs", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	if rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": a, "name": "blue", "enabled": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("interface named as a VRF accepted: %d %s", rec.Code, rec.Body)
	}

	// Interfaces join a VRF by name, of their own virtual firewall only.
	var eth1 models.Interface
	env.srv.db.Where("instance_id = ? AND name = ?", a, "eth1").First(&eth1)
	if rec := env.do("PUT", "/api/interfaces/"+itoa(eth1.ID), map[string]any{"vrf": "green"}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown VRF accepted: %d %s", rec.Code, rec.Body)
	}
	for _, id := range []uint{eth1.ID, eth2} {
		if rec := env.do("PUT", "/api/interfaces/"+itoa(id), map[string]any{"vrf": "blue"}); rec.Code != http.StatusOK {
			t.Fatalf("join: %d %s", rec.Code, rec.Body)
		}
	}
	// Moved out again.
	if rec := env.do("PUT", "/api/interfaces/"+itoa(eth2), map[string]any{"vrf": ""}); rec.Code != http.StatusOK {
		t.Fatalf("leave: %d %s", rec.Code, rec.Body)
	}
	env.create("/api/routes", map[string]any{"instance_id": a, "destination": "default", "gateway": "192.0.2.254", "vrf_id": blue, "enabled": true})
	if rec := env.do("POST", "/api/routes", map[string]any{"instance_id": a, "destination": "10.0.0.0/8", "gateway": "192.0.2.254", "vrf_id": otherBlue, "enabled": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("another VF's VRF accepted: %d %s", rec.Code, rec.Body)
	}

	// Renaming the VRF rewrites its interfaces; deleting it in use is refused.
	if rec := env.do("PUT", "/api/vrfs/"+itoa(blue), map[string]any{"name": "cust1"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/vrfs/"+itoa(blue), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "interface eth1") {
		t.Errorf("delete in use: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.srv.db, 1)
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
// stay in it, refer to its interfaces and peer groups only, and keep the
// VRF from being deleted while they run.
func TestVRFRouting(t *testing.T) {
	env := newEnv(t)
	a := env.create("/api/instances", map[string]any{"name": "main"})
	blue := env.create("/api/vrfs", map[string]any{"instance_id": a, "name": "blue", "route_table": 10})
	env.create("/api/interfaces", map[string]any{"instance_id": a, "name": "eth1", "addresses": []string{"192.0.2.1/24"}, "enabled": true})
	env.create("/api/interfaces", map[string]any{"instance_id": a, "name": "eth2", "addresses": []string{"10.2.0.1/24"}, "enabled": true, "vrf": "blue"})

	env.create("/api/bgp/config", map[string]any{"instance_id": a, "enabled": true, "asn": 65000})
	cfg := env.create("/api/bgp/config", map[string]any{"instance_id": a, "vrf_id": blue, "enabled": true, "asn": 65000})
	if rec := env.do("POST", "/api/bgp/config", map[string]any{"instance_id": a, "vrf_id": blue, "asn": 65001}); rec.Code != http.StatusConflict {
		t.Errorf("second BGP config of the VRF: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/bgp/config/"+itoa(cfg), map[string]any{"evpn": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("EVPN in a VRF accepted: %d %s", rec.Code, rec.Body)
	}
	env.create("/api/bgp/peer-groups", map[string]any{"instance_id": a, "name": "up", "remote_as": "65001"})
	env.create("/api/bgp/peer-groups", map[string]any{"instance_id": a, "vrf_id": blue, "name": "ce", "remote_as": "65002", "bfd": true})
	nbr := env.create("/api/bgp/neighbors", map[string]any{"instance_id": a, "address": "10.2.0.2", "enabled": true, "remote_as": "65002"})
	// The same address in the VRF is another neighbour.
	env.create("/api/bgp/neighbors", map[string]any{"instance_id": a, "vrf_id": blue, "address": "10.2.0.2", "enabled": true, "peer_group": "ce", "v4_activate": true})
	for what, body := range map[string]map[string]any{
		"another VRF's peer group":        {"instance_id": a, "vrf_id": blue, "address": "10.2.0.3", "enabled": true, "peer_group": "up"},
		"update source out of the VRF":    {"instance_id": a, "vrf_id": blue, "address": "10.2.0.4", "enabled": true, "remote_as": "65002", "update_source": "eth1"},
		"link-local on another VRF's":     {"instance_id": a, "vrf_id": blue, "address": "fe80::2", "interface": "eth1", "enabled": true, "remote_as": "65002"},
		"main neighbour, VRF's interface": {"instance_id": a, "address": "10.2.0.5", "enabled": true, "remote_as": "65002", "update_source": "eth2"},
	} {
		if rec := env.do("POST", "/api/bgp/neighbors", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	// A neighbour stays in its VRF.
	if rec := env.do("PUT", "/api/bgp/neighbors/"+itoa(nbr), map[string]any{"vrf_id": blue}); rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	var n models.BgpNeighbor
	env.srv.db.First(&n, nbr)
	if n.VrfID != nil {
		t.Errorf("neighbour moved to VRF %d", *n.VrfID)
	}

	env.create("/api/ospf/config", map[string]any{"instance_id": a, "version": 2, "enabled": true})
	env.create("/api/ospf/config", map[string]any{"instance_id": a, "version": 2, "vrf_id": blue, "enabled": true})
	env.create("/api/ospf/interfaces", map[string]any{"instance_id": a, "version": 2, "name": "eth1", "area": "0.0.0.0"})
	env.create("/api/ospf/interfaces", map[string]any{"instance_id": a, "version": 2, "name": "eth2", "area": "0.0.0.0"})
	if rec := env.do("POST", "/api/isis/config", map[string]any{"instance_id": a, "vrf_id": blue, "enabled": true, "net_interface": "eth1", "net_area": "49.0001"}); rec.Code != http.StatusBadRequest {
		t.Errorf("IS-IS NET from another VRF's interface accepted: %d %s", rec.Code, rec.Body)
	}
	env.create("/api/isis/config", map[string]any{"instance_id": a, "vrf_id": blue, "enabled": true, "net_interface": "eth2", "net_area": "49.0001"})

	doc, err := builder.Build(env.srv.db, 1)
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

	if rec := env.do("DELETE", "/api/vrfs/"+itoa(blue), nil); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "BGP neighbour 10.2.0.2") || !strings.Contains(rec.Body.String(), "OSPFv2") {
		t.Errorf("delete with routing: %d %s", rec.Code, rec.Body)
	}
}
