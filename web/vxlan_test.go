// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/models"
)

func TestVXLANEVPN(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "addresses": []string{"192.0.2.1/24"}, "enabled": true})

	vx := map[string]any{
		"instance_id": inst, "name": "vx100", "kind": "vxlan", "enabled": true, "ipv4_mode": "none",
		"vxlan_vni": 100, "vxlan_local": "192.0.2.1", "vxlan_device": "eth0",
	}
	for field, v := range map[string]any{
		"vxlan_vni":     0,
		"vxlan_local":   "224.0.0.1",
		"vxlan_port":    70000,
		"vxlan_remotes": []string{"2001:db8::2"},
	} {
		c := map[string]any{}
		for k, x := range vx {
			c[k] = x
		}
		c[field] = v
		if rec := env.do("POST", "/api/interfaces", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	env.create("/api/interfaces", vx)
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "br100", "kind": "bridge", "enabled": true, "ipv4_mode": "none", "members": []string{"vx100"}})
	env.create("/api/bgp/config", map[string]any{"instance_id": inst, "enabled": true, "asn": 65000, "evpn": true})
	env.create("/api/bgp/neighbors", map[string]any{"instance_id": inst, "address": "192.0.2.2", "enabled": true, "remote_as": "internal",
		"evpn_activate": true, "evpn_route_reflector_client": true})

	// Renaming the underlay rewrites it; deleting it is refused.
	var eth0 models.Interface
	env.srv.db.Where("name = ?", "eth0").First(&eth0)
	if rec := env.do("PUT", "/api/interfaces/"+itoa(eth0.ID), map[string]any{"name": "wan0"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(eth0.ID), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "VXLAN vx100") {
		t.Errorf("delete of the underlay: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	in := doc.Instance("main")
	x := in.Interface("vx100").VXLAN
	if x == nil || x.VNI != 100 || x.Device != "wan0" || x.Local != "192.0.2.1" {
		t.Errorf("vxlan: %+v", x)
	}
	if !in.BGP.EVPN || !in.BGP.Neighbors[0].EVPN.Activate || !in.BGP.Neighbors[0].EVPN.RouteReflectorClient {
		t.Errorf("bgp: %+v", in.BGP)
	}
}

func TestVRFL3VNI(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "addresses": []string{"192.0.2.1/24"}, "enabled": true})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "vx100", "kind": "vxlan", "enabled": true, "ipv4_mode": "none",
		"vxlan_vni": 100, "vxlan_local": "192.0.2.1"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "br100", "kind": "bridge", "enabled": true, "ipv4_mode": "none", "members": []string{"vx100"}})
	env.create("/api/bgp/config", map[string]any{"instance_id": inst, "enabled": true, "asn": 65000, "evpn": true})

	vrf := map[string]any{"instance_id": inst, "name": "red", "route_table": 10, "evpn_vni": 5000, "evpn_local": "192.0.2.1",
		"evpn_device": "eth0", "evpn_advertise_v4": true, "evpn_import_rts": []string{"65000:5000"}, "evpn_export_rts": []string{" 65000:5000 "}}
	for field, v := range map[string]any{
		"evpn_vni":          100, // vx100's
		"evpn_local":        "",
		"evpn_device":       "eth9",
		"evpn_rd":           "x",
		"evpn_import_rts":   []string{"65000"},
		"evpn_advertise_v4": false,
	} {
		c := map[string]any{}
		for k, x := range vrf {
			c[k] = x
		}
		c[field] = v
		if rec := env.do("POST", "/api/vrfs", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	env.create("/api/vrfs", vrf)
	if rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": inst, "name": "l3br-1", "kind": "bridge", "ipv4_mode": "none"}); rec.Code != http.StatusBadRequest {
		t.Errorf("reserved name accepted: %d %s", rec.Code, rec.Body)
	}

	// Renaming the underlay rewrites it; deleting it is refused.
	var eth0 models.Interface
	env.srv.db.Where("name = ?", "eth0").First(&eth0)
	if rec := env.do("PUT", "/api/interfaces/"+itoa(eth0.ID), map[string]any{"name": "wan0"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(eth0.ID), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "VRF red (EVPN underlay)") {
		t.Errorf("delete of the underlay: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	e := doc.Instance("main").VRFs[0].EVPN
	if e == nil || e.VNI != 5000 || e.Device != "wan0" || !e.AdvertiseIPv4 || e.ExportRTs[0] != "65000:5000" {
		t.Errorf("evpn: %+v", e)
	}
}
