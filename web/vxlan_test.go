// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"maps"
	"net/http"
	"testing"

	"github.com/abundo/portitor/internal/builder"
)

func TestVXLANEVPN(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "addresses": []string{"192.0.2.1/24"}, "enabled": true})

	vx := map[string]any{"kind": "vxlan", "enabled": true, "ipv4-mode": "none", "vxlan-vni": 100, "vxlan-local": "192.0.2.1", "vxlan-device": "eth0"}
	for field, v := range map[string]any{
		"vxlan-vni":     0,
		"vxlan-local":   "224.0.0.1",
		"vxlan-port":    70000,
		"vxlan-remotes": []string{"2001:db8::2"},
	} {
		c := maps.Clone(vx)
		c[field] = v
		if rec := env.cfg("PUT", "instance=main/interface=vx100", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	env.put("instance=main/interface=vx100", vx)
	env.put("instance=main/interface=br100", map[string]any{"kind": "bridge", "enabled": true, "ipv4-mode": "none", "members": []string{"vx100"}})
	env.put("instance=main/bgp=main", map[string]any{"enabled": true, "asn": 65000, "evpn": true})
	env.post("instance=main/bgp-neighbor", map[string]any{"address": "192.0.2.2", "enabled": true, "remote-as": "internal", "evpn-activate": true, "evpn-route-reflector-client": true, "vrf": "main"})

	// Renaming the underlay rewrites it; deleting it is refused.
	env.mustCfg("POST", "instance=main/interface=eth0?action=rename", map[string]any{"keys": []string{"wan0"}})
	if rec := env.cfg("DELETE", "instance=main/interface=wan0", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete of the underlay: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.input(), 1)
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
	env.host("main")
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "addresses": []string{"192.0.2.1/24"}, "enabled": true})
	env.put("instance=main/interface=vx100", map[string]any{"kind": "vxlan", "enabled": true, "ipv4-mode": "none", "vxlan-vni": 100, "vxlan-local": "192.0.2.1"})
	env.put("instance=main/interface=br100", map[string]any{"kind": "bridge", "enabled": true, "ipv4-mode": "none", "members": []string{"vx100"}})
	env.put("instance=main/bgp=main", map[string]any{"enabled": true, "asn": 65000, "evpn": true})

	vrf := map[string]any{"route-table": 10, "evpn-vni": 5000, "evpn-local": "192.0.2.1",
		"evpn-device": "eth0", "evpn-advertise-v4": true, "evpn-import-rts": []string{"65000:5000"}, "evpn-export-rts": []string{" 65000:5000 "}}
	for field, v := range map[string]any{
		"evpn-vni":        100, // vx100's
		"evpn-local":      nil,
		"evpn-device":     "eth9",
		"evpn-rd":         "x",
		"evpn-import-rts": []string{"65000"},
	} {
		c := maps.Clone(vrf)
		c[field] = v
		if rec := env.cfg("PUT", "instance=main/vrf=red", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	none := maps.Clone(vrf)
	none["evpn-advertise-v4"], none["evpn-advertise-v6"] = false, false
	if rec := env.cfg("PUT", "instance=main/vrf=red", none); rec.Code != http.StatusBadRequest {
		t.Errorf("no family advertised accepted: %d %s", rec.Code, rec.Body)
	}
	env.put("instance=main/vrf=red", vrf)
	if rec := env.cfg("PUT", "instance=main/interface=l3br-1", map[string]any{"kind": "bridge", "ipv4-mode": "none"}); rec.Code != http.StatusBadRequest {
		t.Errorf("reserved name accepted: %d %s", rec.Code, rec.Body)
	}

	// Renaming the underlay rewrites it; deleting it is refused.
	env.mustCfg("POST", "instance=main/interface=eth0?action=rename", map[string]any{"keys": []string{"wan0"}})
	if rec := env.cfg("DELETE", "instance=main/interface=wan0", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete of the underlay: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.input(), 1)
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
