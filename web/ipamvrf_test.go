// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestIpamVRF: the same prefix outside the VRFs and in a VRF (its own
// list), a tree each; an empty VRF is shown; next-free counts its own
// VRF's addresses alone; DHCP is on in one VRF; a VRF's rename keeps its
// prefixes, and its delete takes them along.
func TestIpamVRF(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/vrf=red", map[string]any{"route-table": 10})
	env.put("instance=main/vrf=blue", map[string]any{"route-table": 11})
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "enabled": true, "addresses": []string{"10.0.0.1/24"}})
	env.put("instance=main/interface=eth2", map[string]any{"kind": "physical", "enabled": true, "vrf": "red", "addresses": []string{"10.0.0.2/24"}})
	env.post("instance=main/ipam-prefix", map[string]any{"prefix": "10.0.0.0/24"})
	env.post("instance=main/vrf=red/ipam-prefix", map[string]any{"prefix": "10.0.0.0/24", "description": "red's"})
	env.post("instance=main/vrf=red/ipam-address", map[string]any{"address": "10.0.0.3"})

	rec := env.do("GET", "/api/ipam/tree?instance=main", nil)
	var roots []struct {
		Kind, CIDR, Vrf, Interface string
		Children                   []struct{ CIDR string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &roots); err != nil {
		t.Fatal(rec.Body.String())
	}
	var got []string
	for _, r := range roots {
		got = append(got, r.Vrf+":"+r.Kind+":"+r.CIDR+":"+r.Interface)
	}
	if want := ":prefix:10.0.0.0/24:eth1 blue:vrf:blue: red:prefix:10.0.0.0/24:eth2"; strings.Join(got, " ") != want {
		t.Errorf("roots %v, want %s", got, want)
	}

	// The next free: .1 is eth1's (main), .2 eth2's and .3 an address (red).
	next := func(path string) string {
		return env.do("GET", "/api/config/candidate/"+path+"?action=next-free", nil).Body.String()
	}
	if body := next("instance=main/vrf=red/ipam-prefix=10.0.0.0%2F24"); !strings.Contains(body, `"10.0.0.1"`) {
		t.Errorf("red's next free: %s", body)
	}
	if body := next("instance=main/ipam-prefix=10.0.0.0%2F24"); !strings.Contains(body, `"10.0.0.2"`) {
		t.Errorf("main's next free: %s", body)
	}

	// DHCP in one VRF only.
	dhcp := map[string]any{"dhcp-enabled": true, "dhcp-range-start": "10.0.0.100", "dhcp-range-end": "10.0.0.199"}
	env.patch("instance=main/vrf=red/ipam-prefix=10.0.0.0%2F24", dhcp)
	if rec := env.cfg("PATCH", "instance=main/ipam-prefix=10.0.0.0%2F24", dhcp); rec.Code != http.StatusBadRequest {
		t.Errorf("DHCP in two VRFs: %d", rec.Code)
	}

	// A new address of an interface in the VRF takes the VRF's prefix's
	// DHCP settings along.
	env.patch("instance=main/interface=eth2", map[string]any{"addresses": []string{"10.0.1.2/24"}})
	if p := env.node("instance=main/vrf=red/ipam-prefix=10.0.1.0%2F24"); p == nil || !on(p, "dhcp-enabled") {
		t.Errorf("renumbered: %+v", p)
	}

	env.mustCfg("POST", "instance=main/vrf=red?action=rename", map[string]any{"keys": []string{"green"}})
	if env.node("instance=main/vrf=green/ipam-prefix=10.0.1.0%2F24") == nil {
		t.Error("rename: the prefix is gone")
	}
	env.patch("instance=main/interface=eth2", map[string]any{"vrf": ""})
	env.mustCfg("DELETE", "instance=main/vrf=green", nil)
	if env.node("instance=main/ipam-prefix=10.0.0.0%2F24") == nil {
		t.Error("the prefix outside the VRFs went with the VRF")
	}
}
