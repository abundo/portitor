// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"slices"
	"testing"

)

func TestDelegatedAddresses(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "enabled": true, "ipv4-mode": "dhcp", "ipv6-accept-ra": true, "dhcpv6": true, "dhcpv6-pd": true})
	if rec := env.cfg("PUT", "instance=main/interface=eth9", map[string]any{"kind": "physical", "dhcpv6": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("dhcpv6 without router advertisements accepted: %d", rec.Code)
	}
	for _, a := range []string{"<eth0>:1::/64", "<eth0>:12345::1/64", "<eth9>:1::1/64"} {
		if rec := env.cfg("PUT", "instance=main/interface=eth1", map[string]any{"kind": "physical", "addresses": []string{a}}); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d", a, rec.Code)
		}
	}
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "addresses": []string{"<eth0>:01::1/64"}})
	if got := env.node("instance=main/interface=eth1").LeafLists["addresses"]; !slices.Equal(got, []string{"<eth0>:1::1/64"}) {
		t.Errorf("addresses %v", got)
	}
	if rec := env.cfg("PUT", "instance=main/interface=eth2", map[string]any{"kind": "physical", "addresses": []string{"<eth0>:1::1/64"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("address on two interfaces accepted: %d", rec.Code)
	}
	if rec := env.cfg("PATCH", "instance=main/interface=eth0", map[string]any{"dhcpv6-pd": false}); rec.Code != http.StatusBadRequest {
		t.Errorf("prefix delegation turned off while used: %d", rec.Code)
	}
	if rec := env.cfg("DELETE", "instance=main/interface=eth0", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delegating interface deleted while used: %d", rec.Code)
	}
	env.mustCfg("POST", "instance=main/interface=eth0?action=rename", map[string]any{"keys": []string{"wan0"}})
	if got := env.node("instance=main/interface=eth1").LeafLists["addresses"]; !slices.Equal(got, []string{"<wan0>:1::1/64"}) {
		t.Errorf("after rename: %v", got)
	}
}

func TestDelegatedDHCP(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "enabled": true, "ipv4-mode": "dhcp", "ipv6-accept-ra": true, "dhcpv6": true, "dhcpv6-pd": true})
	if rec := env.cfg("PUT", "instance=main/interface=eth1", map[string]any{"kind": "physical", "addresses": []string{"192.168.1.1/24"}, "delegated-dhcp": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("delegated DHCPv6 without a delegated address accepted: %d", rec.Code)
	}
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "addresses": []string{"<eth0>:1::1/64"}})
	for _, r := range [][2]string{{"::1000", ""}, {"::2000", "::1000"}, {"1:0:0:0:0::1", "::2"}, {"::x", "::2"}} {
		body := map[string]any{"delegated-dhcp": true, "delegated-range-start": r[0], "delegated-range-end": r[1]}
		if r[1] == "" {
			body["delegated-range-end"] = nil
		}
		if rec := env.cfg("PATCH", "instance=main/interface=eth1", body); rec.Code != http.StatusBadRequest {
			t.Errorf("range %v accepted: %d", r, rec.Code)
		}
	}
	env.patch("instance=main/interface=eth1", map[string]any{"delegated-dhcp": true, "delegated-range-start": "1000", "delegated-range-end": "::0:1fff"})
	if got := env.node("instance=main/interface=eth1"); !on(got, "delegated-dhcp") || got.Leaf("delegated-range-start") != "::1000" || got.Leaf("delegated-range-end") != "::1fff" || !on(got, "delegated-slaac") {
		t.Errorf("stored %+v", got.Leaves)
	}
}
