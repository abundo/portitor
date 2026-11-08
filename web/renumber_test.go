// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import "testing"

// TestRenumberPrefixes: a new address of an interface takes the DHCP and RA
// settings of the prefix it replaces.
func TestRenumberPrefixes(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "enabled": true, "addresses": []string{"192.168.1.1/24", "2001:db8:1::1/64"}})
	env.post("instance=main/ipam-prefix", map[string]any{"prefix": "2001:db8:1::/64", "ra-enabled": true, "ra-slaac": true, "dhcp-enabled": true, "dhcp-range-start": "2001:db8:1::1000", "dhcp-range-end": "2001:db8:1::1fff"})

	env.patch("instance=main/interface=eth1", map[string]any{"addresses": []string{"192.168.1.1/24", "2001:db8:2::1/64"}})
	oldP, newP := env.node("instance=main/ipam-prefix=2001:db8:1::%2F64"), env.node("instance=main/ipam-prefix=2001:db8:2::%2F64")
	if oldP == nil || on(oldP, "dhcp-enabled") || on(oldP, "ra-enabled") {
		t.Errorf("old prefix kept its settings: %+v", oldP)
	}
	if newP == nil || !on(newP, "ra-enabled") || !on(newP, "ra-slaac") || !on(newP, "dhcp-enabled") ||
		newP.Leaf("dhcp-range-start") != "2001:db8:2::1000" || newP.Leaf("dhcp-range-end") != "2001:db8:2::1fff" {
		t.Errorf("new prefix: %+v", newP)
	}
}
