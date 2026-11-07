// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"slices"
	"testing"

	"github.com/abundo/portitor/models"
)

func TestDelegatedAddresses(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	wan := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "enabled": true, "ipv4_mode": "dhcp",
		"ipv6_accept_ra": true, "dhcpv6": true, "dhcpv6_pd": true})
	if rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": inst, "name": "eth9", "dhcpv6": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("dhcpv6 without router advertisements accepted: %d", rec.Code)
	}
	for _, a := range []string{"<eth0>:1::/64", "<eth0>:12345::1/64", "<eth9>:1::1/64"} {
		if rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "addresses": []string{a}}); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d", a, rec.Code)
		}
	}
	lan := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "addresses": []string{"<eth0>:01::1/64"}})
	var got models.Interface
	env.srv.db.First(&got, lan)
	if !slices.Equal(got.Addresses, models.StringList{"<eth0>:1::1/64"}) {
		t.Errorf("addresses %v", got.Addresses)
	}
	if rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": inst, "name": "eth2", "addresses": []string{"<eth0>:1::1/64"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("address on two interfaces accepted: %d", rec.Code)
	}

	if rec := env.do("PUT", "/api/interfaces/"+itoa(wan), map[string]any{"dhcpv6_pd": false}); rec.Code != http.StatusBadRequest {
		t.Errorf("prefix delegation turned off while used: %d", rec.Code)
	}
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(wan), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delegating interface deleted while used: %d", rec.Code)
	}
	if rec := env.do("PUT", "/api/interfaces/"+itoa(wan), map[string]any{"name": "wan0"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&got, lan)
	if !slices.Equal(got.Addresses, models.StringList{"<wan0>:1::1/64"}) {
		t.Errorf("after rename: %v", got.Addresses)
	}
}

func TestDelegatedDHCP(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "enabled": true, "ipv4_mode": "dhcp",
		"ipv6_accept_ra": true, "dhcpv6": true, "dhcpv6_pd": true})
	if rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "addresses": []string{"192.168.1.1/24"},
		"delegated_dhcp": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("delegated DHCPv6 without a delegated address accepted: %d", rec.Code)
	}
	lan := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "addresses": []string{"<eth0>:1::1/64"}})
	for _, r := range [][2]string{{"::1000", ""}, {"::2000", "::1000"}, {"1:0:0:0:0::1", "::2"}, {"::x", "::2"}} {
		if rec := env.do("PUT", "/api/interfaces/"+itoa(lan), map[string]any{"delegated_dhcp": true,
			"delegated_range_start": r[0], "delegated_range_end": r[1]}); rec.Code != http.StatusBadRequest {
			t.Errorf("range %v accepted: %d", r, rec.Code)
		}
	}
	if rec := env.do("PUT", "/api/interfaces/"+itoa(lan), map[string]any{"delegated_dhcp": true,
		"delegated_range_start": "1000", "delegated_range_end": "::0:1fff"}); rec.Code != http.StatusOK {
		t.Fatalf("range: %d %s", rec.Code, rec.Body)
	}
	var got models.Interface
	env.srv.db.First(&got, lan)
	if !got.DelegatedDhcp || got.DelegatedRangeStart != "::1000" || got.DelegatedRangeEnd != "::1fff" || !got.DelegatedSlaac {
		t.Errorf("stored %+v", got)
	}
}
