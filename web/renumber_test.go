// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"testing"

	"github.com/abundo/portitor/models"
)

func TestRenumberMovesDHCP(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	ifc := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "enabled": true,
		"addresses": []string{"192.168.1.1/24", "2001:db8:1::1/64"}})
	env.create("/api/ipam/prefixes", map[string]any{"instance_id": inst, "prefix": "2001:db8:1::/64",
		"ra_enabled": true, "ra_slaac": true, "dhcp_enabled": true,
		"dhcp_range_start": "2001:db8:1::1000", "dhcp_range_end": "2001:db8:1::1fff"})

	if rec := env.do("PUT", "/api/interfaces/"+itoa(ifc), map[string]any{
		"addresses": []string{"192.168.1.1/24", "2001:db8:2::1/64"}}); rec.Code != http.StatusOK {
		t.Fatalf("renumber: %d %s", rec.Code, rec.Body)
	}
	var oldP, newP models.IpamPrefix
	env.srv.db.Where("prefix = ?", "2001:db8:1::/64").First(&oldP)
	env.srv.db.Where("prefix = ?", "2001:db8:2::/64").First(&newP)
	if oldP.DhcpEnabled || oldP.RaEnabled {
		t.Errorf("old prefix kept its settings: %+v", oldP)
	}
	if !newP.RaEnabled || !newP.RaSlaac || !newP.DhcpEnabled || newP.DhcpRangeStart != "2001:db8:2::1000" || newP.DhcpRangeEnd != "2001:db8:2::1fff" {
		t.Errorf("new prefix: %+v", newP)
	}
}
