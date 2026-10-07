// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"slices"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/models"
)

func TestVRF(t *testing.T) {
	env := newEnv(t)
	a := env.create("/api/instances", map[string]any{"name": "main"})
	b := env.create("/api/instances", map[string]any{"name": "other"})
	env.create("/api/interfaces", map[string]any{"instance_id": a, "name": "eth1", "addresses": []string{"192.0.2.1/24"}, "enabled": true})
	env.create("/api/interfaces", map[string]any{"instance_id": a, "name": "eth2", "addresses": []string{"198.51.100.1/24"}, "enabled": true})
	env.create("/api/interfaces", map[string]any{"instance_id": b, "name": "eth3", "addresses": []string{"203.0.113.1/24"}, "enabled": true})

	vrf := func(inst uint, name string, table int, members ...string) map[string]any {
		return map[string]any{"instance_id": inst, "name": name, "kind": "vrf", "enabled": true, "ipv4_mode": "none",
			"vrf_table": table, "members": members}
	}
	for what, body := range map[string]map[string]any{
		"table 0":        vrf(a, "blue", 0),
		"main table":     vrf(a, "blue", 254),
		"unknown member": vrf(a, "blue", 10, "eth9"),
		"other's member": vrf(a, "blue", 10, "eth3"),
		"dhcp":           func() map[string]any { v := vrf(a, "blue", 10); v["ipv4_mode"] = "dhcp"; return v }(),
	} {
		if rec := env.do("POST", "/api/interfaces", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	blue := env.create("/api/interfaces", vrf(a, "blue", 10, "eth1"))
	// The same name and table in another virtual firewall.
	env.create("/api/interfaces", vrf(b, "blue", 10, "eth3"))
	if rec := env.do("POST", "/api/interfaces", vrf(a, "red", 10)); rec.Code != http.StatusBadRequest {
		t.Errorf("duplicate table accepted: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/interfaces", vrf(a, "red", 11, "eth1")); rec.Code != http.StatusBadRequest {
		t.Errorf("member of two VRFs accepted: %d %s", rec.Code, rec.Body)
	}
	env.create("/api/routes", map[string]any{"instance_id": a, "destination": "default", "gateway": "192.0.2.254", "vrf_id": blue, "enabled": true})
	var otherBlue models.Interface
	env.srv.db.Where("instance_id = ? AND name = ?", b, "blue").First(&otherBlue)
	if rec := env.do("POST", "/api/routes", map[string]any{"instance_id": a, "destination": "10.0.0.0/8", "gateway": "192.0.2.254", "vrf_id": otherBlue.ID, "enabled": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("another VF's VRF accepted: %d %s", rec.Code, rec.Body)
	}

	// Renaming a member rewrites the VRF's members; deleting one drops it.
	var eth1, eth2 models.Interface
	env.srv.db.Where("instance_id = ? AND name = ?", a, "eth1").First(&eth1)
	env.srv.db.Where("instance_id = ? AND name = ?", a, "eth2").First(&eth2)
	if rec := env.do("PUT", "/api/interfaces/"+itoa(eth1.ID), map[string]any{"name": "lan1"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/interfaces/"+itoa(blue), map[string]any{"members": []string{"lan1", "eth2"}}); rec.Code != http.StatusOK {
		t.Fatalf("add member: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(eth2.ID), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete member: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	in := doc.Instance("main")
	if v := in.Interface("blue"); v == nil || v.VRFTable != 10 || !slices.Equal(v.Members, []string{"lan1"}) {
		t.Errorf("vrf: %+v", v)
	}
	if len(in.Routes) != 1 || in.Routes[0].VRF != "blue" || in.RouteTable(in.Routes[0]) != "10" {
		t.Errorf("routes: %+v", in.Routes)
	}
	if v := doc.Instance("other").Interface("blue"); v == nil || v.VRFTable != 10 {
		t.Errorf("other's vrf: %+v", v)
	}
}
