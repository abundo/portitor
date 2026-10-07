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
