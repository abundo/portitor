// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/models"
)

func TestVRRP(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	eth := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "kind": "bridge", "enabled": true, "ipv4_mode": "static", "addresses": []string{"10.0.0.1/24", "fd00::1/64"}})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "wg0", "kind": "wireguard", "enabled": true, "ipv4_mode": "static", "addresses": []string{"10.9.0.1/24"}})

	// Defaults filled in, addresses made canonical.
	rec := env.do("POST", "/api/vrrp/routers", map[string]any{
		"instance_id": inst, "interface": "eth1", "vrid": 10, "preempt": true, "enabled": true,
		"ipv4": []string{" 10.0.0.254/24 "}, "ipv6": []string{"FD00::FE", "fe80::1"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var r models.VrrpRouter
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	if r.Version != 3 || r.Priority != 100 || r.AdvertisementInterval != 1000 ||
		!slices.Equal(r.Ipv4, []string{"10.0.0.254"}) || !slices.Equal(r.Ipv6, []string{"fd00::fe", "fe80::1"}) {
		t.Errorf("not normalised: %+v", r)
	}
	for what, body := range map[string]map[string]any{
		"unknown interface": {"instance_id": inst, "interface": "eth9", "vrid": 1, "ipv4": []string{"10.0.0.2"}},
		"wireguard":         {"instance_id": inst, "interface": "wg0", "vrid": 1, "ipv4": []string{"10.9.0.2"}},
		"vrid 0":            {"instance_id": inst, "interface": "eth1", "vrid": 0, "ipv4": []string{"10.0.0.2"}},
		"same vrid":         {"instance_id": inst, "interface": "eth1", "vrid": 10, "ipv4": []string{"10.0.0.2"}},
		"no addresses":      {"instance_id": inst, "interface": "eth1", "vrid": 2},
		"outside network":   {"instance_id": inst, "interface": "eth1", "vrid": 2, "ipv4": []string{"10.1.0.2"}},
		"not an address":    {"instance_id": inst, "interface": "eth1", "vrid": 2, "ipv4": []string{"gateway"}},
		"v6 with v2":        {"instance_id": inst, "interface": "eth1", "vrid": 2, "version": 2, "ipv6": []string{"fd00::2"}},
		"bad interval":      {"instance_id": inst, "interface": "eth1", "vrid": 2, "advertisement_interval": 15, "ipv4": []string{"10.0.0.2"}},
		"address in use":    {"instance_id": inst, "interface": "eth1", "vrid": 2, "ipv4": []string{"10.0.0.254"}},
	} {
		if rec := env.do("POST", "/api/vrrp/routers", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}

	// Renaming the interface rewrites it; deleting it is refused while a
	// virtual router is on it.
	if rec := env.do("PUT", "/api/interfaces/"+itoa(eth), map[string]any{"name": "lan"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&r, r.ID)
	if r.Interface != "lan" {
		t.Errorf("not rewritten: %+v", r)
	}
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(eth), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "VRRP virtual router 10") {
		t.Errorf("delete interface: %d %s", rec.Code, rec.Body)
	}

	// The document has it, and it validates; disabled, it is shut down.
	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	in := doc.Instance("main")
	if len(in.VRRP) != 1 || in.VRRP[0].Interface != "lan" || in.VRRP[0].VRID != 10 || in.VRRP[0].NoPreempt || in.VRRP[0].Shutdown || !in.FRRRunning() {
		t.Errorf("document: %+v", in.VRRP)
	}
	env.do("PUT", "/api/vrrp/routers/"+itoa(r.ID), map[string]any{"enabled": false, "preempt": false})
	doc, _ = builder.Build(env.srv.db, 2)
	if in := doc.Instance("main"); len(in.VRRP) != 1 || !in.VRRP[0].Shutdown || !in.VRRP[0].NoPreempt {
		t.Errorf("disabled: %+v", in.VRRP)
	}
}
