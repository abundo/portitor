// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/models"
)

func TestBFD(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	eth := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "kind": "physical", "enabled": true, "ipv4_mode": "static", "addresses": []string{"10.0.0.1/24"}})

	// Defaults filled in.
	rec := env.do("POST", "/api/bfd/interfaces", map[string]any{"instance_id": inst, "interface": "eth1", "enabled": true})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var b models.BfdInterface
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	if b.DetectMultiplier != 3 || b.ReceiveInterval != 300 || b.TransmitInterval != 300 {
		t.Errorf("not normalised: %+v", b)
	}
	for what, body := range map[string]map[string]any{
		"unknown interface": {"instance_id": inst, "interface": "eth9"},
		"twice":             {"instance_id": inst, "interface": "eth1"},
		"bad multiplier":    {"instance_id": inst, "interface": "eth1", "detect_multiplier": 300},
	} {
		if rec := env.do("POST", "/api/bfd/interfaces", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	// A route with BFD needs a gateway.
	if rec := env.do("POST", "/api/routes", map[string]any{"instance_id": inst, "destination": "10.1.0.0/16", "interface_id": eth, "bfd": true, "enabled": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("BFD route without gateway: %d %s", rec.Code, rec.Body)
	}
	env.create("/api/routes", map[string]any{"instance_id": inst, "destination": "10.1.0.0/16", "gateway": "10.0.0.2", "bfd": true, "enabled": true})

	// The document has it, and the route is FRR's.
	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	exp := doc.Expand()
	in := exp.Instance("main")
	if len(in.BFD) != 1 || in.BFD[0].Name != "eth1" || !in.HasBFDRoutes() || !in.FRRRunning() {
		t.Errorf("document: %+v %+v", in.BFD, in.Routes)
	}

	// Renaming the interface rewrites it; disabled, it is left out.
	if rec := env.do("PUT", "/api/interfaces/"+itoa(eth), map[string]any{"name": "lan"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&b, b.ID)
	if b.Interface != "lan" {
		t.Errorf("not rewritten: %+v", b)
	}
	env.do("PUT", "/api/bfd/interfaces/"+itoa(b.ID), map[string]any{"enabled": false})
	doc, _ = builder.Build(env.srv.db, 2)
	if in := doc.Instance("main"); len(in.BFD) != 0 || len(in.KernelRoutes()) != 1 {
		t.Errorf("disabled: %+v", in.BFD)
	}

	// Deleting the interface takes its BFD settings along.
	env.do("DELETE", "/api/routes/1", nil)
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(eth), nil); rec.Code != http.StatusNoContent && rec.Code != http.StatusOK {
		t.Fatalf("delete interface: %d %s", rec.Code, rec.Body)
	}
	var n int64
	env.srv.db.Model(&models.BfdInterface{}).Count(&n)
	if n != 0 {
		t.Errorf("BFD settings left: %d", n)
	}
}
