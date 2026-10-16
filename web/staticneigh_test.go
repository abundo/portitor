// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

func TestStaticNeighbours(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	eth := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "kind": "physical", "enabled": true, "ipv4_mode": "static", "addresses": []string{"10.0.0.1/24"}})

	// Normalised.
	rec := env.do("POST", "/api/static-neighbours", map[string]any{"instance_id": inst, "interface_id": eth, "address": " fd00:0::5 ", "mac": "02-00-5E-00-01-01", "enabled": true})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var n models.StaticNeighbour
	_ = json.Unmarshal(rec.Body.Bytes(), &n)
	if n.Address != "fd00::5" || n.MAC != "02:00:5e:00:01:01" {
		t.Errorf("not normalised: %+v", n)
	}
	env.create("/api/static-neighbours", map[string]any{"instance_id": inst, "interface_id": eth, "address": "10.0.0.5", "mac": "02:00:00:00:00:05", "enabled": true})
	env.create("/api/static-neighbours", map[string]any{"instance_id": inst, "interface_id": eth, "address": "10.0.0.6", "mac": "02:00:00:00:00:06", "enabled": false})
	for what, body := range map[string]map[string]any{
		"bad address": {"instance_id": inst, "interface_id": eth, "address": "10.0.0.300", "mac": "02:00:00:00:00:01"},
		"bad mac":     {"instance_id": inst, "interface_id": eth, "address": "10.0.0.7", "mac": "02:00:00:00:00"},
		"twice":       {"instance_id": inst, "interface_id": eth, "address": "fd00::5", "mac": "02:00:00:00:00:01"},
		"no iface":    {"instance_id": inst, "interface_id": 999, "address": "10.0.0.8", "mac": "02:00:00:00:00:01"},
	} {
		if rec := env.do("POST", "/api/static-neighbours", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}

	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	var in *fwconfig.Instance
	for i := range doc.Instances {
		if doc.Instances[i].Name == "main" {
			in = &doc.Instances[i]
		}
	}
	got, _ := json.Marshal(in.StaticNeighbours)
	if string(got) != `[{"interface":"eth1","address":"fd00::5","mac":"02:00:5e:00:01:01"},{"interface":"eth1","address":"10.0.0.5","mac":"02:00:00:00:00:05"}]` {
		t.Errorf("document: %s", got)
	}
}
