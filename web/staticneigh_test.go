// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/abundo/portitor/internal/builder"
)

func TestStaticNeighbours(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "enabled": true, "ipv4-mode": "static", "addresses": []string{"10.0.0.1/24"}})

	// Normalised.
	env.post("instance=main/static-neighbour", map[string]any{"interface": "eth1", "address": " fd00:0::5 ", "mac": "02-00-5E-00-01-01", "enabled": true})
	if n := env.node("instance=main/static-neighbour=eth1,fd00::5"); n == nil || n.Leaf("mac") != "02:00:5e:00:01:01" {
		t.Errorf("not normalised: %+v", n)
	}
	env.post("instance=main/static-neighbour", map[string]any{"interface": "eth1", "address": "10.0.0.5", "mac": "02:00:00:00:00:05", "enabled": true})
	env.post("instance=main/static-neighbour", map[string]any{"interface": "eth1", "address": "10.0.0.6", "mac": "02:00:00:00:00:06", "enabled": false})
	for what, body := range map[string]map[string]any{
		"bad address": {"interface": "eth1", "address": "10.0.0.300", "mac": "02:00:00:00:00:01"},
		"bad mac":     {"interface": "eth1", "address": "10.0.0.7", "mac": "02:00:00:00:00"},
		"twice":       {"interface": "eth1", "address": "fd00::5", "mac": "02:00:00:00:00:01"},
		"no iface":    {"interface": "eth9", "address": "10.0.0.8", "mac": "02:00:00:00:00:01"},
	} {
		if rec := env.cfg("POST", "instance=main/static-neighbour", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}

	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(doc.Instance("main").StaticNeighbours)
	// In key order: interface, then address.
	if string(got) != `[{"interface":"eth1","address":"10.0.0.5","mac":"02:00:00:00:00:05"},{"interface":"eth1","address":"fd00::5","mac":"02:00:5e:00:01:01"}]` {
		t.Errorf("document: %s", got)
	}
}
