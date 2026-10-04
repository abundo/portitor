// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/nftimport"
	"github.com/abundo/portitor/models"
)

// parseAgent answers an nftables parse with nftimport's sample.
type parseAgent struct{ agentAPI }

func (parseAgent) ParseNftables(context.Context, string) (*agentapi.ParseNftablesResult, error) {
	js, err := os.ReadFile("../internal/nftimport/testdata/sample.json")
	if err != nil {
		return nil, err
	}
	text, err := os.ReadFile("../internal/nftimport/testdata/sample.txt")
	return &agentapi.ParseNftablesResult{JSON: js, Text: string(text)}, err
}

func TestImportNftables(t *testing.T) {
	env := newEnv(t)
	env.srv.newAgent = func(*models.Settings) (agentAPI, error) { return parseAgent{}, nil }
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "wan", "enabled": true})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "lan", "enabled": true})
	env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "input", "action": "drop", "enabled": true})

	count := func(model any) int64 {
		var n int64
		env.srv.db.Model(model).Count(&n)
		return n
	}
	before := count(&models.Rule{})
	body := map[string]any{"instance_id": inst, "text": "x", "rename": map[string]string{"eth0": "wan", "eth1": "lan"}}
	var res nftimport.Result
	rec := env.do("POST", "/api/import/nftables", body)
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if rec.Code != http.StatusOK || len(res.Rules) != 7 || len(res.NAT) != 3 {
		t.Fatalf("preview: %d %s", rec.Code, rec.Body)
	}
	if count(&models.Rule{}) != before || count(&models.AddressObject{}) != 0 || count(&models.Service{}) != 0 {
		t.Errorf("the preview wrote rows: rules %d, objects %d, services %d", count(&models.Rule{}), count(&models.AddressObject{}), count(&models.Service{}))
	}

	body["apply"] = true
	if rec := env.do("POST", "/api/import/nftables", body); rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body)
	}
	if n := count(&models.Rule{}); n != before+7 {
		t.Errorf("%d rules, want %d + 7", n, before)
	}
	if count(&models.NatRule{}) != 3 || count(&models.AddressObject{}) != 1 || count(&models.Service{}) != 3 {
		t.Errorf("NAT, objects or services missing")
	}

	// Again, replacing: the hosts/prefixes and services are reused.
	body["replace"] = true
	if rec := env.do("POST", "/api/import/nftables", body); rec.Code != http.StatusOK {
		t.Fatalf("replace: %d %s", rec.Code, rec.Body)
	}
	if count(&models.Rule{}) != 7 || count(&models.NatRule{}) != 3 || count(&models.AddressObject{}) != 1 || count(&models.Service{}) != 3 {
		t.Errorf("replace: rules %d, NAT %d, objects %d, services %d",
			count(&models.Rule{}), count(&models.NatRule{}), count(&models.AddressObject{}), count(&models.Service{}))
	}
}
