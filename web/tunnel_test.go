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
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

func TestTunnel6in4(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "ipv4_mode": "dhcp", "enabled": true})

	const key = "UpD4teKey"
	tunnel := map[string]any{
		"instance_id": inst, "name": "he0", "kind": "6in4", "enabled": true, "ipv4_mode": "none",
		"addresses": []string{"2001:470:1f0a:12::2/64"}, "tunnel_remote": "216.66.80.90",
		"tunnel_default_route": true, "he_tunnel_id": "123456", "he_username": "alice", "new_he_update_key": key,
	}
	for field, v := range map[string]any{
		"tunnel_remote":     "2001:db8::1",
		"tunnel_local":      "127.0.0.1",
		"he_tunnel_id":      "12&myip=1",
		"he_username":       "a b",
		"new_he_update_key": "",
		"ipv4_mode":         "dhcp",
	} {
		c := map[string]any{}
		for k, x := range tunnel {
			c[k] = x
		}
		c[field] = v
		if rec := env.do("POST", "/api/interfaces", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}

	rec := env.do("POST", "/api/interfaces", tunnel)
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), key) || !strings.Contains(rec.Body.String(), `"has_he_update_key":true`) {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("GET", "/api/interfaces?instance_id="+itoa(inst), nil); strings.Contains(rec.Body.String(), key) {
		t.Errorf("update key leaked: %s", rec.Body)
	}
	var he models.Interface
	env.srv.db.Where("name = ?", "he0").First(&he)
	// Saving without a key keeps it.
	if rec := env.do("PUT", "/api/interfaces/"+itoa(he.ID), map[string]any{"description": "HE"}); rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&he, he.ID)
	if he.HeUpdateKey != key || he.Description != "HE" {
		t.Errorf("stored %+v", he)
	}

	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	in := doc.Instance("main")
	var found bool
	for _, ifc := range in.Interfaces {
		if ifc.Name == "he0" {
			found = ifc.Tunnel != nil && ifc.Tunnel.Remote == "216.66.80.90" && ifc.Tunnel.TunnelBroker != nil && ifc.Tunnel.TunnelBroker.UpdateKey == key
		}
	}
	if !found {
		t.Errorf("document: %+v", in.Interfaces)
	}
	if !slices.Contains(in.Routes, fwconfig.Route{Destination: "::/0", Interface: "he0", Metric: fwconfig.TunnelRouteMetric}) {
		t.Errorf("no default route through the tunnel: %+v", in.Routes)
	}
	if b, _ := json.Marshal(redactDoc(*doc)); strings.Contains(string(b), key) {
		t.Error("update key in the deployment history")
	}

	// Without a tunnel id there is no account.
	if rec := env.do("PUT", "/api/interfaces/"+itoa(he.ID), map[string]any{"he_tunnel_id": ""}); rec.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&he, he.ID)
	if he.HeUpdateKey != "" || he.HeUsername != "" {
		t.Errorf("account kept: %+v", he)
	}
}
