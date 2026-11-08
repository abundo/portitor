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
)

func TestTunnel6in4(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "ipv4-mode": "dhcp", "enabled": true})

	const key = "UpD4teKey"
	tunnel := map[string]any{
		"kind": "6in4", "enabled": true, "ipv4-mode": "none",
		"addresses": []string{"2001:470:1f0a:12::2/64"}, "tunnel-remote": "216.66.80.90",
		"tunnel-default-route": true, "he-tunnel-id": "123456", "he-username": "alice", "he-update-key": key,
	}
	for field, v := range map[string]any{
		"tunnel-remote": "2001:db8::1",
		"he-tunnel-id":  "12&myip=1",
		"he-username":   "a b",
		"he-update-key": nil,
		"ipv4-mode":     "dhcp",
	} {
		c := map[string]any{}
		for k, x := range tunnel {
			c[k] = x
		}
		c[field] = v
		if rec := env.cfg("PUT", "instance=main/interface=he0", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}

	env.put("instance=main/interface=he0", tunnel)
	if rec := env.do("GET", "/api/config/candidate/instance=main/interface", nil); strings.Contains(rec.Body.String(), key) {
		t.Errorf("update key leaked: %s", rec.Body)
	}
	// A replace without the key keeps it.
	c := map[string]any{"description": "HE"}
	for k, x := range tunnel {
		if k != "he-update-key" {
			c[k] = x
		}
	}
	env.put("instance=main/interface=he0", c)
	if he := env.node("instance=main/interface=he0"); he.Leaf("he-update-key") != key || he.Leaf("description") != "HE" {
		t.Errorf("stored %+v", he.Leaves)
	}

	doc, err := builder.Build(env.input(), 1)
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
	env.patch("instance=main/interface=he0", map[string]any{"he-tunnel-id": nil})
	if he := env.node("instance=main/interface=he0"); he.Leaf("he-update-key") != "" || he.Leaf("he-username") != "" {
		t.Errorf("account kept: %+v", he.Leaves)
	}
}
