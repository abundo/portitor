// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
)

func TestSNMP(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth1", map[string]any{"kind": "bridge", "enabled": true, "ipv4-mode": "static", "addresses": []string{"10.0.0.1/24"}})

	// Enabled needs a community or a user.
	for what, body := range map[string]map[string]any{
		"enabled with nothing": {"snmp-enabled": true},
		"bad community":        {"snmp-community": "a b"},
		"two-line location":    {"snmp-location": "a\nb"},
	} {
		if rec := env.cfg("PATCH", "instance=main", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", what, rec.Code, rec.Body)
		}
	}

	// The community is a secret: never read back.
	const community = "c0mmunity"
	env.patch("instance=main", map[string]any{"snmp-enabled": true, "snmp-community": community, "snmp-allow": []string{"10.0.0.0/24"}, "snmp-location": "rack 1"})
	if rec := env.do("GET", "/api/config/candidate/instance=main", nil); strings.Contains(rec.Body.String(), community) {
		t.Errorf("get: %s", rec.Body)
	}
	env.patch("instance=main", map[string]any{"snmp-contact": "noc@example.com"})
	env.patch("instance=main/interface=eth1", map[string]any{"snmp-serve": true})

	// Users: secret passwords, checked.
	const auth, priv = "authp4ss", "privp4ss"
	for what, body := range map[string]map[string]any{
		"short password": {"name": "mon", "auth-protocol": "SHA-256", "auth-password": "short"},
		"md5":            {"name": "mon", "auth-protocol": "MD5", "auth-password": auth},
		"no priv pw":     {"name": "mon", "auth-protocol": "SHA-256", "auth-password": auth, "priv-protocol": "AES"},
		"same passwords": {"name": "mon", "auth-protocol": "SHA-256", "auth-password": auth, "priv-protocol": "AES", "priv-password": auth},
		"bad name":       {"name": "a b", "auth-protocol": "SHA-256", "auth-password": auth},
	} {
		if rec := env.cfg("POST", "instance=main/snmp-user", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	env.mustCfg("POST", "instance=main/snmp-user", map[string]any{"name": "mon", "enabled": true, "auth-protocol": "SHA-256", "auth-password": auth, "priv-protocol": "AES", "priv-password": priv})
	// A replace without the passwords keeps them.
	env.put("instance=main/snmp-user=mon", map[string]any{"enabled": true, "auth-protocol": "SHA-256", "priv-protocol": "AES", "description": "NMS"})
	if rec := env.do("GET", "/api/config/candidate/instance=main/snmp-user", nil); strings.Contains(rec.Body.String(), auth) || strings.Contains(rec.Body.String(), priv) {
		t.Errorf("list holds a password: %s", rec.Body)
	}

	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	s := doc.Instance("main").SNMP
	if s == nil || s.Community != community || s.Location != "rack 1" || s.Contact != "noc@example.com" || strings.Join(s.Interfaces, " ") != "eth1" ||
		len(s.Users) != 1 || s.Users[0].AuthPassword != auth || s.Users[0].PrivPassword != priv {
		t.Fatalf("snmp %+v", s)
	}
	b, _ := json.Marshal(doc.Redacted())
	for _, secret := range []string{community, auth, priv} {
		if strings.Contains(string(b), secret) {
			t.Errorf("redacted document holds %q", secret)
		}
	}

	// Clearing the community leaves the user.
	env.patch("instance=main", map[string]any{"snmp-community": nil})
	doc, _ = builder.Build(env.input(), 2)
	if s := doc.Instance("main").SNMP; s == nil || s.Community != "" || len(s.Users) != 1 {
		t.Errorf("after clear: %+v", s)
	}
}
