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
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	eth := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth1", "kind": "bridge", "enabled": true, "ipv4_mode": "static", "addresses": []string{"10.0.0.1/24"}})
	path := "/api/instances/" + itoa(inst)

	// Enabled needs a community or a user.
	if rec := env.do("PUT", path, map[string]any{"snmp_enabled": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("enabled with nothing: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", path, map[string]any{"new_snmp_community": "a b"}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad community: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", path, map[string]any{"snmp_location": "a\nb"}); rec.Code != http.StatusBadRequest {
		t.Errorf("two-line location: %d %s", rec.Code, rec.Body)
	}

	// The community is write-only.
	const community = "c0mmunity"
	rec := env.do("PUT", path, map[string]any{"snmp_enabled": true, "new_snmp_community": community, "snmp_allow": []string{"10.0.0.0/24"}, "snmp_location": "rack 1"})
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), community) || !strings.Contains(rec.Body.String(), `"has_snmp_community":true`) {
		t.Fatalf("set community: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("GET", path, nil); strings.Contains(rec.Body.String(), community) || !strings.Contains(rec.Body.String(), `"has_snmp_community":true`) {
		t.Errorf("get: %s", rec.Body)
	}
	// Another write keeps it.
	env.do("PUT", path, map[string]any{"snmp_contact": "noc@example.com"})
	env.do("PUT", "/api/interfaces/"+itoa(eth), map[string]any{"snmp_serve": true})

	// Users: write-only passwords, checked.
	const auth, priv = "authp4ss", "privp4ss"
	for what, body := range map[string]map[string]any{
		"short password": {"instance_id": inst, "name": "mon", "auth_protocol": "SHA-256", "new_auth_password": "short", "priv_protocol": ""},
		"md5":            {"instance_id": inst, "name": "mon", "auth_protocol": "MD5", "new_auth_password": auth, "priv_protocol": ""},
		"no priv pw":     {"instance_id": inst, "name": "mon", "auth_protocol": "SHA-256", "new_auth_password": auth, "priv_protocol": "AES"},
		"same passwords": {"instance_id": inst, "name": "mon", "auth_protocol": "SHA-256", "new_auth_password": auth, "priv_protocol": "AES", "new_priv_password": auth},
		"bad name":       {"instance_id": inst, "name": "a b", "auth_protocol": "SHA-256", "new_auth_password": auth, "priv_protocol": ""},
	} {
		if rec := env.do("POST", "/api/snmp/users", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	rec = env.do("POST", "/api/snmp/users", map[string]any{"instance_id": inst, "name": "mon", "enabled": true, "auth_protocol": "SHA-256", "new_auth_password": auth, "priv_protocol": "AES", "new_priv_password": priv})
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), auth) || strings.Contains(rec.Body.String(), priv) ||
		!strings.Contains(rec.Body.String(), `"has_auth_password":true`) || !strings.Contains(rec.Body.String(), `"has_priv_password":true`) {
		t.Fatalf("create user: %d %s", rec.Code, rec.Body)
	}
	var u struct{ ID uint }
	_ = json.Unmarshal(rec.Body.Bytes(), &u)
	if rec := env.do("PUT", "/api/snmp/users/"+itoa(u.ID), map[string]any{"description": "NMS"}); rec.Code != http.StatusOK {
		t.Errorf("update keeping passwords: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("GET", "/api/snmp/users?instance_id="+itoa(inst), nil); strings.Contains(rec.Body.String(), auth) {
		t.Errorf("list holds the password: %s", rec.Body)
	}

	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	s := doc.Instance("main").SNMP
	if s == nil || s.Community != community || s.Location != "rack 1" || s.Contact != "noc@example.com" || strings.Join(s.Interfaces, " ") != "eth1" ||
		len(s.Users) != 1 || s.Users[0].AuthPassword != auth || s.Users[0].PrivPassword != priv {
		t.Fatalf("snmp %+v", s)
	}
	b, _ := json.Marshal(redactDoc(*doc))
	for _, secret := range []string{community, auth, priv} {
		if strings.Contains(string(b), secret) {
			t.Errorf("redacted document holds %q", secret)
		}
	}

	// Clearing the community leaves the user.
	if rec := env.do("PUT", path, map[string]any{"clear_snmp_community": true}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"has_snmp_community":false`) {
		t.Errorf("clear: %d %s", rec.Code, rec.Body)
	}
}
