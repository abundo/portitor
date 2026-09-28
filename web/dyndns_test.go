// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/models"
)

func TestDynDNS(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	eth0 := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "ipv4_mode": "dhcp", "enabled": true})
	other := env.create("/api/instances", map[string]any{"name": "lab"})
	eth9 := env.create("/api/interfaces", map[string]any{"instance_id": other, "name": "eth9", "enabled": true})

	const secret = "c2VjcmV0c2VjcmV0c2VjcmV0"
	client := map[string]any{
		"instance_id": inst, "name": "home", "enabled": true, "interface_id": eth0,
		"server": "192.0.2.53", "zone": "Example.com.", "tsig_name": "ddns-key.example.com.", "tsig_secret": secret,
	}
	for field, v := range map[string]any{
		"server":       "ns1.example.com",
		"interface_id": eth9,
		"tsig_secret":  "not base64!",
		"name":         "Home Net",
	} {
		c := map[string]any{}
		for k, x := range client {
			c[k] = x
		}
		c[field] = v
		if rec := env.do("POST", "/api/dyndns/clients", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}

	rec := env.do("POST", "/api/dyndns/clients", client)
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), secret) || !strings.Contains(rec.Body.String(), `"has_tsig_secret":true`) {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created models.DyndnsClient
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := itoa(created.ID)
	if created.Zone != "example.com" || created.TsigAlgorithm != "hmac-sha256" {
		t.Errorf("not normalised: %+v", created)
	}
	if rec := env.do("GET", "/api/dyndns/clients/"+id, nil); strings.Contains(rec.Body.String(), secret) {
		t.Errorf("secret leaked: %s", rec.Body)
	}
	// Saving without a secret keeps it; a key needs one.
	if rec := env.do("PUT", "/api/dyndns/clients/"+id, map[string]any{"description": "ISP"}); rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	var stored models.DyndnsClient
	env.srv.db.First(&stored, created.ID)
	if stored.TsigSecret != secret || stored.Description != "ISP" {
		t.Errorf("stored %+v", stored)
	}

	recs := "/api/dyndns/records"
	env.create(recs, map[string]any{"client_id": created.ID, "name": "home", "type": "a", "ttl": 60})
	env.create(recs, map[string]any{"client_id": created.ID, "name": "home", "type": "TXT"})
	www := env.create(recs, map[string]any{"client_id": created.ID, "name": "www", "type": "CNAME", "value": "home"})
	for what, r := range map[string]map[string]any{
		"duplicate":       {"name": "home.example.com.", "type": "A"},
		"cname conflict":  {"name": "www", "type": "TXT", "value": "x"},
		"outside zone":    {"name": "home.example.org.", "type": "A"},
		"bad type":        {"name": "mx", "type": "MX", "value": "10 mail"},
		"A with v6":       {"name": "v6", "type": "A", "value": "2001:db8::1"},
		"cname no target": {"name": "ftp", "type": "CNAME"},
	} {
		r["client_id"] = created.ID
		if rec := env.do("POST", recs, r); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	// Editing a record is checked against the others, not itself.
	if rec := env.do("PUT", recs+"/"+itoa(www), map[string]any{"value": "home.example.com."}); rec.Code != http.StatusOK {
		t.Errorf("edit record: %d %s", rec.Code, rec.Body)
	}
	// Moving the zone away from a record's absolute name is refused.
	env.create(recs, map[string]any{"client_id": created.ID, "name": "fixed.example.com.", "type": "A", "value": "192.0.2.10"})
	if rec := env.do("PUT", "/api/dyndns/clients/"+id, map[string]any{"zone": "example.org"}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not in zone") {
		t.Errorf("zone change: %d %s", rec.Code, rec.Body)
	}

	// The interface cannot go away under the client.
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(eth0), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "dynamic DNS home") {
		t.Errorf("delete used interface: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/interfaces/"+itoa(eth0), map[string]any{"instance_id": other}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "dynamic DNS home") {
		t.Errorf("move used interface: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	d := doc.Instance("main").DynDNS
	if len(d) != 1 || d[0].Interface != "eth0" || d[0].TSIG.Secret != secret || len(d[0].Records) != 4 || d[0].Records[0].Type != "A" {
		t.Fatalf("document: %+v", d)
	}
	if r := redactDoc(*doc); r.Instance("main").DynDNS[0].TSIG.Secret != "<redacted>" || doc.Instance("main").DynDNS[0].TSIG.Secret != secret {
		t.Error("redaction")
	}

	// Removing the key clears the secret.
	env.do("PUT", "/api/dyndns/clients/"+id, map[string]any{"tsig_name": ""})
	env.srv.db.First(&stored, created.ID)
	if stored.TsigSecret != "" || stored.TsigAlgorithm != "" {
		t.Errorf("key not cleared: %+v", stored)
	}
	if rec := env.do("DELETE", "/api/dyndns/clients/"+id, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	var n int64
	env.srv.db.Model(&models.DyndnsRecord{}).Count(&n)
	if n != 0 {
		t.Errorf("%d records left", n)
	}
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(eth0), nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete unused interface: %d %s", rec.Code, rec.Body)
	}
}
