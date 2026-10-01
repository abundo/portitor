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
	"github.com/abundo/portitor/internal/render"
	"github.com/abundo/portitor/models"
)

func TestCertificates(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	wan := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "wan", "ipv4_mode": "dhcp", "enabled": true})
	other := env.create("/api/instances", map[string]any{"name": "lab"})
	eth9 := env.create("/api/interfaces", map[string]any{"instance_id": other, "name": "eth9", "enabled": true})

	cert := map[string]any{
		"instance_id": inst, "name": "www", "enabled": true, "interface_id": wan,
		"domains": []string{"WWW.Example.com.", " example.com", "www.example.com"}, "email": "admin@example.com",
	}
	for field, v := range map[string]any{
		"interface_id": eth9,
		"domains":      []string{"*.example.com"},
		"ca":           "http://ca.example.com/directory",
		"key_type":     "dsa",
		"challenge":    "dns-01",
		"email":        "nobody",
		"name":         "Web Server",
	} {
		c := map[string]any{}
		for k, x := range cert {
			c[k] = x
		}
		c[field] = v
		if rec := env.do("POST", "/api/certificates", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}

	rec := env.do("POST", "/api/certificates", cert)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created models.Certificate
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if !slices.Equal(created.Domains, []string{"www.example.com", "example.com"}) ||
		created.Ca != "letsencrypt" || created.KeyType != "ec256" || created.Challenge != "http-01" {
		t.Errorf("not normalised: %+v", created)
	}

	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	main := doc.Instance("main")
	if main == nil || len(main.Certificates) != 1 || main.Certificates[0].Interface != "wan" {
		t.Fatalf("document: %+v", main)
	}
	var found bool
	for _, r := range render.AutoInputRules(main) {
		found = found || (r.Service == render.ACMEHTTPService && slices.Equal(r.InInterfaces, []string{"wan"}))
	}
	if !found {
		t.Errorf("no HTTP-01 auto rule: %+v", render.AutoInputRules(main))
	}

	if rec := env.do("DELETE", "/api/interfaces/"+itoa(wan), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "certificate www") {
		t.Errorf("delete used interface: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/certificates/"+itoa(created.ID), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(wan), nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete unused interface: %d %s", rec.Code, rec.Body)
	}
}
