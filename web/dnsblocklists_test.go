// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

func TestDNSBlocklists(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})

	tif := map[string]any{"instance_id": inst, "name": "tif", "enabled": true, "urls": []string{"https://example.com/tif-1.txt", "https://example.com/tif-2.txt"}}
	for field, v := range map[string]any{
		"name":    "TIF list!",
		"urls":    []string{},
		"action":  "redirect",
		"refresh": 2,
	} {
		b := map[string]any{}
		for k, x := range tif {
			b[k] = x
		}
		b[field] = v
		if rec := env.do("POST", "/api/dns/blocklists", b); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	id := env.create("/api/dns/blocklists", tif)
	var row models.DnsBlocklist
	env.srv.db.First(&row, id)
	if row.Action != fwconfig.BlocklistNXDomain || row.Refresh != fwconfig.DefaultBlocklistRefresh {
		t.Errorf("defaults: %+v", row)
	}

	// The key is write-only, needs {key} and https, and stays when an
	// edit leaves it out.
	const key = "abuse-ch-key-0123"
	urlhaus := map[string]any{"instance_id": inst, "name": "urlhaus", "enabled": true, "urls": []string{"https://example.com/{key}/rpz.txt"}, "refresh": 10}
	if rec := env.do("POST", "/api/dns/blocklists", urlhaus); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no key") {
		t.Errorf("{key} without a key: %d %s", rec.Code, rec.Body)
	}
	urlhaus["auth_key"] = key
	urlhaus["urls"] = []string{"http://example.com/{key}/rpz.txt"}
	if rec := env.do("POST", "/api/dns/blocklists", urlhaus); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unencrypted") {
		t.Errorf("key over http: %d %s", rec.Code, rec.Body)
	}
	urlhaus["urls"] = []string{"https://example.com/{key}/rpz.txt"}
	rec := env.do("POST", "/api/dns/blocklists", urlhaus)
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), key) || !strings.Contains(rec.Body.String(), `"has_auth_key":true`) {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	uh := env.create("/api/dns/blocklists", map[string]any{"instance_id": inst, "name": "other", "urls": []string{"https://example.com/x"}})
	env.do("DELETE", "/api/dns/blocklists/"+itoa(uh), nil)
	row = models.DnsBlocklist{}
	env.srv.db.Where("name = ?", "urlhaus").First(&row)
	if rec := env.do("PUT", "/api/dns/blocklists/"+itoa(row.ID), map[string]any{"action": "log"}); rec.Code != http.StatusOK {
		t.Fatalf("edit: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&row, row.ID)
	if row.AuthKey != key || row.Action != fwconfig.BlocklistLog {
		t.Errorf("after edit: %+v", row)
	}

	// The allowed names are normalised.
	if rec := env.do("PUT", "/api/instances/"+itoa(inst), map[string]any{"dns_blocklist_allow": []string{"Example.COM.", "*.cdn.example"}}); rec.Code != http.StatusOK {
		t.Fatalf("allow: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/instances/"+itoa(inst), map[string]any{"dns_blocklist_allow": []string{"not a domain"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad allowed name: %d %s", rec.Code, rec.Body)
	}

	// The document has the enabled lists, by name, with the key; the
	// history's copy hides it.
	env.do("PUT", "/api/dns/blocklists/"+itoa(id), map[string]any{"enabled": false})
	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	dns := doc.Instance("main").DNS
	if len(dns.Blocklists) != 1 || dns.Blocklists[0].Name != "urlhaus" || dns.Blocklists[0].Key != key || dns.Blocklists[0].Refresh != 10 ||
		strings.Join(dns.BlocklistAllow, ",") != "example.com,cdn.example" {
		t.Errorf("document: %+v %v", dns.Blocklists, dns.BlocklistAllow)
	}
	if red := redactDoc(*doc); red.Instance("main").DNS.Blocklists[0].Key != "<redacted>" || doc.Instance("main").DNS.Blocklists[0].Key != key {
		t.Errorf("redacted: %+v", red.Instance("main").DNS.Blocklists)
	}
}
