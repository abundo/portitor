// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
)

func TestDNSBlocklists(t *testing.T) {
	env := newEnv(t)
	env.host("main")

	tif := map[string]any{"enabled": true, "urls": []string{"https://example.com/tif-1.txt", "https://example.com/tif-2.txt"}}
	for field, v := range map[string]any{
		"urls":    []string{},
		"action":  "redirect",
		"refresh": 2,
	} {
		b := map[string]any{}
		for k, x := range tif {
			b[k] = x
		}
		b[field] = v
		if rec := env.cfg("PUT", "instance=main/dns-blocklist=tif", b); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	if rec := env.cfg("PUT", "instance=main/dns-blocklist=TIF%20list!", tif); rec.Code != http.StatusBadRequest {
		t.Errorf("bad name accepted: %d %s", rec.Code, rec.Body)
	}
	env.put("instance=main/dns-blocklist=tif", tif)
	if row := env.node("instance=main/dns-blocklist=tif"); row.Leaf("action") != fwconfig.BlocklistNXDomain || row.Leaf("refresh") != "720" {
		t.Errorf("defaults: %+v", row.Leaves)
	}

	// The key is a secret, needs {key} and https, and stays when a replace
	// leaves it out.
	const key = "abuse-ch-key-0123"
	urlhaus := map[string]any{"enabled": true, "urls": []string{"https://example.com/{key}/rpz.txt"}, "refresh": 10}
	if rec := env.cfg("PUT", "instance=main/dns-blocklist=urlhaus", urlhaus); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "no key") {
		t.Errorf("{key} without a key: %d %s", rec.Code, rec.Body)
	}
	urlhaus["auth-key"] = key
	urlhaus["urls"] = []string{"http://example.com/{key}/rpz.txt"}
	if rec := env.cfg("PUT", "instance=main/dns-blocklist=urlhaus", urlhaus); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unencrypted") {
		t.Errorf("key over http: %d %s", rec.Code, rec.Body)
	}
	urlhaus["urls"] = []string{"https://example.com/{key}/rpz.txt"}
	env.put("instance=main/dns-blocklist=urlhaus", urlhaus)
	if rec := env.do("GET", "/api/config/candidate/instance=main/dns-blocklist", nil); strings.Contains(rec.Body.String(), key) {
		t.Errorf("the key read back: %s", rec.Body)
	}
	delete(urlhaus, "auth-key")
	urlhaus["action"] = "log"
	env.put("instance=main/dns-blocklist=urlhaus", urlhaus)
	if row := env.node("instance=main/dns-blocklist=urlhaus"); row.Leaf("auth-key") != key || row.Leaf("action") != fwconfig.BlocklistLog {
		t.Errorf("after edit: %+v", row.Leaves)
	}

	// The allowed names are normalised.
	env.patch("instance=main", map[string]any{"dns-blocklist-allow": []string{"Example.COM.", "*.cdn.example"}})
	if rec := env.cfg("PATCH", "instance=main", map[string]any{"dns-blocklist-allow": []string{"not a domain"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad allowed name: %d %s", rec.Code, rec.Body)
	}

	// The document has the enabled lists, by name, with the key; the
	// history's copy hides it.
	env.patch("instance=main/dns-blocklist=tif", map[string]any{"enabled": false})
	doc, err := builder.Build(env.input(), 1)
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
