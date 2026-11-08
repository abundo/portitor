// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
)

func TestDynDNS(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "ipv4-mode": "dhcp", "enabled": true})
	env.vf("lab")
	env.put("instance=lab/interface=eth9", map[string]any{"kind": "physical", "enabled": true})

	const secret = "c2VjcmV0c2VjcmV0c2VjcmV0"
	client := map[string]any{
		"enabled": false, "interface": "eth0",
		"server": "192.0.2.53", "zone": "Example.com.", "tsig-name": "ddns-key.example.com.", "tsig-secret": secret,
	}
	for field, v := range map[string]any{
		"server":      "ns1",
		"interface":   "eth9",
		"tsig-secret": "not base64!",
	} {
		c := maps.Clone(client)
		c[field] = v
		if rec := env.cfg("PUT", "instance=main/dns-update=home", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	if rec := env.cfg("PUT", "instance=main/dns-update=..", client); rec.Code != http.StatusBadRequest {
		t.Errorf("bad name accepted: %d %s", rec.Code, rec.Body)
	}
	home := "instance=main/dns-update=home"
	env.put(home, client)
	if d := env.node(home); d.Leaf("zone") != "example.com" || d.Leaf("tsig-algorithm") != "hmac-sha256" {
		t.Errorf("not normalised: %+v", d.Leaves)
	}
	if rec := env.do("GET", "/api/config/candidate/"+home, nil); strings.Contains(rec.Body.String(), secret) {
		t.Errorf("secret leaked: %s", rec.Body)
	}
	// A nameserver by name.
	env.patch(home, map[string]any{"server": "ns1.example.net:5353"})
	// A replace without the secret keeps it.
	c := maps.Clone(client)
	delete(c, "tsig-secret")
	c["server"], c["description"] = "ns1.example.net:5353", "ISP"
	env.put(home, c)
	if d := env.node(home); d.Leaf("tsig-secret") != secret || d.Leaf("description") != "ISP" {
		t.Errorf("stored %+v", d.Leaves)
	}

	recs := home + "/record"
	env.post(recs, map[string]any{"name": "home", "type": "a", "ttl": 60})
	env.post(recs, map[string]any{"name": "home", "type": "TXT"})
	www := env.post(recs, map[string]any{"name": "www", "type": "CNAME", "value": "home"})
	for what, r := range map[string]map[string]any{
		"duplicate":       {"name": "home.example.com.", "type": "A"},
		"cname conflict":  {"name": "www", "type": "TXT", "value": "x"},
		"outside zone":    {"name": "home.example.org.", "type": "A"},
		"bad type":        {"name": "mx", "type": "MX", "value": "10 mail"},
		"A with v6":       {"name": "v6", "type": "A", "value": "2001:db8::1"},
		"cname no target": {"name": "ftp", "type": "CNAME"},
	} {
		if rec := env.cfg("POST", recs, r); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	// Editing a record is checked against the others, not itself.
	env.patch(recs+"="+www, map[string]any{"value": "home.example.com."})
	env.patch(home, map[string]any{"enabled": true})
	// Moving the zone away from a record's absolute name is refused.
	env.post(recs, map[string]any{"name": "fixed.example.com.", "type": "A", "value": "192.0.2.10"})
	if rec := env.cfg("PATCH", home, map[string]any{"zone": "example.org"}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not in zone") {
		t.Errorf("zone change: %d %s", rec.Code, rec.Body)
	}
	// The interface can't go away under the client.
	if rec := env.cfg("DELETE", "instance=main/interface=eth0", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete used interface: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.input(), 1)
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
	env.patch(home, map[string]any{"tsig-name": nil})
	if d := env.node(home); d.Leaf("tsig-secret") != "" || d.Leaf("tsig-algorithm") != "" {
		t.Errorf("key not cleared: %+v", d.Leaves)
	}
	env.mustCfg("DELETE", home, nil)
	env.mustCfg("DELETE", "instance=main/interface=eth0", nil)
}

func TestDNSUpdateProvider(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "ipv4-mode": "dhcp", "enabled": true})

	const token = "cf-token-secret"
	settings := func(m map[string]string) []map[string]any {
		var out []map[string]any
		for k, v := range m {
			out = append(out, map[string]any{"name": k, "value": v})
		}
		return out
	}
	client := map[string]any{
		"enabled": false, "interface": "eth0", "zone": "example.com",
		"provider": "glesys", "provider-setting": settings(map[string]string{"project": "CL1", "api_key": token}),
		"server": "192.0.2.53", "tsig-name": "k.example.com", // left out with a provider
	}
	home := "instance=main/dns-update=home"
	for name, s := range map[string]map[string]string{
		"missing key":   {"project": "CL1"},
		"unknown field": {"project": "CL1", "api_key": "k", "nope": "x"},
		"control char":  {"project": "CL\n1", "api_key": "k"},
	} {
		c := maps.Clone(client)
		c["provider-setting"] = settings(s)
		if rec := env.cfg("PUT", home, c); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", name, rec.Code, rec.Body)
		}
	}
	c := maps.Clone(client)
	c["provider"] = "nope"
	if rec := env.cfg("PUT", home, c); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown provider accepted: %d %s", rec.Code, rec.Body)
	}
	env.put(home, client)
	if rec := env.do("GET", "/api/config/candidate/"+home, nil); strings.Contains(rec.Body.String(), token) {
		t.Errorf("the token read back: %s", rec.Body)
	}
	if d := env.node(home); d.Leaf("server") != "" || d.Leaf("tsig-name") != "" {
		t.Errorf("stored %+v", d.Leaves)
	}

	env.post(home+"/record", map[string]any{"name": "home", "type": "A"})
	env.patch(home, map[string]any{"enabled": true})
	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	d := doc.Instance("main").DynDNS[0]
	if d.Provider != "glesys" || d.Server != "" || d.ProviderSettings["api_key"] != token {
		t.Fatalf("document: %+v", d)
	}
	red := redactDoc(*doc)
	if r := red.Instance("main").DynDNS[0].ProviderSettings; r["api_key"] != "<redacted>" {
		t.Errorf("redaction: %v", r)
	}
	// Back to RFC 2136 clears the settings.
	env.patch(home, map[string]any{"provider": "rfc2136", "server": "192.0.2.53"})
	if s := env.node(home).Lists["provider-setting"]; len(s) != 0 {
		t.Errorf("settings kept: %v", s)
	}
	if rec := env.do("GET", "/api/dyndns/providers", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"cloudflare"`) {
		t.Errorf("providers: %d", rec.Code)
	}
}

// The dynamic zone editor replaces a client's records in one PUT.
func TestDynDNSRecordsReplace(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "ipv4-mode": "dhcp", "enabled": true})
	env.put("instance=main/dns-update=home", map[string]any{"enabled": false, "interface": "eth0", "server": "192.0.2.53", "zone": "example.com"})
	path := "instance=main/dns-update=home/record"
	for what, body := range map[string][]map[string]any{
		"duplicate":      {{"id": 1, "name": "home", "type": "A"}, {"id": 2, "name": "home", "type": "a"}},
		"cname conflict": {{"id": 1, "name": "www", "type": "CNAME", "value": "home"}, {"id": 2, "name": "www", "type": "TXT"}},
		"bad type":       {{"id": 1, "name": "mx", "type": "MX", "value": "10 mail"}},
		"cname target":   {{"id": 1, "name": "www", "type": "CNAME"}},
	} {
		if rec := env.cfg("PUT", path, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	env.put(path, []map[string]any{{"id": 1, "name": "@", "type": "a", "ttl": 60}, {"id": 2, "name": "www", "type": "CNAME", "value": "@"}})
	if rs := env.node("instance=main/dns-update=home").Lists["record"]; len(rs) != 2 || rs[0].Leaf("type") != "A" || rs[1].Leaf("type") != "CNAME" {
		t.Fatalf("replace: %v", rs)
	}
	env.put(path, []map[string]any{})
	if rs := env.node("instance=main/dns-update=home").Lists["record"]; len(rs) != 0 {
		t.Fatalf("clear: %v", rs)
	}
}
