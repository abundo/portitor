// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
	"github.com/abundo/portitor/models"
)

func TestACMEProxy(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	lan := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "lan", "ipv4_mode": "static",
		"addresses": []string{"192.168.1.1/24"}, "enabled": true, "acme_proxy_serve": true})
	dc := env.create("/api/dyndns/clients", map[string]any{
		"instance_id": inst, "name": "ns", "enabled": false, "interface_id": lan,
		"server": "192.0.2.53", "zone": "example.com",
		"tsig_name": "acme-key", "tsig_algorithm": "hmac-sha256", "tsig_secret": "c2VjcmV0",
	})
	chain, key := testPair(t, "acme.example.com")
	cert := env.create("/api/certificates", map[string]any{"instance_id": inst, "name": "proxy", "enabled": true,
		"source": "import", "fullchain": chain, "privkey": key})
	other := env.create("/api/instances", map[string]any{"name": "lab"})
	env.create("/api/objects", map[string]any{"name": "servers", "addresses": []string{"192.168.1.0/26"}})

	if rec := env.do("PUT", "/api/instances/"+itoa(inst), map[string]any{"acme_proxy_enabled": true}); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "add a policy first") {
		t.Errorf("enabled without policies: %d %s", rec.Code, rec.Body)
	}

	pol := map[string]any{"instance_id": inst, "name": "lan", "enabled": true, "dyndns_client_id": dc,
		"domains": []string{"*.LAN.example.com.", "*.lan.example.com"}, "sources": []string{"servers"}}
	for field, v := range map[string]any{
		"domains":          []string{"bad name"},
		"sources":          []string{"nothing"},
		"dyndns_client_id": 0,
		"name":             "",
	} {
		p := map[string]any{}
		for k, x := range pol {
			p[k] = x
		}
		p[field] = v
		if rec := env.do("POST", "/api/acme-proxy/policies", p); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	eth9 := env.create("/api/interfaces", map[string]any{"instance_id": other, "name": "eth9", "enabled": true})
	labDC := env.create("/api/dyndns/clients", map[string]any{"instance_id": other, "name": "ns", "interface_id": eth9, "server": "192.0.2.53", "zone": "example.com"})
	p := map[string]any{}
	for k, x := range pol {
		p[k] = x
	}
	p["dyndns_client_id"] = labDC
	if rec := env.do("POST", "/api/acme-proxy/policies", p); rec.Code != http.StatusBadRequest {
		t.Errorf("another VF's DNS update client accepted: %d %s", rec.Code, rec.Body)
	}
	pid := env.create("/api/acme-proxy/policies", pol)

	if rec := env.do("PUT", "/api/instances/"+itoa(inst), map[string]any{"acme_proxy_enabled": true, "acme_proxy_certificate_id": cert,
		"acme_proxy_email": "admin@example.com"}); rec.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	x := doc.Instance("main").ACMEProxy
	if x == nil || x.Port != 8555 || x.CA != "letsencrypt" || x.Certificate != "proxy" || !slices.Equal(x.Interfaces, []string{"lan"}) || len(x.Policies) != 1 {
		t.Fatalf("document: %+v", x)
	}
	if p := x.Policies[0]; !slices.Equal(p.Domains, []string{"*.lan.example.com"}) || !slices.Equal(p.Sources, []string{"192.168.1.0/26"}) ||
		p.DNS01.Client != "ns" || p.DNS01.TSIG == nil || p.DNS01.TSIG.Secret != "c2VjcmV0" {
		t.Errorf("policy: %+v", p)
	}
	var found bool
	for _, r := range render.AutoInputRules(doc.Instance("main")) {
		found = found || r.Service == fwconfig.ACMEProxyService && r.SourceSet == fwconfig.ACMEProxySet
	}
	if !found {
		t.Error("no auto rule")
	}
	if red := redactDoc(*doc); red.Instance("main").ACMEProxy.Policies[0].DNS01.TSIG.Secret != "<redacted>" || x.Policies[0].DNS01.TSIG.Secret != "c2VjcmV0" {
		t.Error("TSIG secret not redacted, or redacted in place")
	}

	// Renaming the host object rewrites the sources.
	var obj models.AddressObject
	env.srv.db.Where("name = ?", "servers").First(&obj)
	if rec := env.do("PUT", "/api/objects/"+itoa(obj.ID), map[string]any{"name": "web-servers"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	var got models.AcmeProxyPolicy
	env.srv.db.First(&got, pid)
	if !slices.Equal(got.Sources, []string{"web-servers"}) {
		t.Errorf("sources after rename: %v", got.Sources)
	}

	for _, c := range []struct{ path, want string }{
		{"/api/dyndns/clients/" + itoa(dc), "ACME proxy policy lan"},
		{"/api/certificates/" + itoa(cert), "used by the ACME proxy"},
		{"/api/acme-proxy/policies/" + itoa(pid), "turn it off first"},
	} {
		if rec := env.do("DELETE", c.path, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("delete %s: %d %s", c.path, rec.Code, rec.Body)
		}
	}
	if rec := env.do("PUT", "/api/instances/"+itoa(inst), map[string]any{"acme_proxy_enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/acme-proxy/policies/"+itoa(pid), nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete policy of a stopped proxy: %d %s", rec.Code, rec.Body)
	}
}

// A policy may get its names upstream by HTTP-01 on an interface instead
// of DNS-01: no DNS update client, and the interface can't be deleted.
func TestACMEProxyHTTP01(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	lan := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "lan", "ipv4_mode": "static",
		"addresses": []string{"192.168.1.1/24"}, "enabled": true, "acme_proxy_serve": true})
	wan := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "wan", "ipv4_mode": "static",
		"addresses": []string{"198.51.100.1/24"}, "enabled": true})
	other := env.create("/api/instances", map[string]any{"name": "lab"})
	eth9 := env.create("/api/interfaces", map[string]any{"instance_id": other, "name": "eth9", "enabled": true})

	pol := map[string]any{"instance_id": inst, "name": "web", "enabled": true, "challenge": "http-01",
		"domains": []string{"*.web.example.com"}, "sources": []string{"192.168.1.0/24"}}
	for _, ifc := range []any{nil, eth9} {
		pol["interface_id"] = ifc
		if rec := env.do("POST", "/api/acme-proxy/policies", pol); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "pick an interface") {
			t.Errorf("interface %v: %d %s", ifc, rec.Code, rec.Body)
		}
	}
	pol["interface_id"] = wan
	pid := env.create("/api/acme-proxy/policies", pol)
	if rec := env.do("PUT", "/api/instances/"+itoa(inst), map[string]any{"acme_proxy_enabled": true}); rec.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	x := doc.Instance("main").ACMEProxy
	if x == nil || len(x.Policies) != 1 {
		t.Fatalf("document: %+v", x)
	}
	if p := x.Policies[0]; p.Challenge != fwconfig.ChallengeHTTP01 || p.Interface != "wan" || p.DNS01 != nil {
		t.Errorf("policy: %+v", p)
	}
	var found bool
	for _, r := range render.AutoInputRules(doc.Instance("main")) {
		found = found || r.Service == render.ACMEHTTPService && slices.Equal(r.InInterfaces, []string{"wan"})
	}
	if !found {
		t.Error("no HTTP-01 auto rule on wan")
	}
	if red := redactDoc(*doc); red.Instance("main").ACMEProxy.Policies[0].DNS01 != nil {
		t.Error("redacting added a DNS update client")
	}

	if rec := env.do("DELETE", "/api/interfaces/"+itoa(wan), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "ACME proxy policy web") {
		t.Errorf("delete wan: %d %s", rec.Code, rec.Body)
	}
	// Back to DNS-01: the interface is dropped.
	dc := env.create("/api/dyndns/clients", map[string]any{"instance_id": inst, "name": "ns", "interface_id": lan,
		"server": "192.0.2.53", "zone": "example.com"})
	if rec := env.do("PUT", "/api/acme-proxy/policies/"+itoa(pid), map[string]any{"challenge": "dns-01", "dyndns_client_id": dc}); rec.Code != http.StatusOK {
		t.Fatalf("to DNS-01: %d %s", rec.Code, rec.Body)
	}
	var got models.AcmeProxyPolicy
	env.srv.db.First(&got, pid)
	if got.InterfaceID != nil || got.DyndnsClientID == nil || *got.DyndnsClientID != dc {
		t.Errorf("after DNS-01: %+v", got)
	}
}
