// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

func TestACMEProxy(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=lan", map[string]any{"kind": "physical", "ipv4-mode": "static", "addresses": []string{"192.168.1.1/24"}, "enabled": true, "acme-proxy-serve": true})
	env.put("instance=main/dns-update=ns", map[string]any{"enabled": false, "interface": "lan", "server": "192.0.2.53", "zone": "example.com", "tsig-name": "acme-key", "tsig-algorithm": "hmac-sha256", "tsig-secret": "c2VjcmV0"})
	chain, key := testPair(t, "acme.example.com")
	env.put("instance=main/certificate=proxy", map[string]any{"enabled": true, "source": "import", "full-chain": chain, "priv-key": key})
	env.vf("lab")
	env.put("host=servers", map[string]any{"addresses": []string{"192.168.1.0/26"}})

	if rec := env.cfg("PATCH", "instance=main", map[string]any{"acme-proxy-enabled": true}); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "add a policy first") {
		t.Errorf("enabled without policies: %d %s", rec.Code, rec.Body)
	}

	pol := map[string]any{"enabled": true, "dns-update": "ns", "domains": []string{"*.LAN.example.com.", "*.lan.example.com"}, "sources": []string{"servers"}}
	for field, v := range map[string]any{
		"domains":    []string{"bad name"},
		"sources":    []string{"nothing"},
		"dns-update": nil,
	} {
		p := maps.Clone(pol)
		p[field] = v
		if rec := env.cfg("PUT", "instance=main/acme-proxy-policy=lan", p); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	env.put("instance=lab/interface=eth9", map[string]any{"kind": "physical", "enabled": true})
	env.put("instance=lab/dns-update=ns2", map[string]any{"enabled": false, "interface": "eth9", "server": "192.0.2.53", "zone": "example.com"})
	p := maps.Clone(pol)
	p["dns-update"] = "ns2"
	if rec := env.cfg("PUT", "instance=main/acme-proxy-policy=lan", p); rec.Code != http.StatusBadRequest {
		t.Errorf("another VF's DNS update client accepted: %d %s", rec.Code, rec.Body)
	}
	env.put("instance=main/acme-proxy-policy=lan", pol)
	env.patch("instance=main", map[string]any{"acme-proxy-enabled": true, "acme-proxy-certificate": "proxy", "acme-proxy-email": "admin@example.com"})

	doc, err := builder.Build(env.input(), 1)
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
	if red := doc.Redacted(); red.Instance("main").ACMEProxy.Policies[0].DNS01.TSIG.Secret != "<redacted>" || x.Policies[0].DNS01.TSIG.Secret != "c2VjcmV0" {
		t.Error("TSIG secret not redacted, or redacted in place")
	}

	// Renaming the host object rewrites the sources.
	env.mustCfg("POST", "host=servers?action=rename", map[string]any{"keys": []string{"web-servers"}})
	if got := env.node("instance=main/acme-proxy-policy=lan").LeafLists["sources"]; !slices.Equal(got, []string{"web-servers"}) {
		t.Errorf("sources after rename: %v", got)
	}
	for _, path := range []string{"instance=main/dns-update=ns", "instance=main/certificate=proxy", "instance=main/acme-proxy-policy=lan"} {
		if rec := env.cfg("DELETE", path, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("delete %s: %d %s", path, rec.Code, rec.Body)
		}
	}
	env.patch("instance=main", map[string]any{"acme-proxy-enabled": false})
	env.mustCfg("DELETE", "instance=main/acme-proxy-policy=lan", nil)
}

// A policy may get its names upstream by HTTP-01 on an interface instead
// of DNS-01: no DNS update client, and the interface can't be deleted.
func TestACMEProxyHTTP01(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=lan", map[string]any{"kind": "physical", "ipv4-mode": "static", "addresses": []string{"192.168.1.1/24"}, "enabled": true, "acme-proxy-serve": true})
	env.put("instance=main/interface=wan", map[string]any{"kind": "physical", "ipv4-mode": "static", "addresses": []string{"198.51.100.1/24"}, "enabled": true})
	env.vf("lab")
	env.put("instance=lab/interface=eth9", map[string]any{"kind": "physical", "enabled": true})

	pol := map[string]any{"enabled": true, "challenge": "http-01", "domains": []string{"*.web.example.com"}, "sources": []string{"192.168.1.0/24"}}
	for _, ifc := range []any{nil, "eth9"} {
		pol["interface"] = ifc
		if rec := env.cfg("PUT", "instance=main/acme-proxy-policy=web", pol); rec.Code != http.StatusBadRequest {
			t.Errorf("interface %v: %d %s", ifc, rec.Code, rec.Body)
		}
	}
	pol["interface"] = "wan"
	env.put("instance=main/acme-proxy-policy=web", pol)
	env.patch("instance=main", map[string]any{"acme-proxy-enabled": true})

	doc, err := builder.Build(env.input(), 1)
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
	if red := doc.Redacted(); red.Instance("main").ACMEProxy.Policies[0].DNS01 != nil {
		t.Error("redacting added a DNS update client")
	}
	if rec := env.cfg("DELETE", "instance=main/interface=wan", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete wan: %d %s", rec.Code, rec.Body)
	}
	// Back to DNS-01: the interface is dropped.
	env.put("instance=main/dns-update=ns", map[string]any{"enabled": false, "interface": "lan", "server": "192.0.2.53", "zone": "example.com"})
	env.patch("instance=main/acme-proxy-policy=web", map[string]any{"challenge": "dns-01", "dns-update": "ns"})
	if got := env.node("instance=main/acme-proxy-policy=web"); got.Leaf("interface") != "" || got.Leaf("dns-update") != "ns" {
		t.Errorf("after DNS-01: %+v", got.Leaves)
	}
}
