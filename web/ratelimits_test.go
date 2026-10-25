// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

func TestRateLimits(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	other := env.create("/api/instances", map[string]any{"name": "guest"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "enabled": true, "shape_egress": 40, "shape_ingress": 400})
	if rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": inst, "name": "ifb-eth0"}); rec.Code != http.StatusBadRequest {
		t.Errorf("ifb- interface name accepted: %d", rec.Code)
	}
	ssh := env.create("/api/rate-limits", map[string]any{"instance_id": inst, "name": " ssh ", "rate": 4, "per": "minute", "burst": 2, "per_source": true})
	sshURL := fmt.Sprint("/api/rate-limits/", ssh)
	env.create("/api/rate-limits", map[string]any{"instance_id": other, "name": "theirs", "rate": 1, "per": "second"})
	for _, body := range []map[string]any{
		{"instance_id": inst, "name": "zero", "rate": 0, "per": "second"},
		{"instance_id": inst, "name": "bytes", "rate": 1, "unit": "mbytes", "per": "second", "connections": true},
		{"instance_id": inst, "name": "burst", "rate": 1, "per": "second", "burst": -1},
		{"instance_id": inst, "name": "ssh", "rate": 1, "per": "second"},
		{"instance_id": inst, "name": "bytes", "rate": 1, "unit": "mbytes", "per": "second"},
		{"instance_id": inst, "name": "bits", "rate": 1, "unit": "mbits", "per": "second", "connections": true},
	} {
		if rec := env.do("POST", "/api/rate-limits", body); rec.Code < 400 {
			t.Errorf("%v accepted: %d", body, rec.Code)
		}
	}

	rule := env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "input", "action": "accept", "in_interfaces": []string{"eth0"}, "rate_limit": "ssh", "enabled": true})
	if rec := env.do("POST", "/api/rules", map[string]any{"instance_id": inst, "chain": "input", "action": "accept", "rate_limit": "theirs"}); rec.Code != http.StatusBadRequest {
		t.Errorf("other instance's rate limit accepted: %d", rec.Code)
	}

	// A limit that polices connections needs accept rules.
	env.create("/api/rate-limits", map[string]any{"instance_id": inst, "name": "host", "rate": 2, "unit": "mbit", "connections": true, "per_source": true})
	if rec := env.do("POST", "/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "drop", "rate_limit": "host"}); rec.Code != http.StatusBadRequest {
		t.Errorf("drop rule with a connection limit accepted: %d", rec.Code)
	}
	env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "accept", "rate_limit": "host", "enabled": true})
	drop := env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "input", "action": "drop", "rate_limit": "ssh"})
	if rec := env.do("PUT", sshURL, map[string]any{"connections": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("connections on a limit a drop rule names: %d", rec.Code)
	}
	env.do("DELETE", fmt.Sprint("/api/rules/", drop), nil)

	if rec := env.do("PUT", sshURL, map[string]any{"name": "admin"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	var r models.Rule
	env.srv.db.First(&r, rule)
	if r.RateLimit != "admin" {
		t.Errorf("rule after rename: %q", r.RateLimit)
	}
	rec := env.do("DELETE", sshURL, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "input rule") {
		t.Errorf("delete in use: %d %s", rec.Code, rec.Body)
	}

	// Shaping: accept rules only; a rate per second in bytes or bits.
	if rec := env.do("POST", "/api/rate-limits", map[string]any{"instance_id": inst, "name": "pk", "rate": 5, "unit": "mbytes", "shape": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("shaping in mbytes accepted: %d", rec.Code)
	}
	var dm models.RateLimit
	env.srv.db.First(&dm, env.create("/api/rate-limits", map[string]any{"instance_id": inst, "name": "dflt", "rate": 5, "shape": true}))
	if dm.Unit != "mbit" {
		t.Errorf("shaping unit defaults to %q", dm.Unit)
	}
	env.do("DELETE", fmt.Sprint("/api/rate-limits/", dm.ID), nil)
	bulk := env.create("/api/rate-limits", map[string]any{"instance_id": inst, "name": "bulk", "rate": 50, "unit": "mbit", "per": "minute", "burst": 3, "per_source": true, "shape": true})
	var bl models.RateLimit
	env.srv.db.First(&bl, bulk)
	if bl.Per != "second" || bl.Burst != 0 || bl.PerSource {
		t.Errorf("shaping kept limit fields: %+v", bl)
	}
	if rec := env.do("POST", "/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "reject", "rate_limit": "bulk"}); rec.Code != http.StatusBadRequest {
		t.Errorf("reject rule that shapes accepted: %d", rec.Code)
	}
	env.create("/api/rules", map[string]any{"instance_id": inst, "chain": "forward", "action": "accept", "rate_limit": "bulk", "enabled": true})

	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	main := doc.Instances[0]
	// Less the services' (TestServiceRateLimits).
	main.RateLimits = slices.DeleteFunc(main.RateLimits, func(l fwconfig.RateLimit) bool { return strings.HasSuffix(l.Name, " server") })
	want := []fwconfig.RateLimit{
		{Name: "admin", Rate: 4, Per: "second", Burst: 2, PerSource: true},
		{Name: "bulk", Rate: 50, Unit: "mbit", Per: "second", Shape: true},
		{Name: "host", Rate: 2, Unit: "mbit", Per: "second", PerSource: true, Connections: true},
	}
	if len(main.RateLimits) != 3 || main.RateLimits[0] != want[0] || main.RateLimits[1] != want[1] || main.RateLimits[2] != want[2] {
		t.Errorf("rate limits: %+v", main.RateLimits)
	}
	if sh := main.Shapers(); len(sh) != 1 || sh[0].Name != "bulk" || sh[0].Bits() != 50000000 {
		t.Errorf("shapers: %+v", sh)
	}
	if ifc := main.Interfaces[0]; ifc.ShapeEgress != 40 || ifc.ShapeIngress != 400 {
		t.Errorf("shaping: %+v", ifc)
	}
}

// A new instance gets a rate limit for each of its DNS, DHCP and NTP
// servers, switched on. Renaming one keeps it the service's; deleting one
// that is on, or shaping one, is refused; switching one on again makes it
// anew if it was deleted.
func TestServiceRateLimits(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	instURL := fmt.Sprint("/api/instances/", inst)
	var in models.Instance
	env.srv.db.First(&in, inst)
	if !in.DnsRateLimit || !in.DhcpRateLimit || !in.NtpRateLimit {
		t.Fatalf("service rate limits off: %v %v %v", in.DnsRateLimit, in.DhcpRateLimit, in.NtpRateLimit)
	}
	limitOf := func(service string) models.RateLimit {
		var l models.RateLimit
		env.srv.db.Where("instance_id = ? AND service = ?", inst, service).Limit(1).Find(&l)
		return l
	}
	dns := limitOf("dns")
	if dns.Name != "dns server" || dns.Rate != fwconfig.DefaultServiceRate || dns.Unit != fwconfig.RateUnitMBit || dns.Shape {
		t.Errorf("dns server rate limit: %+v", dns)
	}
	dnsURL := fmt.Sprint("/api/rate-limits/", dns.ID)

	if rec := env.do("PUT", dnsURL, map[string]any{"name": "resolver", "rate": 5, "service": ""}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	if l := limitOf("dns"); l.Name != "resolver" || l.Rate != 5 {
		t.Errorf("after rename: %+v", l)
	}
	if rec := env.do("DELETE", dnsURL, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "DNS server") {
		t.Errorf("delete while on: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", dnsURL, map[string]any{"shape": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("shaping a service's limit: %d", rec.Code)
	}
	if rec := env.do("POST", "/api/rate-limits", map[string]any{"instance_id": inst, "name": "mine", "rate": 1, "service": "ntp"}); rec.Code < 400 {
		var n int64
		env.srv.db.Model(&models.RateLimit{}).Where("instance_id = ? AND service = ?", inst, "ntp").Count(&n)
		if n != 1 {
			t.Errorf("a second ntp rate limit through the API: %d", n)
		}
	}

	// Off, the DHCP server's can go; on again, it is back.
	if rec := env.do("PUT", instURL, map[string]any{"dhcp_rate_limit": false}); rec.Code != http.StatusOK {
		t.Fatalf("switch off: %d %s", rec.Code, rec.Body)
	}
	dhcp := limitOf("dhcp")
	if rec := env.do("DELETE", fmt.Sprint("/api/rate-limits/", dhcp.ID), nil); rec.Code >= 400 {
		t.Errorf("delete while off: %d %s", rec.Code, rec.Body)
	}
	env.do("PUT", instURL, map[string]any{"ntp_enabled": true, "ntp_servers": []map[string]any{{"address": "192.0.2.123"}}})
	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	main := doc.Instances[0]
	if main.DNS.RateLimit != "resolver" || main.DHCP.RateLimit != "" || main.NTP == nil || main.NTP.RateLimit != "ntp server" {
		t.Errorf("document: dns %q dhcp %q ntp %+v", main.DNS.RateLimit, main.DHCP.RateLimit, main.NTP)
	}
	if rec := env.do("PUT", instURL, map[string]any{"dhcp_rate_limit": true}); rec.Code != http.StatusOK {
		t.Fatalf("switch on: %d %s", rec.Code, rec.Body)
	}
	if l := limitOf("dhcp"); l.Name != "dhcp server" || l.ID == dhcp.ID {
		t.Errorf("dhcp server rate limit made again: %+v", l)
	}
}
