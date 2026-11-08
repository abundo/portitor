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
)

func TestRateLimits(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.vf("guest")
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "enabled": true, "shape-egress": 40, "shape-ingress": 400})
	if rec := env.cfg("POST", "instance=main/interface", map[string]any{"kind": "physical", "name": "ifb-eth0"}); rec.Code != http.StatusBadRequest {
		t.Errorf("ifb- interface name accepted: %d", rec.Code)
	}
	env.post("instance=main/rate-limit", map[string]any{"name": "ssh", "rate": 4, "burst": 2, "per-source": true})
	env.post("instance=guest/rate-limit", map[string]any{"name": "theirs", "rate": 1})
	for _, body := range []map[string]any{
		{"name": "zero", "rate": 0},
		{"name": "bytes", "rate": 1, "unit": "mbytes", "connections": true},
		{"name": "burst", "rate": 1, "burst": -1},
		{"name": "ssh", "rate": 1},
		{"name": "bits", "rate": 1, "unit": "mbits", "connections": true},
	} {
		if rec := env.cfg("POST", "instance=main/rate-limit", body); rec.Code < 400 {
			t.Errorf("%v accepted: %d", body, rec.Code)
		}
	}

	rule := env.post("instance=main/rule", map[string]any{"chain": "input", "action": "accept", "in-interfaces": []string{"eth0"}, "rate-limit": "ssh"})
	if rec := env.cfg("POST", "instance=main/rule", map[string]any{"chain": "input", "action": "accept", "rate-limit": "theirs"}); rec.Code != http.StatusBadRequest {
		t.Errorf("other instance's rate limit accepted: %d", rec.Code)
	}

	// A limit that polices connections needs accept rules.
	env.post("instance=main/rate-limit", map[string]any{"name": "host", "rate": 2, "unit": "mbit", "connections": true, "per-source": true})
	if rec := env.cfg("POST", "instance=main/rule", map[string]any{"chain": "forward", "action": "drop", "rate-limit": "host"}); rec.Code != http.StatusBadRequest {
		t.Errorf("drop rule with a connection limit accepted: %d", rec.Code)
	}
	env.post("instance=main/rule", map[string]any{"chain": "forward", "action": "accept", "rate-limit": "host"})
	drop := env.post("instance=main/rule", map[string]any{"chain": "input", "action": "drop", "rate-limit": "ssh"})
	if rec := env.cfg("PATCH", "instance=main/rate-limit=ssh", map[string]any{"connections": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("connections on a limit a drop rule names: %d", rec.Code)
	}
	env.mustCfg("DELETE", "instance=main/rule="+drop, nil)

	env.mustCfg("POST", "instance=main/rate-limit=ssh?action=rename", map[string]any{"keys": []string{"admin"}})
	if got := env.node("instance=main/rule=" + rule).Leaf("rate-limit"); got != "admin" {
		t.Errorf("rule after rename: %q", got)
	}
	if rec := env.cfg("DELETE", "instance=main/rate-limit=admin", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete in use: %d %s", rec.Code, rec.Body)
	}

	// Shaping: accept rules only; a rate per second in bytes or bits.
	if rec := env.cfg("POST", "instance=main/rate-limit", map[string]any{"name": "pk", "rate": 5, "unit": "mbytes", "shape": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("shaping in mbytes accepted: %d", rec.Code)
	}
	env.post("instance=main/rate-limit", map[string]any{"name": "dflt", "rate": 5, "shape": true})
	if u := env.node("instance=main/rate-limit=dflt").Leaf("unit"); u != "mbit" {
		t.Errorf("shaping unit defaults to %q", u)
	}
	env.mustCfg("DELETE", "instance=main/rate-limit=dflt", nil)
	env.post("instance=main/rate-limit", map[string]any{"name": "bulk", "rate": 50, "unit": "mbit", "per": "minute", "burst": 3, "per-source": true, "shape": true})
	if bl := env.node("instance=main/rate-limit=bulk"); bl.Leaf("per") != "second" || bl.Leaf("burst") != "" || on(bl, "per-source") {
		t.Errorf("shaping kept limit fields: %+v", bl.Leaves)
	}
	if rec := env.cfg("POST", "instance=main/rule", map[string]any{"chain": "forward", "action": "reject", "rate-limit": "bulk"}); rec.Code != http.StatusBadRequest {
		t.Errorf("reject rule that shapes accepted: %d", rec.Code)
	}
	env.post("instance=main/rule", map[string]any{"chain": "forward", "action": "accept", "rate-limit": "bulk"})

	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	main := doc.Instance("main")
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
	if ifc := main.Interface("eth0"); ifc.ShapeEgress != 40 || ifc.ShapeIngress != 400 {
		t.Errorf("shaping: %+v", ifc)
	}
}

// A new instance gets a rate limit for each of its DNS, DHCP and NTP
// servers, switched on. Renaming one keeps it the service's; deleting one
// that is on, or shaping one, is refused; switching one on again makes it
// anew if it was deleted.
func TestServiceRateLimits(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	in := env.node("instance=main")
	if !on(in, "dns-rate-limit") || !on(in, "dhcp-rate-limit") || !on(in, "ntp-rate-limit") {
		t.Fatalf("service rate limits off: %v", in.Leaves)
	}
	limitOf := func(service string) string {
		for _, l := range env.node("instance=main").Lists["rate-limit"] {
			if l.Leaf("service") == service {
				return l.Leaf("name")
			}
		}
		return ""
	}
	dns := env.node("instance=main/rate-limit=dns%20server")
	if dns == nil || dns.Leaf("service") != "dns" || dns.Leaf("rate") != "1" || dns.Leaf("unit") != fwconfig.RateUnitMBit || on(dns, "shape") {
		t.Fatalf("dns server rate limit: %+v", dns)
	}
	env.mustCfg("POST", "instance=main/rate-limit=dns%20server?action=rename", map[string]any{"keys": []string{"resolver"}})
	env.patch("instance=main/rate-limit=resolver", map[string]any{"rate": 5})
	if limitOf("dns") != "resolver" {
		t.Errorf("after rename: %q", limitOf("dns"))
	}
	if rec := env.cfg("DELETE", "instance=main/rate-limit=resolver", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete while on: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("PATCH", "instance=main/rate-limit=resolver", map[string]any{"shape": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("shaping a service's limit: %d", rec.Code)
	}
	env.mustCfg("POST", "instance=main/rate-limit", map[string]any{"name": "mine", "rate": 1, "service": "ntp"})
	if env.node("instance=main/rate-limit=mine").Leaf("service") != "" {
		t.Error("a second ntp rate limit through the API")
	}

	// Off, the DHCP server's can go; on again, it is back.
	env.patch("instance=main", map[string]any{"dhcp-rate-limit": false})
	env.mustCfg("DELETE", "instance=main/rate-limit=dhcp%20server", nil)
	env.patch("instance=main", map[string]any{"ntp-enabled": true, "ntp-server": []map[string]any{{"address": "192.0.2.123"}}})
	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	main := doc.Instance("main")
	if main.DNS.RateLimit != "resolver" || main.DHCP.RateLimit != "" || main.NTP == nil || main.NTP.RateLimit != "ntp server" {
		t.Errorf("document: dns %q dhcp %q ntp %+v", main.DNS.RateLimit, main.DHCP.RateLimit, main.NTP)
	}
	env.patch("instance=main", map[string]any{"dhcp-rate-limit": true})
	if limitOf("dhcp") != "dhcp server" {
		t.Errorf("dhcp server rate limit not made again: %q", limitOf("dhcp"))
	}
}
