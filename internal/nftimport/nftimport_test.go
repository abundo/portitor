// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package nftimport

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/models"
)

func load(t *testing.T, opt Options) *Result {
	t.Helper()
	js, err := os.ReadFile("testdata/sample.json")
	if err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile("testdata/sample.txt")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Import(js, string(text), opt)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

var opt = Options{
	Interfaces: map[string]bool{"wan": true, "lan": true},
	Rename:     map[string]string{"eth0": "wan", "eth1": "lan"},
}

func TestImport(t *testing.T) {
	res := load(t, opt)
	type rule struct {
		chain, in, out, src, dst, services, action string
		log                                        bool
	}
	var got []rule
	for _, r := range res.Rules {
		got = append(got, rule{r.Chain, strings.Join(r.InInterfaces, ","), strings.Join(r.OutInterfaces, ","),
			strings.Join(r.SrcAddrs, ","), strings.Join(r.DstAddrs, ","), strings.Join(r.Services, ","), r.Action, r.Log})
	}
	want := []rule{
		{"input", "lan", "", "192.168.1.0/24", "", "ssh,tcp-8000-8080", "accept", false},
		{"input", "", "", "blocked", "", "", "drop", false},
		{"input", "", "", "", "", "dns", "accept", false},
		{"input", "", "", "", "", "ping6,icmp6-nd-neighbor-solicit", "accept", false},
		{"input", "", "", "", "", "http,tcp-443", "accept", true},
		{"forward", "", "wan", "", "2001:db8::/32", "", "reject", false},
		{"forward", "", "", "", "", "", "accept", false}, // policy accept
	}
	if !slices.Equal(got, want) {
		t.Errorf("rules:\n got %v\nwant %v", got, want)
	}
	if res.Rules[0].Description != "admin" || res.Rules[0].Family != "ipv4" {
		t.Errorf("first rule: %+v", res.Rules[0])
	}

	var nat []string
	for _, n := range res.NAT {
		nat = append(nat, fmt.Sprintf("%s %s %s %s %s %s:%d", n.Kind, strings.Join(n.InInterfaces, ","),
			strings.Join(n.OutInterfaces, ","), n.Protocol, n.DstPorts, n.ToAddr, n.ToPort))
	}
	wantNAT := []string{
		"dnat wan  tcp 8443 192.168.1.10:443",
		"dnat wan  udp 5000-5010 192.168.1.11:0",
		"masquerade  wan   :0",
	}
	if !slices.Equal(nat, wantNAT) {
		t.Errorf("nat:\n got %q\nwant %q", nat, wantNAT)
	}

	if len(res.Objects) != 1 || res.Objects[0].Name != "blocked" ||
		!slices.Equal([]string(res.Objects[0].Addresses), []string{"1.2.3.4", "10.9.0.0/16"}) {
		t.Errorf("objects: %+v", res.Objects)
	}
	var svc []string
	for _, s := range res.Services {
		svc = append(svc, s.Name)
	}
	if !slices.Equal(svc, []string{"tcp-8000-8080", "icmp6-nd-neighbor-solicit", "tcp-443"}) {
		t.Errorf("services: %v", svc)
	}

	reasons := map[string]string{}
	builtin := 0
	for _, s := range res.Skipped {
		reasons[s.Text] = s.Reason
		if s.Builtin {
			builtin++
		}
	}
	if builtin != 3 {
		t.Errorf("%d built-in rules skipped, want 3: %+v", builtin, res.Skipped)
	}
	for text, want := range map[string]string{
		`icmp type echo-request limit rate 5/second burst 5 packets accept`: "limit",
		`iifname != "eth0" udp dport 123 reject`:                            "negated",
		`jump custom`:                                                       "jump",
		`tcp dport 9999 accept`:                                             "no hook",
		`oifname "eth2" snat to 203.0.113.5`:                                "eth2",
	} {
		if !strings.Contains(reasons[text], want) {
			t.Errorf("%s: reason %q, want one with %q", text, reasons[text], want)
		}
	}
	if !slices.Equal(res.Interfaces, []string{"eth0", "eth1", "eth2"}) {
		t.Errorf("interfaces: %v", res.Interfaces)
	}
}

// TestImportExisting reuses what exists with the same content and renames
// around what differs.
func TestImportExisting(t *testing.T) {
	o := opt
	o.Objects = map[string][]string{"blocked": {"10.9.0.0/16", "1.2.3.4"}}
	o.Services = map[string]models.Service{
		"tcp-443":       {Type: models.ServiceTypePorts, Ports: models.ServicePortList{{Protocol: "tcp", DstLo: 443}}},
		"tcp-8000-8080": {Type: models.ServiceTypePorts, Ports: models.ServicePortList{{Protocol: "udp", DstLo: 1}}},
	}
	res := load(t, o)
	if len(res.Objects) != 0 || res.Rules[1].SrcAddrs[0] != "blocked" {
		t.Errorf("same set: objects %+v, rule %v", res.Objects, res.Rules[1].SrcAddrs)
	}
	if got := strings.Join(res.Rules[0].Services, ","); got != "ssh,tcp-8000-8080-imported" {
		t.Errorf("services of the first rule: %s", got)
	}
	if got := strings.Join(res.Rules[4].Services, ","); got != "http,tcp-443" {
		t.Errorf("services of the web rule: %s", got)
	}

	o.Objects = map[string][]string{"blocked": {"1.1.1.1"}}
	res = load(t, o)
	if len(res.Objects) != 1 || res.Objects[0].Name != "blocked-imported" || res.Rules[1].SrcAddrs[0] != "blocked-imported" {
		t.Errorf("other set: objects %+v, rule %v", res.Objects, res.Rules[1].SrcAddrs)
	}
}

// TestImportUnmapped leaves out the rules on interfaces with no mapping.
func TestImportUnmapped(t *testing.T) {
	res := load(t, Options{Interfaces: map[string]bool{"wan": true}})
	for _, r := range res.Rules {
		if len(r.InInterfaces)+len(r.OutInterfaces) > 0 {
			t.Errorf("rule on an unmapped interface: %+v", r)
		}
	}
	if len(res.NAT) != 0 {
		t.Errorf("NAT on unmapped interfaces: %+v", res.NAT)
	}
}
