// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"strconv"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

// withSynProxy adds a forward rule with a SYN proxy, to a server of each
// IP version, to the first instance, and numbers the rules.
func withSynProxy(doc fwconfig.Document) fwconfig.Document {
	in := &doc.Instances[0]
	in.Rules = append(in.Rules, fwconfig.Rule{
		Chain: fwconfig.ChainForward, InInterfaces: []string{"wan"},
		DstAddrs: []string{"192.168.1.10", "2001:db8::10"},
		Services: []fwconfig.ServiceMatch{{Protocol: fwconfig.ProtoTCP, DstPorts: "443"}, {Protocol: fwconfig.ProtoUDP, DstPorts: "443"}},
		Action:   fwconfig.ActionAccept, Log: true,
		SynProxy: &fwconfig.SynProxy{WScale: 7}, Description: "web server",
	})
	return withRuleIDs(doc)
}

func TestNftablesSynProxy(t *testing.T) {
	doc := withSynProxy(fwconfig.SampleDocument())
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	b, err := Render(doc, Options{Paths: DefaultPaths(), Units: DefaultUnits()})
	if err != nil {
		t.Fatal(err)
	}
	nft := mustFile(t, b, "/etc/nftables.d/portitor.nft")
	rules := doc.Instances[0].Rules
	id := rules[len(rules)-1].ID
	n := 0
	for _, r := range rules {
		if r.Kind != fwconfig.RuleKindComment && r.Chain != "" {
			n++
		}
	}
	name := "rule " + strconv.Itoa(n)
	for _, want := range []string{
		"chain " + SynProxyChain + " {\n\t\ttype filter hook prerouting priority raw; policy accept;\n",
		`iifname "eth0" ip daddr 192.168.1.10 tcp dport 443 ` + synOnly + ` fib daddr type != local notrack comment "` + name + `: syn proxy"`,
		`iifname "eth0" ip6 daddr 2001:db8::10 tcp dport 443 ` + synOnly + ` fib daddr type != local notrack`,
		`iifname "eth0" ip daddr 192.168.1.10 tcp dport 443 ct state invalid,untracked synproxy mss 1460 wscale 7 timestamp sack-perm`,
		`iifname "eth0" ip6 daddr 2001:db8::10 tcp dport 443 ct state invalid,untracked synproxy mss 1440 wscale 7 timestamp sack-perm`,
		`fib saddr type != local ct state invalid,untracked ip saddr 192.168.1.10 tcp sport 443 accept comment "` + name + `: syn proxy cookie"`,
		`fib saddr type != local ct state new ip daddr 192.168.1.10 tcp dport 443 ` + synOnly + ` counter name "` + RuleCounter(id, CounterOrig) + `" log prefix "forward ` + name + ` accept"`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("missing %q in\n%s", want, nft)
		}
	}
	// In output too: the SYN cookie is invalid to conntrack.
	out := nft[strings.Index(nft, "chain output {"):]
	if p, d := strings.Index(out, "syn proxy cookie"), strings.Index(out, "ct state invalid counter"); p < 0 || p > d {
		t.Errorf("syn proxy cookie accept not before the invalid drop:\n%s", out)
	}
	// UDP 443 is the rule's alone.
	if strings.Contains(nft, "udp dport 443 ct state invalid,untracked") || strings.Contains(nft, "udp dport 443 tcp flags") {
		t.Errorf("syn proxy on UDP:\n%s", nft)
	}
	if !strings.Contains(nft, `iifname "eth0" ip daddr 192.168.1.10 udp dport 443 counter name`) {
		t.Errorf("the rule's UDP accept missing:\n%s", nft)
	}
	// In forward, the synproxy comes before the invalid drop.
	fwd := nft[strings.Index(nft, "chain forward {"):]
	if p, d := strings.Index(fwd, "synproxy mss"), strings.Index(fwd, "ct state invalid counter"); p < 0 || p > d {
		t.Errorf("synproxy not before the invalid drop:\n%s", fwd)
	}

	// Without one, nothing of it.
	b, err = Render(fwconfig.SampleDocument(), Options{Paths: DefaultPaths(), Units: DefaultUnits()})
	if err != nil {
		t.Fatal(err)
	}
	if nft := mustFile(t, b, "/etc/nftables.d/portitor.nft"); strings.Contains(nft, "synproxy") || strings.Contains(nft, SynProxyChain) {
		t.Errorf("syn proxy without a rule having one:\n%s", nft)
	}
}
