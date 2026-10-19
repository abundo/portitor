// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

func TestNftablesPolicyRoutes(t *testing.T) {
	doc := fwconfig.SampleDocument()
	in := &doc.Instances[0]
	nft := Nftables(in, nil, DefaultPaths())
	for _, want := range []string{
		// After the NAT64 chain, whose marks it leaves alone; an exception
		// first, then the IPv4 gateway's (its IPv4 alone), then the
		// interface's (both versions).
		"\tchain prerouting_policy {\n\t\ttype filter hook prerouting priority mangle + 1; policy accept;\n" +
			"\t\tmeta mark != 0 return\n" +
			"\t\tiifname { \"eth1\", \"n64-eth1\" } ip daddr 192.168.50.0/24 counter accept comment \"policy route 1: office: main table\"\n" +
			"\t\tiifname \"eth1.20\" meta nfproto ipv4 tcp dport { 80, 443 } counter meta mark set 0x5101 accept comment \"policy route 2: IoT web by the LAN router\"\n" +
			"\t\tip saddr @A_admins_v4 counter meta mark set 0x5102 accept comment \"policy route 3: admins through the VPN\"\n" +
			"\t\tip6 saddr @A_admins_v6 counter meta mark set 0x5102 accept comment \"policy route 3: admins through the VPN\"\n\t}\n",
		// Routed, the packet loses the mark before the shapers mark it.
		"\t\tmeta mark & 0xffffff00 == 0x5100 meta mark set 0 comment \"policy routes\"\n",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("missing:\n%s\nin:\n%s", want, nft)
		}
	}

	// Exceptions alone mark nothing.
	in.PolicyRoutes = in.PolicyRoutes[:1]
	if nft := Nftables(in, nil, DefaultPaths()); strings.Contains(nft, "meta mark set 0x51") || strings.Contains(nft, `"policy routes"`) {
		t.Errorf("exceptions only:\n%s", nft)
	}
	in.PolicyRoutes = nil
	if nft := Nftables(in, nil, DefaultPaths()); strings.Contains(nft, "policy_") || strings.Contains(nft, "policy route") {
		t.Errorf("no policy routes:\n%s", nft)
	}
}
