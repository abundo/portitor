// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

// withHAConfig makes the document an HA host's whose portitor-config, on
// 8444, the peer reaches.
func withHAConfig(doc fwconfig.Document) fwconfig.Document {
	doc = fwconfig.SampleHA(doc)
	doc.HA.Peer, doc.HA.PeerConfig, doc.HA.PeerConfigFingerprint, doc.HA.ConfigPort = "https://192.168.1.2:8443", "https://[2001:db8::2]:8444", doc.HA.PeerFingerprint, 8444
	doc.HA.AgentPort = 8443
	return doc
}

func TestHAConfigRule(t *testing.T) {
	b, err := Render(withHAConfig(fwconfig.SampleDocument()), Options{Paths: DefaultPaths(), Units: DefaultUnits()})
	if err != nil {
		t.Fatal(err)
	}
	nft := mustFile(t, b, "/etc/nftables.d/portitor.nft")
	for _, want := range []string{
		"ip saddr @AUTO_portitor_config_peer_v4 tcp dport 8444 accept",
		"ip6 saddr @AUTO_portitor_config_peer_v6 tcp dport 8444 accept",
		"ip saddr @AUTO_portitor_agent_peer_v4 tcp dport 8443 accept",
		"192.168.1.2", "2001:db8::2",
		`ip6 saddr @AUTO_portitor_agent_peer_link_v6 iifname "ha0" tcp dport 8443 accept`,
		`oifname "ha0" ip6 daddr fe80::2 tcp dport 8443 accept`,
		`ip6 saddr @AUTO_conntrack_sync_v6 iifname "ha0" udp dport 3780 accept`,
		"ip daddr 192.168.1.2 tcp dport 8444 accept",
		"ip6 daddr 2001:db8::2 tcp dport 8444 accept",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("missing %q:\n%s", want, nft)
		}
	}
	ct := mustFile(t, b, "/etc/conntrackd/conntrackd.conf")
	for _, want := range []string{"IPv6_address fe80::1\n", "IPv6_Destination_Address fe80::2\n", "Interface ha0\n"} {
		if !strings.Contains(ct, want) {
			t.Errorf("conntrackd.conf: missing %q:\n%s", want, ct)
		}
	}
	if guest := mustFile(t, b, "/etc/portitor/instances/guest/nftables.nft"); strings.Contains(guest, HAConfigService) {
		t.Error("the portitor-config peer rule belongs to the default instance only")
	}
}
