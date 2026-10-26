// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

// withDHCPHA puts the sample's DHCP on an HA pair, as its standby.
func withDHCPHA(doc fwconfig.Document) fwconfig.Document {
	doc.Instances[0].DHCP.HA = &fwconfig.DHCPHA{Role: fwconfig.DHCPHAStandby, Interface: "eth1", This: "192.168.1.2", Peer: "192.168.1.1"}
	return doc
}

// withHAConfig makes the document an HA host's whose portitor-config, on
// 8444, the peer reaches.
func withHAConfig(doc fwconfig.Document) fwconfig.Document {
	fp := strings.Repeat("ab", 32)
	doc.HA = &fwconfig.HA{Node: fwconfig.HAPrimary, Peer: "https://192.168.1.2:8443", PeerFingerprint: fp, Secret: strings.Repeat("s", 43),
		PeerConfig: "https://[2001:db8::2]:8444", PeerConfigFingerprint: fp, ConfigPort: 8444}
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
		"192.168.1.2", "2001:db8::2",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("missing %q:\n%s", want, nft)
		}
	}
	if guest := mustFile(t, b, "/etc/portitor/instances/guest/nftables.nft"); strings.Contains(guest, HAConfigService) {
		t.Error("the portitor-config peer rule belongs to the default instance only")
	}
}

func TestKeaHA(t *testing.T) {
	b, err := Render(withDHCPHA(fwconfig.SampleDocument()), Options{Paths: DefaultPaths(), Units: DefaultUnits()})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		file, port string
	}{{"/etc/kea/kea-dhcp4.conf", ":8001/"}, {"/etc/kea/kea-dhcp6.conf", ":8002/"}} {
		text := mustFile(t, b, c.file)
		var conf map[string]map[string]any
		if err := json.Unmarshal([]byte(text[strings.Index(text, "{"):]), &conf); err != nil {
			t.Fatalf("%s: %v\n%s", c.file, err, text)
		}
		for _, d := range conf {
			hooks, _ := json.Marshal(d["hooks-libraries"])
			h := string(hooks)
			if !strings.Contains(h, "libdhcp_ha.so") || !strings.Contains(h, "libdhcp_lease_cmds.so") ||
				!strings.Contains(h, `"this-server-name":"standby"`) || !strings.Contains(h, `"hot-standby"`) ||
				!strings.Contains(h, "http://192.168.1.1"+c.port) || !strings.Contains(h, "http://192.168.1.2"+c.port) {
				t.Errorf("%s hooks: %s", c.file, h)
			}
		}
	}
	// Only the peer gets in, on both ports, from one set.
	nft := mustFile(t, b, "/etc/nftables.d/portitor.nft")
	if strings.Count(nft, "set AUTO_dhcp_ha_v4") != 1 || !strings.Contains(nft, "192.168.1.1") ||
		!strings.Contains(nft, "tcp dport 8001") || !strings.Contains(nft, "tcp dport 8002") {
		t.Errorf("ruleset:\n%s", nft)
	}
	// Without HA, no hooks.
	b, _ = Render(fwconfig.SampleDocument(), Options{Paths: DefaultPaths(), Units: DefaultUnits()})
	if strings.Contains(mustFile(t, b, "/etc/kea/kea-dhcp4.conf"), "hooks-libraries") {
		t.Error("hooks without HA")
	}
}

// With DHCPv6 subnets alone no DHCPv4 server runs, so none calls its HA
// peer on a port the ruleset keeps closed.
func TestKeaHAIPv6Only(t *testing.T) {
	doc := withDHCPHA(fwconfig.SampleDocument())
	in := &doc.Instances[0]
	in.DHCP.Subnets = slices.DeleteFunc(in.DHCP.Subnets, func(s fwconfig.DHCPSubnet) bool { return fwconfig.AddrFamily(s.Prefix) == "ipv4" })
	b, err := Render(doc, Options{Paths: DefaultPaths(), Units: DefaultUnits()})
	if err != nil {
		t.Fatal(err)
	}
	if b.File("/etc/kea/kea-dhcp4.conf") != nil {
		t.Error("kea-dhcp4.conf without DHCPv4 subnets")
	}
	nft := mustFile(t, b, "/etc/nftables.d/portitor.nft")
	if strings.Contains(nft, "tcp dport 8001") || !strings.Contains(nft, "tcp dport 8002") {
		t.Errorf("ruleset:\n%s", nft)
	}
}
