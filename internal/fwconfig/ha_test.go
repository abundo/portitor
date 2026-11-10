// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestValidateHA(t *testing.T) {
	secret, fp := strings.Repeat("s", 43), strings.Repeat("ab", 32)
	ok := func() *HA {
		return &HA{Node: HAPrimary, Peer: "https://192.0.2.2:8443", PeerFingerprint: fp, PeerLink: "https://192.0.2.130:8443", Secret: secret,
			WitnessSecret: strings.Repeat("w", 43), PeerConfig: "https://192.0.2.2:8444", PeerConfigFingerprint: fp, Epoch: 2}
	}
	doc := SampleHA(SampleDocument())
	doc.HA = ok()
	if err := doc.Validate(); err != nil {
		t.Fatalf("valid HA: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(h *HA)
		want   string
	}{
		{"witness secret short", func(h *HA) { h.WitnessSecret = "short" }, "witness secret must be"},
		{"witness secret is the pair's", func(h *HA) { h.WitnessSecret = h.Secret }, "not the pair's secret"},
		{"peer config not https", func(h *HA) { h.PeerConfig = "http://192.0.2.2:8444" }, "peer config must be"},
		{"peer config with a path", func(h *HA) { h.PeerConfig = "https://192.0.2.2:8444/x" }, "peer config must be"},
		{"peer config without its pin", func(h *HA) { h.PeerConfigFingerprint = "" }, "peer config fingerprint"},
		{"negative epoch", func(h *HA) { h.Epoch = -1 }, "epoch must not be negative"},
		{"config port too high", func(h *HA) { h.ConfigPort = 70000 }, "config port must be"},
		{"agent port too high", func(h *HA) { h.AgentPort = 70000 }, "agent port must be"},
		{"no HA link path", func(h *HA) { h.PeerLink = "" }, "peer link must be"},
		{"one path", func(h *HA) { h.PeerLink = h.Peer }, "two paths"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := SampleHA(SampleDocument())
			doc.HA = ok()
			c.mutate(doc.HA)
			err := doc.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}

func TestValidateHAInterfaces(t *testing.T) {
	iface := func(in *Instance, role string) *Interface { return in.HAInterface(role) }
	cases := []struct {
		name   string
		mutate func(d *Document)
		want   string
	}{
		{"unknown role", func(d *Document) { iface(&d.Instances[0], HARoleLink).HARole = "other" }, "HA role must be"},
		{"no HA link", func(d *Document) { iface(&d.Instances[0], HARoleLink).HARole = "" }, "with the role ha_link"},
		{"no management", func(d *Document) {
			m := iface(&d.Instances[0], HARoleManagement)
			m.HARole, m.HAGateway = "", ""
		}, "with the role management"},
		{"two HA links", func(d *Document) {
			m := iface(&d.Instances[0], HARoleManagement)
			m.HARole, m.HAGateway = HARoleLink, ""
		}, "only one interface"},
		{"role on a VLAN", func(d *Document) {
			m := iface(&d.Instances[0], HARoleLink)
			m.Kind, m.Parent, m.VLANID = KindVLAN, "eth0", 40
		}, "needs a physical interface"},
		{"role off the host", func(d *Document) {
			d.Instances[1].Interfaces[0].HARole = HARoleLink
		}, "default instance"},
		{"disabled", func(d *Document) { iface(&d.Instances[0], HARoleLink).Enabled = false }, "must be enabled"},
		{"no address", func(d *Document) { iface(&d.Instances[0], HARoleLink).Addresses = nil }, "needs a static address"},
		{"no gateway", func(d *Document) { iface(&d.Instances[0], HARoleManagement).HAGateway = "" }, "needs a gateway"},
		{"gateway elsewhere", func(d *Document) { iface(&d.Instances[0], HARoleManagement).HAGateway = "198.51.100.1" }, "is not on the interface"},
		{"gateway is its own address", func(d *Document) { iface(&d.Instances[0], HARoleManagement).HAGateway = "192.0.2.1" }, "is not on the interface"},
		{"a gateway on the HA link", func(d *Document) { iface(&d.Instances[0], HARoleLink).HAGateway = "192.0.2.130" }, "only the management interface"},
		{"the peer as a link's gateway", func(d *Document) { iface(&d.Instances[0], HARoleLink).HAGatewayPeer = true }, "only the management interface has the peer"},
		{"a gateway on a traffic interface", func(d *Document) { d.Instances[0].Interfaces[0].HAGateway = "192.0.2.130" }, "only the management interface"},
		{"VRRP on a pair", func(d *Document) { d.Instances[1].VRRP = SampleDocument().Instances[1].VRRP }, "VRRP is not used"},
		{"multicast mac", func(d *Document) { d.Instances[0].Interfaces[0].MAC = "03:11:22:33:44:55" }, "locally administered"},
		{"universal mac", func(d *Document) { d.Instances[0].Interfaces[0].MAC = "bc:24:11:33:44:55" }, "locally administered"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := SampleHA(SampleDocument())
			doc.Instances = slices.Clone(doc.Instances)
			for i := range doc.Instances {
				doc.Instances[i].Interfaces = slices.Clone(doc.Instances[i].Interfaces)
			}
			c.mutate(&doc)
			err := doc.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}

func TestGateDevices(t *testing.T) {
	in := Instance{Interfaces: []Interface{
		{Name: "wan", Kind: KindPhysical},
		{Name: "lan", Kind: KindPhysical},
		{Name: "lan.10", Kind: KindVLAN, Parent: "lan"},
		{Name: "wg0", Kind: KindWireGuard},
		{Name: "ha0", Kind: KindPhysical, HARole: HARoleLink},
		{Name: "mgmt0", Kind: KindPhysical, HARole: HARoleManagement},
	}}
	if got := in.GateDevices(); !slices.Equal(got, []string{"wan", "lan"}) {
		t.Errorf("got %v", got)
	}
}

func TestHABlackholes(t *testing.T) {
	in := Instance{Interfaces: []Interface{
		{Name: "wan", Kind: KindPhysical, Enabled: true},
		{Name: "lan", Kind: KindPhysical, Enabled: true, Addresses: []string{"192.0.2.1/24", "2001:db8::1/64"}},
		{Name: "lan.10", Kind: KindVLAN, Enabled: true, Parent: "lan", Addresses: []string{"198.51.100.1/24"}, VRF: "red"},
		{Name: "lo1", Kind: KindLoopback, Enabled: true, Addresses: []string{"203.0.113.1/32"}},
		{Name: "off", Kind: KindPhysical, Addresses: []string{"203.0.113.1/24"}},
		{Name: "ha0", Kind: KindPhysical, Enabled: true, HARole: HARoleLink, Addresses: []string{"fe80::1/64"}},
	}}
	var got []string
	for _, r := range in.HABlackholes() {
		if !r.Blackhole {
			t.Errorf("%+v", r)
		}
		got = append(got, r.Destination+" "+r.VRF)
	}
	if !slices.Equal(got, []string{"192.0.2.0/24 ", "2001:db8::/64 ", "198.51.100.0/24 red"}) {
		t.Errorf("got %q", got)
	}
	// Off a pair there is no gate, and no such route.
	if r := (&Instance{Interfaces: []Interface{{Name: "tun", Kind: KindWireGuard}}}).HABlackholes(); r != nil {
		t.Errorf("%+v", r)
	}
}

func TestDeriveHAMAC(t *testing.T) {
	a, b := DeriveHAMAC("pair", "lan"), DeriveHAMAC("pair", "wan")
	if !haMACRe.MatchString(a) || !haMACRe.MatchString(b) || a == b {
		t.Errorf("%s %s", a, b)
	}
	if a != DeriveHAMAC("pair", "lan") || a == DeriveHAMAC("other", "lan") {
		t.Error("it must follow the pair and the name alone")
	}
}

func TestHAConfigAccess(t *testing.T) {
	doc := SampleDocument()
	doc.HA = &HA{Node: HASecondary, Peer: "https://192.0.2.1:8443", PeerConfig: "https://[2001:db8::1]:8444"}
	if in := doc.Expand().Instances[0]; in.HAConfig != nil {
		t.Fatalf("no config port: %+v", in.HAConfig)
	}
	doc.HA.ConfigPort = 8444
	exp := doc.Expand()
	for _, in := range exp.Instances {
		if !in.Default {
			if in.HAConfig != nil {
				t.Errorf("%s: %+v", in.Name, in.HAConfig)
			}
			continue
		}
		if h := in.HAConfig; h == nil || h.Port != 8444 || strings.Join(h.From, " ") != "192.0.2.1 2001:db8::1" {
			t.Errorf("default: %+v", h)
		}
	}
	// The HA link's peer is link-local, on its interface: the agent's
	// port alone, there.
	doc.HA.AgentPort, doc.HA.PeerLink = 8443, "https://[fe80::1%25ha0]:8443"
	if h := doc.Expand().Instances[0].HAConfig; h == nil || h.Link != "ha0" || h.LinkPeer != "fe80::1" || slices.Contains(h.From, "fe80::1") {
		t.Errorf("link: %+v", h)
	}
	doc.HA.Peer, doc.HA.PeerConfig, doc.HA.PeerLink = "https://peer.example:8443", "", ""
	if in := doc.Expand().Instances[0]; in.HAConfig != nil {
		t.Errorf("peer by name: %+v", in.HAConfig)
	}
}

func TestHALinkAddress(t *testing.T) {
	for _, c := range []struct {
		node string
		id   uint32
		want string
	}{{HAPrimary, 0, "fe80::1"}, {HASecondary, 0, "fe80::2"}, {HAPrimary, 7, "fe80::7:1"}, {HASecondary, 0x12345, "fe80::1:2345:2"}} {
		a := HALinkAddress(c.node, c.id)
		if a.String() != c.want || !IsHALinkAddress(a) {
			t.Errorf("%s %d: %s", c.node, c.id, a)
		}
	}
	for _, s := range []string{"fe80::be24:11ff:feca:4735", "fe80::3", "fd00::1", "169.254.1.1", "fe80::1:0:0:0:1", "fe80::1:0:1:0:1"} {
		if IsHALinkAddress(netip.MustParseAddr(s)) {
			t.Errorf("%s is not one", s)
		}
	}
}
