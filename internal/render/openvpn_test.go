// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

func TestOpenVPNConf(t *testing.T) {
	doc := fwconfig.SampleDocument()
	exp := doc.Expand()
	in := &exp.Instances[0]
	p := DefaultPaths()

	udp := OpenVPNConf(in, in.Interface("ovpn0"), p)
	for _, want := range []string{
		"dev ovpn0\ndev-type tun\nproto udp6\nport 1194\n",
		"ifconfig-noexec\n",
		"ifconfig 10.8.0.1 255.255.255.0\nifconfig-pool 10.8.0.2 10.8.0.126 255.255.255.128\npush \"route-gateway 10.8.0.1\"\n",
		"ifconfig-ipv6 fd00:8::1/64 fd00:8::\nifconfig-ipv6-pool fd00:8::2/65\n",
		"push \"route 10.8.0.0 255.255.255.0\"\npush \"route-ipv6 fd00:8::/64\"\npush \"route 192.168.1.0 255.255.255.0\"\npush \"route-ipv6 fd00:1::/64\"\n",
		"push \"dhcp-option DNS 10.8.0.1\"\npush \"dhcp-option DOMAIN home.arpa\"\n",
		"explicit-exit-notify 1\n",
		"cert /var/lib/portitor/certificates/main/www/fullchain.pem\nkey /var/lib/portitor/certificates/main/www/privkey.pem\n",
		"verify-client-cert none\nusername-as-common-name\n",
		"management /run/portitor/openvpn/main/udp.sock unix\nmanagement-client-auth\n",
		"<tls-crypt>\n" + fwconfig.SampleTLSCrypt + "</tls-crypt>\n",
	} {
		if !strings.Contains(udp, want) {
			t.Errorf("udp: missing %q in\n%s", want, udp)
		}
	}
	tcp := OpenVPNConf(in, in.Interface("ovt-ovpn0"), p)
	for _, want := range []string{
		"dev ovt-ovpn0\ndev-type tun\nproto tcp6-server\n",
		"ifconfig 10.8.0.129 255.255.255.128\nifconfig-pool 10.8.0.130 10.8.0.254 255.255.255.128\n",
		"ifconfig-ipv6-pool fd00:8::8000:0:0:2/65\n",
		"push \"route 10.8.0.0 255.255.255.0\"\n",
		"management /run/portitor/openvpn/main/tcp.sock unix\n",
	} {
		if !strings.Contains(tcp, want) {
			t.Errorf("tcp: missing %q in\n%s", want, tcp)
		}
	}
	if strings.Contains(tcp, "explicit-exit-notify") {
		t.Errorf("tcp: explicit-exit-notify")
	}

	// The port on the listen interface, both protocols; a rule for the
	// interface (its DNS, its zone) takes the TCP device too.
	nft := Nftables(in, nil, p)
	if !strings.Contains(nft, `iifname "eth0" meta l4proto { tcp, udp } th dport 1194 accept comment "auto: openvpn ovpn0"`) {
		t.Errorf("no openvpn rule in\n%s", grepLines(nft, "1194"))
	}

	b, err := Render(doc, Options{Paths: p})
	if err != nil {
		t.Fatal(err)
	}
	f := p.Files(in)
	for _, path := range []string{f.OpenVPNUDP, f.OpenVPNTCP} {
		file := b.File(path)
		if file == nil || !file.Secret || file.Mode != 0o600 {
			t.Fatalf("%s: %+v", path, file)
		}
	}
	for _, file := range b.Redacted() {
		if strings.Contains(file.Content, "00112233445566778899aabbccddeeff") {
			t.Errorf("%s: tls-crypt key not redacted", file.Path)
		}
	}

	// Full tunnel without IPv6 in it blocks IPv6.
	o := in.Interface("ovpn0")
	o.Addresses = []string{"10.8.0.1/24"}
	o.OpenVPN.RedirectGateway = true
	if c := OpenVPNConf(in, o, p); !strings.Contains(c, "push \"redirect-gateway def1 bypass-dhcp\"\npush \"block-ipv6\"\n") || strings.Contains(c, "ifconfig-ipv6") {
		t.Errorf("redirect:\n%s", c)
	}
}

func grepLines(s, sub string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
