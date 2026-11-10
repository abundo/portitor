// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package wgimport

import (
	"reflect"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/wgkeys"
)

func TestParse(t *testing.T) {
	priv, pub, _ := wgkeys.Generate()
	_, peerPub, _ := wgkeys.Generate()
	psk, _, _ := wgkeys.Generate()
	conf := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.99.0.1/24, fd00:99::1\nListenPort = 51821\nMTU = 1380\nDNS = 1.1.1.1\nPostUp = true\n\n" +
		"# phone\n[Peer]\nPublicKey = " + peerPub + "\nPresharedKey = " + psk + "\nAllowedIPs = 10.99.0.2/32, fd00:99::2/128\nEndpoint = vpn.example.com:51820\nPersistentKeepalive = 25\nFoo = bar\n\n" +
		"# Name = laptop\n[Peer]\nPublicKey = " + peerPub + "\nPersistentKeepalive = off\n\n" +
		"[Peer]\nPublicKey = " + peerPub + "\n"
	got, err := Parse(conf)
	if err != nil {
		t.Fatal(err)
	}
	want := &Config{
		PrivateKey: priv, PublicKey: pub, ListenPort: 51821, MTU: 1380,
		Addresses: []string{"10.99.0.1/24", "fd00:99::1/128"},
		Peers: []Peer{
			{Name: "phone", PublicKey: peerPub, PresharedKey: psk, AllowedIPs: []string{"10.99.0.2/32", "fd00:99::2/128"}, Endpoint: "vpn.example.com:51820", Keepalive: 25},
			{Name: "laptop", PublicKey: peerPub},
			{Name: "peer3", PublicKey: peerPub},
		},
		Warnings: []string{"[Interface] dns is not imported", "[Interface] postup is not imported", "[Peer] foo is not imported"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseErrors(t *testing.T) {
	priv, _, _ := wgkeys.Generate()
	_, peerPub, _ := wgkeys.Generate()
	for _, c := range []struct{ conf, err string }{
		{"[Interface]\nPrivateKey = nope\n", "not a WireGuard key"},
		{"[Interface]\nListenPort = 1\n", "no [Interface] PrivateKey"},
		{"PrivateKey = " + priv + "\n", "line 1: a key outside"},
		{"[Interface]\nPrivateKey = " + priv + "\n[Wat]\n", "line 3: unknown section"},
		{"[Interface]\nPrivateKey = " + priv + "\nListenPort\n", "line 3: expected key = value"},
		{"[Interface]\nPrivateKey = " + priv + "\nListenPort = x\n", "line 3: x is not a number"},
		{"[Interface]\nPrivateKey = " + priv + "\n[Peer]\nAllowedIPs = 10.0.0.1/32\n", "peer1 has no PublicKey"},
		{"[Interface]\nPrivateKey = " + priv + "\n[Peer]\nPublicKey = " + peerPub + "\nPresharedKey = x\n", "PresharedKey is not"},
	} {
		if _, err := Parse(c.conf); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%q: %v, want %q", c.conf, err, c.err)
		}
	}
}
