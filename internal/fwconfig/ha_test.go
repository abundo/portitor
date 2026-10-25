// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"strings"
	"testing"
)

func TestValidateHA(t *testing.T) {
	secret, fp := strings.Repeat("s", 43), strings.Repeat("ab", 32)
	ok := func() *HA {
		return &HA{Node: HAPrimary, Peer: "https://192.0.2.2:8443", PeerFingerprint: fp, Secret: secret,
			WitnessSecret: strings.Repeat("w", 43), PeerConfig: "https://192.0.2.2:8444", PeerConfigFingerprint: fp, Epoch: 2}
	}
	doc := SampleDocument()
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
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := SampleDocument()
			doc.HA = ok()
			c.mutate(doc.HA)
			err := doc.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
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
	doc.HA.Peer, doc.HA.PeerConfig = "https://peer.example:8443", ""
	if in := doc.Expand().Instances[0]; in.HAConfig != nil {
		t.Errorf("peer by name: %+v", in.HAConfig)
	}
}
