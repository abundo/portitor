// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"strings"
	"testing"
)

func TestValidateISIS(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(s *ISIS)
		want   string
	}{
		{"bad net", func(s *ISIS) { s.NET = "49.0001.0102.5500.0002" }, "NET"},
		{"net upper case", func(s *ISIS) { s.NET = "49.000A.0102.5500.0002.00" }, "NET"},
		{"net nsel", func(s *ISIS) { s.NET = "49.0001.0102.5500.0002.01" }, "NET"},
		{"bad level", func(s *ISIS) { s.Level = "level-3" }, "level must be"},
		{"bad metric style", func(s *ISIS) { s.MetricStyle = "huge" }, "metric style must be"},
		{"narrow with topology", func(s *ISIS) { s.MetricStyle = ISISMetricNarrow }, "IPv6 topology needs wide metrics"},
		{"narrow metric", func(s *ISIS) { s.MetricStyle, s.IPv6Topology = ISISMetricNarrow, false }, "metric out of range (1-63)"},
		{"unknown interface", func(s *ISIS) { s.Interfaces[0].Name = "eth9" }, "interface eth9: unknown interface"},
		{"interface twice", func(s *ISIS) { s.Interfaces[1].Name = "lk-main" }, "interface lk-main listed twice"},
		{"no family", func(s *ISIS) { s.Interfaces[1].IPv4 = false }, "IPv4, IPv6 or both"},
		{"bad circuit type", func(s *ISIS) { s.Interfaces[1].CircuitType = "level-2" }, "circuit type must be"},
		{"priority", func(s *ISIS) { s.Interfaces[1].Priority = ptr(128) }, "priority out of range"},
		{"multiplier", func(s *ISIS) { s.Interfaces[0].HelloMultiplier = 1 }, "hello multiplier"},
		{"redistribute source", func(s *ISIS) { s.Redistribute[0].Source = "rip" }, "source must be"},
		{"redistribute level", func(s *ISIS) { s.Redistribute[0].Level = ISISLevel12 }, "level must be level-1, level-2"},
		{"redistribute twice", func(s *ISIS) { s.Redistribute[1] = s.Redistribute[0] }, "listed twice"},
		{"redistribute family", func(s *ISIS) { s.Redistribute[0].Family = "ip" }, "family must be"},
		{"unknown route map", func(s *ISIS) { s.Redistribute[0].RouteMap = "nope" }, `unknown route map "nope"`},
		{"default twice", func(s *ISIS) { s.DefaultOriginate = append(s.DefaultOriginate, s.DefaultOriginate[0]) }, "listed twice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := SampleDocument()
			c.mutate(doc.Instance("guest").ISIS)
			err := doc.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}

	// On a tunnel without layer 2, only passive.
	doc := SampleDocument()
	in := doc.Instance("guest")
	in.Interface("eth2").Kind = KindWireGuard
	in.ISIS.Interfaces[1].Passive = false
	if err := doc.Validate(); err == nil || !strings.Contains(err.Error(), "only passive") {
		t.Fatalf("got %v", err)
	}
}

func TestParseISISNet(t *testing.T) {
	for in, want := range map[string]string{
		"49.0001.1921.6800.1001.00":                "49.0001.1921.6800.1001.00",
		" 49.0001.ABCD.6800.1001.00":               "49.0001.abcd.6800.1001.00",
		"49.1921.6800.1001.00":                     "49.1921.6800.1001.00",
		"39.0001.0002.0003.0004.1921.6800.1001.00": "39.0001.0002.0003.0004.1921.6800.1001.00",
	} {
		if got, ok := ParseISISNet(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "49.0001.1921.6800.1001", "49.0001.1921.6800.1001.0", "4.0001.1921.6800.1001.00", "49.0001.1921.6800.100g.00"} {
		if _, ok := ParseISISNet(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}
