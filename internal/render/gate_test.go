// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"os"
	"strings"
	"testing"
)

func TestGate(t *testing.T) {
	closed := Gate([]string{"ens18", "ens22"}, []string{"ens18", "ens22", "ens22.5"}, false)
	for _, want := range []string{
		"delete table netdev portitor_gate\n",
		`type filter hook ingress devices = { "ens18", "ens22" } priority -500; policy drop;`,
		`type filter hook egress devices = { "ens18", "ens22" } priority -500; policy drop;`,
		"ether type 0x88cc accept",
		"delete table inet portitor_gate\n",
		"delete table arp portitor_gate\n",
		"delete table bridge portitor_gate\n",
		"table inet portitor_gate {\n",
		"type filter hook prerouting priority -500; policy accept;\n\t\tiifname { \"ens18\", \"ens22\", \"ens22.5\" } drop",
		"type filter hook output priority -500; policy accept;\n\t\toifname { \"ens18\", \"ens22\", \"ens22.5\" } drop",
		"type filter hook postrouting priority -500; policy accept;\n\t\toifname { \"ens18\", \"ens22\", \"ens22.5\" } drop",
		"table arp portitor_gate {\n",
		"type filter hook input priority -500; policy accept;\n\t\tiifname",
		"table bridge portitor_gate {\n",
	} {
		if !strings.Contains(closed, want) {
			t.Errorf("closed gate lacks %q:\n%s", want, closed)
		}
	}
	open := Gate([]string{"ens18"}, []string{"ens18"}, true)
	if !strings.Contains(open, "policy accept;") || strings.Contains(open, "policy drop;") || strings.Contains(open, "table inet portitor_gate {") {
		t.Errorf("open gate:\n%s", open)
	}
	for _, fam := range []string{"inet", "arp", "bridge"} {
		if !strings.Contains(open, "delete table "+fam+" portitor_gate\n") {
			t.Errorf("open gate keeps the %s table:\n%s", fam, open)
		}
	}
	// A namespace with no physical traffic interface has no gate: a
	// base chain without devices is refused.
	if empty := Gate(nil, nil, false); strings.Contains(empty, "chain") || !strings.Contains(empty, "delete table inet portitor_gate") {
		t.Errorf("empty gate:\n%s", empty)
	}
	if nd := GateNetdev([]string{"ens18"}, false); strings.Contains(nd, "inet") || !strings.Contains(nd, "policy drop;") {
		t.Errorf("netdev gate:\n%s", nd)
	}
	// dev/lab/gate-test.py loads the rendered gate, not a copy of it.
	if out := os.Getenv("PORTITOR_GATE_OUT"); out != "" {
		if err := os.WriteFile(out, []byte(Gate([]string{"a0"}, []string{"a0", "a0.5"}, false)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
