// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"strings"
	"testing"
)

func TestGate(t *testing.T) {
	closed := Gate([]string{"ens18", "ens22"}, false)
	for _, want := range []string{
		"delete table netdev portitor_gate\n",
		`type filter hook ingress devices = { "ens18", "ens22" } priority -500; policy drop;`,
		`type filter hook egress devices = { "ens18", "ens22" } priority -500; policy drop;`,
		"ether type 0x88cc accept",
	} {
		if !strings.Contains(closed, want) {
			t.Errorf("closed gate lacks %q:\n%s", want, closed)
		}
	}
	if open := Gate([]string{"ens18"}, true); !strings.Contains(open, "policy accept;") || strings.Contains(open, "policy drop;") {
		t.Errorf("open gate:\n%s", open)
	}
	// A namespace with no physical traffic interface has no gate: a
	// base chain without devices is refused.
	if empty := Gate(nil, false); strings.Contains(empty, "chain") {
		t.Errorf("empty gate:\n%s", empty)
	}
}
