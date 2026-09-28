// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"strings"
	"testing"
)

func TestParseServices(t *testing.T) {
	m := parseServices(strings.NewReader(`# comment
ssh		22/tcp				# SSH Remote Login Protocol
domain		53/tcp
domain		53/udp
http		80/tcp		www		# WorldWideWeb HTTP
www-alt		80/tcp
broken		x/tcp
nolproto	99
`))
	want := map[servicePort]string{
		{"tcp", 22}: "ssh",
		{"tcp", 53}: "domain",
		{"udp", 53}: "domain",
		{"tcp", 80}: "http",
	}
	if len(m) != len(want) {
		t.Fatalf("got %v, want %v", m, want)
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%v: got %q, want %q", k, m[k], v)
		}
	}
}
