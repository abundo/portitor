// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"slices"
	"testing"
)

func TestAntiLockoutSkipsLoopback(t *testing.T) {
	c := &Config{Listen: "0.0.0.0:8443", AllowFrom: []string{"127.0.0.1/32", "::1/128", "127.0.0.0/8"}}
	if l := c.antiLockout(); l != nil {
		t.Fatalf("loopback only: got %+v, want no rule", l)
	}
	c.AllowFrom = []string{"127.0.0.1/32", "192.0.2.0/24", "::/120"}
	l := c.antiLockout()
	if l == nil || !slices.Equal(l.AllowFrom, []string{"192.0.2.0/24", "::/120"}) {
		t.Fatalf("got %+v, want 192.0.2.0/24 and ::/120", l)
	}
}
