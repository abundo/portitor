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

func TestAntiLockoutConfigPort(t *testing.T) {
	c := &Config{Listen: "192.0.2.1:8443", AllowFrom: []string{"192.0.2.0/24"}}
	if got := c.antiLockout().Ports(); !slices.Equal(got, []int{22, 8443, 8444}) {
		t.Fatalf("default: got %v, want 22, 8443 and 8444", got)
	}
	port := 443
	c.ConfigPort = &port
	if got := c.antiLockout().Ports(); !slices.Equal(got, []int{22, 8443, 443}) {
		t.Fatalf("config_port 443: got %v", got)
	}
	port = 0
	if got := c.antiLockout().Ports(); !slices.Equal(got, []int{22, 8443}) {
		t.Fatalf("config_port 0: got %v, want 22 and 8443", got)
	}
}
