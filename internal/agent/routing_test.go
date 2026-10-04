// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"net/netip"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

func TestParseIPRoute(t *testing.T) {
	data := `[{"dst":"default","gateway":"192.0.2.1","dev":"wan0","protocol":"dhcp","metric":100,"flags":[]},
{"dst":"192.0.2.0/24","dev":"wan0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.10","flags":[]},
{"type":"unreachable","dst":"10.9.0.0/16","table":"100","protocol":"99","flags":[]},
{"dst":"10.8.0.0/16","protocol":"99","flags":[],"nexthops":[{"gateway":"192.0.2.2","dev":"wan0"},{"gateway":"192.0.2.3","dev":"wan0"}]}]`
	got := parseIPRoute([]byte(data), false)
	if len(got) != 5 {
		t.Fatalf("got %d routes: %+v", len(got), got)
	}
	if r := got[0]; r.Destination != "default" || r.Gateway != "192.0.2.1" || r.Interface != "wan0" ||
		r.Metric != 100 || r.Type != "unicast" || r.Family != "ipv4" || r.Table != "main" {
		t.Errorf("default: %+v", r)
	}
	if r := got[1]; r.Scope != "link" || r.Source != "192.0.2.10" {
		t.Errorf("connected: %+v", r)
	}
	if r := got[2]; r.Type != "unreachable" || r.Interface != "" || r.Table != "100" {
		t.Errorf("unreachable: %+v", r)
	}
	if r := got[4]; r.Destination != "10.8.0.0/16" || r.Gateway != "192.0.2.3" {
		t.Errorf("multipath: %+v", r)
	}
	if parseIPRoute([]byte("garbage"), true) != nil {
		t.Error("garbage parsed")
	}
}

func TestAddressOwners(t *testing.T) {
	doc := fwconfig.SampleDocument().Expand()
	owners := addressOwners(doc)
	if o := owners[netip.MustParseAddr("10.255.0.2")]; o != "guest" {
		t.Errorf("link end 10.255.0.2: %q", o)
	}
	if o := owners[netip.MustParseAddr("10.255.0.1")]; o != "main" {
		t.Errorf("link end 10.255.0.1: %q", o)
	}
}
