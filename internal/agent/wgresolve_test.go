// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"testing"
	"time"

	"github.com/abundo/portitor/internal/fwconfig"
)

func TestPlanReresolve(t *testing.T) {
	now := time.Unix(1700000200, 0)
	dump := parseWGDump(prefixDump("wg0", "PRIV\tPUB\t51820\toff\n"+
		"FRESH\t(none)\t203.0.113.9:51820\t10.99.0.2/32\t1700000100\t0\t0\t25\n"+
		"STALE\t(none)\t203.0.113.10:51820\t10.99.0.3/32\t1700000000\t0\t0\t25\n"+
		"NEVER\t(none)\t(none)\t10.99.0.4/32\t0\t0\t0\t25\n"+
		"LITERAL\t(none)\t203.0.113.11:51820\t10.99.0.5/32\t0\t0\t0\t25\n"))
	peers := []fwconfig.WGPeer{
		{PublicKey: "FRESH", Endpoint: "a.example.org:51820"},
		{PublicKey: "STALE", Endpoint: "b.example.org:51820"},
		{PublicKey: "NEVER", Endpoint: "c.example.org:51820"},
		{PublicKey: "LITERAL", Endpoint: "203.0.113.11:51820"},
		{PublicKey: "NOEP"},
		{PublicKey: "GONE", Endpoint: "d.example.org:51820"}, // not in the dump
	}
	equal(t, planReresolve("fw-x", "wg0", peers, dump, now),
		"fw-x wg set wg0 peer STALE endpoint b.example.org:51820",
		"fw-x wg set wg0 peer NEVER endpoint c.example.org:51820")
}

func TestWithoutNamedEndpoints(t *testing.T) {
	in := "[Peer]\nPublicKey = a\nEndpoint = vpn.example.com:51820\n\n[Peer]\nPublicKey = b\nEndpoint = 192.0.2.1:51820\n\n[Peer]\nPublicKey = c\nEndpoint = [2001:db8::1]:51820\n"
	want := "[Peer]\nPublicKey = a\n\n[Peer]\nPublicKey = b\nEndpoint = 192.0.2.1:51820\n\n[Peer]\nPublicKey = c\nEndpoint = [2001:db8::1]:51820\n"
	if got := withoutNamedEndpoints(in); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}
