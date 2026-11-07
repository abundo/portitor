// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcpd

import (
	"bytes"
	"encoding/hex"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var raTestConfig = RAConfig{
	Interface: "lan0",
	Other:     true,
	Prefixes: []RAPrefix{
		{Prefix: netip.MustParsePrefix("fd00:1::/64"), Autonomous: true},
		{Prefix: netip.MustParsePrefix("fd00:2::/56")},
	},
	RDNSS: []netip.Addr{netip.MustParseAddr("fd00:1::1")},
	DNSSL: []string{"home.arpa"},
	NAT64: netip.MustParsePrefix("64:ff9b::/96"),
}

func TestMarshalRA(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	now := time.Unix(1e9, 0)
	got := marshalRA(&raTestConfig, mac, nil, now, false)
	want := unhex(t, `
		86 00 0000  40 40 0708  00000000  00000000
		01 01 020000000001
		03 04 40 c0 00015180 00003840 00000000 fd000001000000000000000000000000
		03 04 38 80 00015180 00003840 00000000 fd000002000000000000000000000000
		19 03 0000 00000708 fd000001000000000000000000000001
		1f 03 0000 00000708 04686f6d650461727061000000000000
		26 02 0708 0064ff9b0000000000000000`)
	if !bytes.Equal(got, want) {
		t.Fatalf("got\n%x\nwant\n%x", got, want)
	}

	// The last one: every lifetime 0; a gone prefix is deprecated with
	// what is left of its deadline, and left out after it.
	c := RAConfig{Interface: "lan0", Managed: true, RDNSS: raTestConfig.RDNSS}
	gone := []gonePrefix{
		{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Until: now.Add(time.Hour)},
		{Prefix: netip.MustParsePrefix("2001:db8:2::/64"), Until: now.Add(-time.Second)},
	}
	got = marshalRA(&c, nil, gone, now, false)
	want = unhex(t, `
		86 00 0000  40 80 0708  00000000  00000000
		03 04 40 c0 00000e10 00000000 00000000 20010db8000100000000000000000000
		19 03 0000 00000708 fd000001000000000000000000000001`)
	if !bytes.Equal(got, want) {
		t.Fatalf("deprecated: got\n%x\nwant\n%x", got, want)
	}
	got = marshalRA(&c, nil, gone, now, true)
	want = unhex(t, `
		86 00 0000  40 80 0000  00000000  00000000
		03 04 40 c0 00000000 00000000 00000000 20010db8000100000000000000000000
		19 03 0000 00000000 fd000001000000000000000000000001`)
	if !bytes.Equal(got, want) {
		t.Fatalf("final: got\n%x\nwant\n%x", got, want)
	}
}

func TestPREF64Lengths(t *testing.T) {
	for p, word := range map[string]string{
		"2001:db8::/32":         "070d",
		"2001:db8:100::/40":     "070c",
		"2001:db8:122::/48":     "070b",
		"2001:db8:122:300::/56": "070a",
		"2001:db8:122:344::/64": "0709",
	} {
		c := RAConfig{NAT64: netip.MustParsePrefix(p)}
		b := marshalRA(&c, nil, nil, time.Now(), false)
		opt := b[16:]
		if opt[0] != optPREF64 || hex.EncodeToString(opt[2:4]) != word {
			t.Errorf("%s: %x", p, opt)
		}
	}
	// A length PREF64 can't say is left out (validation refuses it).
	c := RAConfig{NAT64: netip.MustParsePrefix("2001:db8::/80")}
	if b := marshalRA(&c, nil, nil, time.Now(), false); len(b) != 16 {
		t.Errorf("/80: %x", b)
	}
}

func TestValidRS(t *testing.T) {
	ll := netip.MustParseAddr("fe80::1")
	rs := unhex(t, "85 00 0000 00000000")
	slla := unhex(t, "85 00 0000 00000000 01 01 020000000002")
	for _, tc := range []struct {
		name string
		msg  []byte
		hops int
		src  netip.Addr
		ok   bool
	}{
		{"plain", rs, 255, ll, true},
		{"with link-layer address", slla, 255, ll, true},
		{"unspecified source", rs, 255, netip.IPv6Unspecified(), true},
		{"unspecified with link-layer address", slla, 255, netip.IPv6Unspecified(), false},
		{"forwarded", rs, 254, ll, false},
		{"short", rs[:6], 255, ll, false},
		{"code", unhex(t, "85 01 0000 00000000"), 255, ll, false},
		{"zero-length option", unhex(t, "85 00 0000 00000000 01 00 000000000000"), 255, ll, false},
		{"truncated option", unhex(t, "85 00 0000 00000000 01 02 020000000002"), 255, ll, false},
	} {
		if got := validRS(tc.msg, tc.hops, tc.src); got != tc.ok {
			t.Errorf("%s: %v", tc.name, got)
		}
	}
}

func TestRASched(t *testing.T) {
	t0 := time.Unix(1e9, 0)
	var s raSched
	s.burst(t0)
	// The initial advertisements: at once, then at most 16 s apart, but
	// never less than 3 s.
	at := t0
	for i := range raInitialCount {
		if w := s.wake(); !w.Equal(at) {
			t.Fatalf("initial %d at %v, want %v", i, w.Sub(t0), at.Sub(t0))
		}
		if m, u := s.due(at); !m || u.IsValid() {
			t.Fatalf("initial %d: %v %v", i, m, u)
		}
		s.sent(at, true, raMaxInterval)
		at = at.Add(raMaxInitialInterval)
	}
	at = at.Add(-raMaxInitialInterval)
	if w := s.wake(); !w.Equal(at.Add(raMaxInterval)) {
		t.Fatalf("after the initial ones: %v", w.Sub(at))
	}

	// A solicitation: answered to the solicitor after the delay.
	now := at.Add(time.Minute)
	c1 := netip.MustParseAddr("fe80::c1%lan0")
	s.solicit(now, c1, 200*time.Millisecond)
	if w := s.wake(); !w.Equal(now.Add(200 * time.Millisecond)) {
		t.Fatalf("reply at %v", w.Sub(now))
	}
	if m, u := s.due(now.Add(200 * time.Millisecond)); m || u != netip.MustParseAddr("fe80::c1") {
		t.Fatalf("reply: %v %v", m, u)
	}

	// Two solicitors before the reply: one to all nodes, not sooner than
	// 3 s after the last.
	now = now.Add(time.Minute)
	s.solicit(now, c1, 100*time.Millisecond)
	s.solicit(now, netip.MustParseAddr("fe80::c2"), 400*time.Millisecond)
	if m, u := s.due(now.Add(100 * time.Millisecond)); !m || u.IsValid() {
		t.Fatalf("two: %v %v", m, u)
	}
	s.sent(now.Add(100*time.Millisecond), true, raMaxInterval)
	last := now.Add(100 * time.Millisecond)
	s.solicit(last, netip.IPv6Unspecified(), 0)
	if w := s.wake(); !w.Equal(last.Add(raMinDelay)) {
		t.Fatalf("multicast reply at %v", w.Sub(last))
	}
	if m, _ := s.due(last.Add(time.Second)); m {
		t.Fatal("multicast reply within 3 s")
	}

	// Without a usable source address, again in a second; the initial
	// count waits for one that went out.
	s.burst(last.Add(time.Hour))
	if m, _ := s.due(last.Add(time.Hour)); !m {
		t.Fatal("burst")
	}
	s.sent(last.Add(time.Hour), false, raMaxInterval)
	if s.initial != raInitialCount || !s.wake().Equal(last.Add(time.Hour+time.Second)) {
		t.Fatalf("failed: %d %v", s.initial, s.wake().Sub(last))
	}
}

func TestDeprecate(t *testing.T) {
	now := time.Unix(1e9, 0)
	p1 := RAPrefix{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), Autonomous: true}
	p2 := RAPrefix{Prefix: netip.MustParsePrefix("2001:db8:2::/64"), Autonomous: true}
	onLink := RAPrefix{Prefix: netip.MustParsePrefix("2001:db8:3::/64")}
	old := &RAConfig{Prefixes: []RAPrefix{p1, onLink}}
	cur := &RAConfig{Prefixes: []RAPrefix{p2}}
	gone := deprecate(nil, old, cur, now)
	if len(gone) != 1 || gone[0].Prefix != p1.Prefix || !gone[0].Until.Equal(now.Add(raDeprecate)) {
		t.Fatalf("gone: %v", gone)
	}
	// Back again: no longer deprecated. Expired: forgotten.
	if g := deprecate(gone, cur, old, now); len(g) != 1 || g[0].Prefix != p2.Prefix {
		t.Fatalf("back: %v", g)
	}
	if g := deprecate(gone, cur, cur, now.Add(3*time.Hour)); len(g) != 0 {
		t.Fatalf("expired: %v", g)
	}
}
