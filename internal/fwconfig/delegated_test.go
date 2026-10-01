// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"net/netip"
	"slices"
	"testing"
)

func TestDelegatedResolve(t *testing.T) {
	cases := []struct{ in, pd, want, err string }{
		{"<wan0>:2000::1/64", "2a00:db8:1000::/48", "2a00:db8:1000:2000::1/64", ""},
		{"<wan0>:2000::/64", "2a00:db8:1000::/48", "2a00:db8:1000:2000::/64", ""},
		{"<wan0>::1/64", "2a00:db8:1000:ab00::/56", "2a00:db8:1000:ab00::1/64", ""},
		{"<wan0>:2f::a:b:c:d/128", "2a00:db8:1000:ab00::/56", "2a00:db8:1000:ab2f:a:b:c:d/128", ""},
		{"<wan0>:100::1/64", "2a00:db8:1000:ab00::/56", "", "does not fit"},
		{"<wan0>:1::1/64", "2a00:db8:1000:ab00::/64", "", "does not fit"},
		{"<wan0>::1/64", "2a00:db8:1000:ab00::/64", "2a00:db8:1000:ab00::1/64", ""},
	}
	for _, tc := range cases {
		d, err := ParseDelegated(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if d.String() != tc.in {
			t.Errorf("%s: String() = %s", tc.in, d)
		}
		got, err := d.Resolve(netip.MustParsePrefix(tc.pd))
		if tc.err != "" {
			if err == nil {
				t.Errorf("%s in %s: want error %q, got %s", tc.in, tc.pd, tc.err, got)
			}
			continue
		}
		if err != nil || got.String() != tc.want {
			t.Errorf("%s in %s = %s, %v; want %s", tc.in, tc.pd, got, err, tc.want)
		}
	}
}

func TestParseDelegatedRejects(t *testing.T) {
	for _, s := range []string{
		"<wan0>", "<wan0>:2000::1", "<wan0>:2000::1/48", "<wan0>:2000::1/129", "<wan0>2000::1/64",
		"<wan0>:12345::1/64", "<wan0>:2000:1/64", "<wan0>:2000::1:2:3:4:5/64", "<wan 0>::1/64",
		"<wan0>:2000::1%eth0/64", "<wan0>:g::1/64",
	} {
		if d, err := ParseDelegated(s); err == nil {
			t.Errorf("%q parsed as %s", s, d)
		}
	}
}

func TestResolveDelegated(t *testing.T) {
	doc := SampleDocument()
	in := &doc.Instances[0]
	in.Interfaces[0].DHCPv6, in.Interfaces[0].DHCPv6PD = true, true
	in.Interfaces[1].Addresses = append(in.Interfaces[1].Addresses, "<eth0>:1::1/64")
	in.RA = append(in.RA, RAInterface{
		Interface: "eth1.20",
		Prefixes:  []RAPrefix{{Prefix: "<eth0>:20::/64", Autonomous: true}},
		RDNSS:     []string{"<eth0>:1::1/64"},
	})
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	before := slices.Clone(in.Interfaces[1].Addresses)

	// Nothing delegated yet: the delegated address and RA are left out.
	none := doc.ResolveDelegated(nil)
	if got := none.Instances[0].Interfaces[1].Addresses; !slices.Equal(got, before[:2]) {
		t.Errorf("addresses = %v", got)
	}
	if n := len(none.Instances[0].RA); n != len(in.RA)-1 {
		t.Errorf("%d RAs, want %d", n, len(in.RA)-1)
	}
	if err := none.Validate(); err != nil {
		t.Error(err)
	}

	got := doc.ResolveDelegated(DelegatedPrefixes{"main": {"eth0": netip.MustParsePrefix("2001:db8:aa00::/48")}})
	if a := got.Instances[0].Interfaces[1].Addresses; a[2] != "2001:db8:aa00:1::1/64" {
		t.Errorf("addresses = %v", a)
	}
	ra := got.Instances[0].RA[len(got.Instances[0].RA)-1]
	if ra.Prefixes[0].Prefix != "2001:db8:aa00:20::/64" || ra.RDNSS[0] != "2001:db8:aa00:1::1" {
		t.Errorf("ra = %+v", ra)
	}
	if err := got.Validate(); err != nil {
		t.Error(err)
	}
	if !slices.Equal(in.Interfaces[1].Addresses, before) {
		t.Error("ResolveDelegated changed its document")
	}
}
