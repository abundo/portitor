// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcpd

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

func testConfig6() *Config {
	return &Config{
		LeaseTime: 4000,
		Domain:    "lan.example",
		DUID:      "000400112233445566778899aabbccddeeff",
		Subnets6: []Subnet6{{
			Interface: "lan",
			Prefix:    netip.MustParsePrefix("2001:db8:1::/64"),
			Pools:     []Range{{netip.MustParseAddr("2001:db8:1::100"), netip.MustParseAddr("2001:db8:1::1ff")}},
			DNS:       []netip.Addr{netip.MustParseAddr("2001:db8:1::1")},
			Reservations: []Reservation{
				{MAC: "02:00:00:00:00:0c", Addr: netip.MustParseAddr("2001:db8:1::50"), Hostname: "printer.lan.example"},
			},
		}},
	}
}

var (
	duidA   = &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{2, 0, 0, 0, 0, 0xa}}
	duidRes = &dhcpv6.DUIDLLT{HWType: iana.HWTypeEthernet, Time: 1, LinkLayerAddr: net.HardwareAddr{2, 0, 0, 0, 0, 0xc}}
	src6    = netip.MustParseAddrPort("[fe80::1%lan]:546")
)

func msg6(t *testing.T, typ dhcpv6.MessageType, duid dhcpv6.DUID, server bool, addrs ...string) *dhcpv6.Message {
	t.Helper()
	m, _ := dhcpv6.NewMessage()
	m.MessageType = typ
	m.Options.Add(dhcpv6.OptClientID(duid))
	if server {
		m.Options.Add(dhcpv6.OptServerID(&dhcpv6.DUIDUUID{UUID: [16]byte{0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}}))
	}
	ia := &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 1}}
	for _, a := range addrs {
		ia.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP(a)})
	}
	m.Options.Add(ia)
	// Through the wire format.
	p, err := dhcpv6.FromBytes(m.ToBytes())
	if err != nil {
		t.Fatal(err)
	}
	return p.(*dhcpv6.Message)
}

func iaAddr(r *dhcpv6.Message) (netip.Addr, time.Duration) {
	ia := r.Options.OneIANA()
	if ia == nil {
		return netip.Addr{}, 0
	}
	for _, a := range ia.Options.Addresses() {
		if a.ValidLifetime > 0 {
			addr, _ := netip.AddrFromSlice(a.IPv6Addr)
			return addr, a.ValidLifetime
		}
	}
	return netip.Addr{}, 0
}

func TestDHCPv6(t *testing.T) {
	ts := newTestServer(t, testConfig6())
	adv := ts.Handle6("lan", msg6(t, dhcpv6.MessageTypeSolicit, duidA, false), src6, "")
	if adv == nil || adv.MessageType != dhcpv6.MessageTypeAdvertise {
		t.Fatalf("advertise %v", adv)
	}
	a, valid := iaAddr(adv)
	if a != netip.MustParseAddr("2001:db8:1::100") || valid != 4000*time.Second {
		t.Fatalf("advertised %v %v", a, valid)
	}
	if ts.store.Get(a) != nil {
		t.Error("bound on solicit")
	}
	if len(adv.Options.DNS()) != 1 || adv.Options.ServerID() == nil || adv.Options.ClientID() == nil {
		t.Errorf("options %v", adv.Options)
	}
	// A solicit naming a server is dropped; a request naming another too.
	if ts.Handle6("lan", msg6(t, dhcpv6.MessageTypeSolicit, duidA, true), src6, "") != nil {
		t.Error("solicit with a server id answered")
	}
	rep := ts.Handle6("lan", msg6(t, dhcpv6.MessageTypeRequest, duidA, true, a.String()), src6, "")
	if got, _ := iaAddr(rep); got != a || rep.MessageType != dhcpv6.MessageTypeReply {
		t.Fatalf("reply %v", rep)
	}
	l := ts.store.Get(a)
	if l == nil || l.IAID != 1 || l.MAC != "02:00:00:00:00:0a" {
		t.Errorf("lease %+v", l)
	}
	// A renewal: the same address.
	rep = ts.Handle6("lan", msg6(t, dhcpv6.MessageTypeRenew, duidA, true, a.String()), src6, "")
	if got, _ := iaAddr(rep); got != a {
		t.Errorf("renew %v", rep)
	}
	// A rebind for an address the store doesn't know, free: kept.
	other := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{2, 0, 0, 0, 0, 0xb}}
	rep = ts.Handle6("lan", msg6(t, dhcpv6.MessageTypeRebind, other, false, "2001:db8:1::150"), src6, "")
	if got, _ := iaAddr(rep); got != netip.MustParseAddr("2001:db8:1::150") {
		t.Errorf("rebind unknown %v", rep)
	}
	// Another's address: lifetimes 0 for it, and a new one.
	rep = ts.Handle6("lan", msg6(t, dhcpv6.MessageTypeRebind, other, false, a.String()), src6, "")
	if got, _ := iaAddr(rep); got == a || !got.IsValid() {
		t.Errorf("rebind another's %v", got)
	}
	// Confirm.
	rep = ts.Handle6("lan", msg6(t, dhcpv6.MessageTypeConfirm, duidA, false, "2001:db8:9::1"), src6, "")
	if rep.Options.Status().StatusCode != iana.StatusNotOnLink {
		t.Errorf("confirm %v", rep.Options.Status())
	}
	// Release.
	ts.Handle6("lan", msg6(t, dhcpv6.MessageTypeRelease, duidA, true, a.String()), src6, "")
	if ts.store.Get(a).Valid(t0) {
		t.Error("not released")
	}
	// The reservation, its MAC from the DUID-LLT.
	adv = ts.Handle6("lan", msg6(t, dhcpv6.MessageTypeSolicit, duidRes, false), src6, "")
	if got, _ := iaAddr(adv); got != netip.MustParseAddr("2001:db8:1::50") {
		t.Errorf("reservation %v", got)
	}
	// And from the neighbour table, which comes first (the offer above
	// held it for that client).
	clear(ts.offers)
	opaque := &dhcpv6.DUIDEN{EnterpriseNumber: 9, EnterpriseIdentifier: []byte{1}}
	adv = ts.Handle6("lan", msg6(t, dhcpv6.MessageTypeSolicit, opaque, false), src6, "02:00:00:00:00:0c")
	if got, _ := iaAddr(adv); got != netip.MustParseAddr("2001:db8:1::50") {
		t.Errorf("reservation by neighbour %v", got)
	}
}

func TestMACFrom(t *testing.T) {
	if m := MACFromEUI64(netip.MustParseAddr("fe80::ff:fe00:c")); m.String() != "02:00:00:00:00:0c" {
		t.Errorf("eui64 %v", m)
	}
	if m := MACFromEUI64(netip.MustParseAddr("fe80::1234:5678:9abc:def0")); m != nil {
		t.Errorf("not eui64 %v", m)
	}
	if m := MACFromDUID(duidRes.ToBytes()); m.String() != "02:00:00:00:00:0c" {
		t.Errorf("duid-llt %v", m)
	}
}
