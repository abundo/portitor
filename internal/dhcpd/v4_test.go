// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcpd

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

var (
	t0     = time.Unix(1_800_000_000, 0)
	srvID  = netip.MustParseAddr("192.168.1.1")
	macA   = net.HardwareAddr{0x02, 0, 0, 0, 0, 0xa}
	macB   = net.HardwareAddr{0x02, 0, 0, 0, 0, 0xb}
	bcast  = netip.MustParseAddrPort("255.255.255.255:68")
	noAddr = netip.AddrPort{}
)

func testConfig() *Config {
	return &Config{
		LeaseTime: 3600,
		Domain:    "lan.example",
		Subnets4: []Subnet4{{
			Interface: "lan",
			Prefix:    netip.MustParsePrefix("192.168.1.0/24"),
			ServerID:  srvID,
			Pools:     []Range{{netip.MustParseAddr("192.168.1.100"), netip.MustParseAddr("192.168.1.110")}},
			Router:    srvID,
			DNS:       []netip.Addr{srvID},
			Reservations: []Reservation{
				{MAC: "02:00:00:00:00:0c", Addr: netip.MustParseAddr("192.168.1.50"), Hostname: "printer.lan.example"},
			},
		}},
	}
}

type testServer struct {
	*Server
	t *testing.T
	// inUse are the hosts that answer ARP for an address.
	inUse map[netip.Addr]net.HardwareAddr
	path  string
}

func newTestServer(t *testing.T, cfg *Config) *testServer {
	t.Helper()
	path := filepath.Join(t.TempDir(), "leases")
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ts := &testServer{Server: NewServer(cfg, st), t: t, inUse: map[netip.Addr]net.HardwareAddr{}, path: path}
	ts.now = func() time.Time { return t0 }
	ts.jitter = func(int64) int64 { return 0 }
	ts.probe = func(_ string, a netip.Addr) net.HardwareAddr { return ts.inUse[a] }
	return ts
}

type pkt func(*Packet4)

func withType(t byte) pkt { return func(p *Packet4) { p.Set(optMessageType, []byte{t}) } }
func withMAC(m net.HardwareAddr) pkt {
	return func(p *Packet4) { p.CHAddr = m; p.HLen = byte(len(m)) }
}
func withOpt(code byte, v []byte) pkt { return func(p *Packet4) { p.Set(code, v) } }
func withAddr(code byte, a string) pkt {
	return func(p *Packet4) { p.SetAddrs(code, netip.MustParseAddr(a)) }
}
func withCIAddr(a string) pkt { return func(p *Packet4) { p.CIAddr = netip.MustParseAddr(a) } }

// send runs a request through the wire format both ways.
func (ts *testServer) send(opts ...pkt) (*Packet4, netip.AddrPort) {
	ts.t.Helper()
	req := &Packet4{Op: bootRequest, HType: 1, HLen: 6, XID: 42, CHAddr: macA}
	for _, o := range opts {
		o(req)
	}
	parsed, err := Parse4(req.Marshal(minMaxSize))
	if err != nil {
		ts.t.Fatal(err)
	}
	r, dst := ts.Handle4("lan", parsed, netip.MustParseAddrPort("0.0.0.0:68"))
	if r == nil {
		return nil, dst
	}
	back, err := Parse4(r.Marshal(parsed.MaxSize()))
	if err != nil {
		ts.t.Fatal(err)
	}
	return back, dst
}

func (ts *testServer) bind(mac net.HardwareAddr) netip.Addr {
	ts.t.Helper()
	off, _ := ts.send(withType(Discover), withMAC(mac))
	if off == nil || off.Type() != Offer {
		ts.t.Fatalf("no offer: %+v", off)
	}
	ack, _ := ts.send(withType(Request), withMAC(mac), withAddr(optRequestedIP, off.YIAddr.String()), withAddr(optServerID, srvID.String()))
	if ack == nil || ack.Type() != Ack {
		ts.t.Fatalf("no ack: %+v", ack)
	}
	return ack.YIAddr
}

func TestParseTolerant(t *testing.T) {
	base := func(opts ...byte) []byte {
		b := make([]byte, headerLen)
		b[0], b[1], b[2] = bootRequest, 1, 6
		b = append(b, magic[:]...)
		return append(b, opts...)
	}
	cases := []struct {
		name  string
		in    []byte
		check func(*Packet4) bool
	}{
		{"truncated option keeps earlier", base(53, 1, 1, 12, 9, 'a'), func(p *Packet4) bool {
			return p.Type() == Discover && p.Options[optHostname] == nil
		}},
		{"no End", base(53, 1, 3), func(p *Packet4) bool { return p.Type() == Request }},
		{"repeated options concatenate", base(55, 2, 1, 3, 55, 1, 6, 255), func(p *Packet4) bool {
			return bytes.Equal(p.Options[optParamRequest], []byte{1, 3, 6})
		}},
		{"empty hostname dropped", base(12, 0, 255), func(p *Packet4) bool {
			_, ok := p.Options[optHostname]
			return !ok
		}},
		{"hostname NUL cut", base(12, 4, 'p', 'c', 0, 0, 255), func(p *Packet4) bool {
			return string(p.Options[optHostname]) == "pc"
		}},
	}
	for _, c := range cases {
		p, err := Parse4(c.in)
		if err != nil || !c.check(p) {
			t.Errorf("%s: %v %+v", c.name, err, p)
		}
	}
	// Overloaded file field.
	b := base(52, 1, 1, 255)
	copy(b[108:], []byte{53, 1, 7, 255})
	if p, _ := Parse4(b); p.Type() != Release {
		t.Errorf("overload: %+v", p.Options)
	}
	if _, err := Parse4(make([]byte, 100)); err == nil {
		t.Error("short packet parsed")
	}
}

func TestMarshal(t *testing.T) {
	p := &Packet4{Op: bootReply, HLen: 6}
	p.Set(optServerID, srvID.AsSlice())
	p.Set(optMessageType, []byte{Offer})
	p.Set(optDomain, bytes.Repeat([]byte{'x'}, 400))
	b := p.Marshal(minMaxSize)
	if len(b) < minPacket || len(b) > minMaxSize-ipUDPLen {
		t.Errorf("length %d", len(b))
	}
	if b[headerLen+4] != optMessageType {
		t.Errorf("first option %d", b[headerLen+4])
	}
	q, _ := Parse4(b)
	if q.Options[optDomain] != nil || q.Addr(optServerID) != srvID {
		t.Errorf("an option that doesn't fit is left out, the server id not: %+v", q.Options)
	}
	big := p.Marshal(1500)
	q, _ = Parse4(big)
	if len(q.Options[optDomain]) != 400 {
		t.Errorf("long option with room: %d", len(q.Options[optDomain]))
	}
	small := (&Packet4{Op: bootReply}).Marshal(0)
	if len(small) != minPacket {
		t.Errorf("padding: %d", len(small))
	}
}

func TestDiscoverRequest(t *testing.T) {
	ts := newTestServer(t, testConfig())
	off, dst := ts.send(withType(Discover), withCIAddr("10.0.0.9"), withOpt(optParamRequest, []byte{1, 3, 6, 15}))
	if off.Type() != Offer || off.YIAddr != netip.MustParseAddr("192.168.1.100") {
		t.Fatalf("offer %+v", off)
	}
	if dst != bcast {
		t.Errorf("ciaddr of a DISCOVER is ignored: %v", dst)
	}
	if off.Addr(optServerID) != srvID || off.Addr(optRouter) != srvID || string(off.Options[optDomain]) != "lan.example" {
		t.Errorf("options %+v", off.Options)
	}
	if lt, _ := off.Uint32(optLeaseTime); lt != 3600 {
		t.Errorf("lease %d", lt)
	}
	if !bytes.Equal(off.Options[optSubnetMask], []byte{255, 255, 255, 0}) {
		t.Errorf("mask %v", off.Options[optSubnetMask])
	}
	// Another client isn't offered the same address meanwhile.
	off2, _ := ts.send(withType(Discover), withMAC(macB))
	if off2.YIAddr == off.YIAddr {
		t.Errorf("same offer to two clients")
	}
	// A request for another server's offer drops ours.
	if r, _ := ts.send(withType(Request), withAddr(optServerID, "192.168.1.2"), withAddr(optRequestedIP, off.YIAddr.String())); r != nil {
		t.Errorf("answered another server's request: %+v", r)
	}
	ack, dst := ts.send(withType(Request), withAddr(optServerID, srvID.String()), withAddr(optRequestedIP, off.YIAddr.String()))
	if ack.Type() != Ack || ack.YIAddr != off.YIAddr || dst != bcast {
		t.Fatalf("ack %+v to %v", ack, dst)
	}
	l := ts.store.Get(off.YIAddr)
	if l == nil || l.MAC != macA.String() || l.Expires != t0.Unix()+3600 {
		t.Errorf("lease %+v", l)
	}
	// Renewing: unicast to ciaddr.
	ack, dst = ts.send(withType(Request), withCIAddr(off.YIAddr.String()))
	if ack.Type() != Ack || dst != netip.AddrPortFrom(off.YIAddr, 68) || ack.CIAddr != off.YIAddr {
		t.Errorf("renew %+v to %v", ack, dst)
	}
}

func TestRequestCases(t *testing.T) {
	ts := newTestServer(t, testConfig())
	a := ts.bind(macA)
	cases := []struct {
		name string
		opts []pkt
		want byte // 0: no reply
		addr string
	}{
		{"init-reboot own", []pkt{withAddr(optRequestedIP, a.String())}, Ack, a.String()},
		{"another's address", []pkt{withMAC(macB), withAddr(optRequestedIP, a.String())}, Nak, ""},
		{"wrong network", []pkt{withAddr(optRequestedIP, "10.1.1.1")}, Nak, ""},
		{"outside the pool", []pkt{withAddr(optRequestedIP, "192.168.1.20")}, Nak, ""},
		{"another's reservation", []pkt{withAddr(optRequestedIP, "192.168.1.50")}, Nak, ""},
		// After a failover: the store doesn't know it, it is free.
		{"unknown free address", []pkt{withMAC(macB), withCIAddr("192.168.1.105")}, Ack, "192.168.1.105"},
		{"no address at all", []pkt{withMAC(net.HardwareAddr{2, 0, 0, 0, 0, 0xd})}, Ack, "192.168.1.101"},
	}
	for _, c := range cases {
		r, dst := ts.send(append([]pkt{withType(Request)}, c.opts...)...)
		switch {
		case c.want == 0 && r != nil:
			t.Errorf("%s: reply %+v", c.name, r)
		case c.want != 0 && (r == nil || r.Type() != c.want):
			t.Errorf("%s: %+v", c.name, r)
		case c.want == Nak && dst != bcast:
			t.Errorf("%s: NAK to %v", c.name, dst)
		case c.addr != "" && r.YIAddr != netip.MustParseAddr(c.addr):
			t.Errorf("%s: address %v", c.name, r.YIAddr)
		}
	}
	// macB moved to .105: one lease per client.
	if l := ts.leaseOf([]*Subnet4{&ts.cfg.Subnets4[0]}, client4{mac: macB.String()}); l.Addr != netip.MustParseAddr("192.168.1.105") {
		t.Errorf("macB %+v", l)
	}
}

func TestClientID(t *testing.T) {
	ts := newTestServer(t, testConfig())
	id := []byte{1, 2, 3}
	off, _ := ts.send(withType(Discover), withOpt(optClientID, id))
	if !bytes.Equal(off.Options[optClientID], id) {
		t.Errorf("client id not echoed")
	}
	ts.send(withType(Request), withOpt(optClientID, id), withAddr(optRequestedIP, off.YIAddr.String()))
	// The same client id on another MAC (a dock) is the same client.
	r, _ := ts.send(withType(Discover), withMAC(macB), withOpt(optClientID, id))
	if r.YIAddr != off.YIAddr {
		t.Errorf("client id: %v != %v", r.YIAddr, off.YIAddr)
	}
	// Without its id, found by MAC, and the lease keeps the id.
	ts.send(withType(Request), withAddr(optRequestedIP, off.YIAddr.String()))
	if l := ts.store.Get(off.YIAddr); l.ClientID != "010203" {
		t.Errorf("id lost: %+v", l)
	}
	// Another id on the same MAC is another client.
	r, _ = ts.send(withType(Discover), withOpt(optClientID, []byte{9}))
	if r.YIAddr == off.YIAddr {
		t.Errorf("another client id got the lease")
	}
}

func TestDeclineRelease(t *testing.T) {
	ts := newTestServer(t, testConfig())
	a := ts.bind(macA)
	// Another client can't decline it.
	ts.send(withType(Decline), withMAC(macB), withAddr(optRequestedIP, a.String()))
	if ts.store.Get(a).Declined {
		t.Fatal("declined by another client")
	}
	ts.send(withType(Release), withCIAddr(a.String()))
	if ts.store.Get(a).Valid(t0) {
		t.Fatal("not released")
	}
	// Released, it comes back to its client, not to another.
	if off, _ := ts.send(withType(Discover), withMAC(macB)); off.YIAddr == a {
		t.Errorf("released address went to another client first")
	}
	b := ts.bind(macA)
	if b != a {
		t.Errorf("client got %v, not its %v", b, a)
	}
	ts.send(withType(Decline), withAddr(optRequestedIP, a.String()))
	if l := ts.store.Get(a); !l.Declined || !l.Valid(t0) {
		t.Fatalf("decline: %+v", l)
	}
	if off, _ := ts.send(withType(Discover)); off.YIAddr == a {
		t.Errorf("declined address offered")
	}
}

func TestAllocation(t *testing.T) {
	cfg := testConfig()
	cfg.Subnets4[0].Pools = []Range{{netip.MustParseAddr("192.168.1.254"), netip.MustParseAddr("192.168.1.255")}}
	ts := newTestServer(t, cfg)
	if off, _ := ts.send(withType(Discover)); off.YIAddr != netip.MustParseAddr("192.168.1.254") {
		t.Errorf(".255 handed out: %+v", off)
	}
	cfg = testConfig()
	ts = newTestServer(t, cfg)
	ts.inUse[netip.MustParseAddr("192.168.1.100")] = net.HardwareAddr{2, 9, 9, 9, 9, 9}
	if off, _ := ts.send(withType(Discover)); off.YIAddr != netip.MustParseAddr("192.168.1.101") {
		t.Errorf("address in use offered: %v", off.YIAddr)
	}
	// The client's own address isn't checked.
	a := ts.bind(macB)
	ts.inUse[a] = net.HardwareAddr{2, 9, 9, 9, 9, 9}
	if off, _ := ts.send(withType(Discover), withMAC(macB)); off.YIAddr != a {
		t.Errorf("own lease checked: %v", off.YIAddr)
	}
	// A reservation.
	off, _ := ts.send(withType(Discover), withMAC(net.HardwareAddr{2, 0, 0, 0, 0, 0xc}), withOpt(optParamRequest, []byte{12}))
	if off.YIAddr != netip.MustParseAddr("192.168.1.50") || string(off.Options[optHostname]) != "printer" {
		t.Errorf("reservation %v %q", off.YIAddr, off.Options[optHostname])
	}
	// The requested address, when free.
	off, _ = ts.send(withType(Discover), withMAC(net.HardwareAddr{2, 0, 0, 0, 0, 0xe}), withAddr(optRequestedIP, "192.168.1.108"))
	if off.YIAddr != netip.MustParseAddr("192.168.1.108") {
		t.Errorf("requested %v", off.YIAddr)
	}
}

func TestLeaseTimes(t *testing.T) {
	ts := newTestServer(t, testConfig())
	ts.jitter = func(n int64) int64 { return n - 1 }
	off, _ := ts.send(withType(Discover), withOpt(optLeaseTime, binary.BigEndian.AppendUint32(nil, 10)))
	if lt, _ := off.Uint32(optLeaseTime); lt != minLease {
		t.Errorf("minimum lease: %d", lt)
	}
	off, _ = ts.send(withType(Discover))
	t1, _ := off.Uint32(optT1)
	t2, _ := off.Uint32(optT2)
	if t1 != 1800-224 || t2 != 3150 {
		t.Errorf("T1 %d T2 %d", t1, t2)
	}
}

func TestV6OnlyAndInform(t *testing.T) {
	cfg := testConfig()
	cfg.Subnets4[0].V6OnlyPreferred = 1800
	ts := newTestServer(t, cfg)
	off, _ := ts.send(withType(Discover), withOpt(optParamRequest, []byte{1, 108}))
	if v, _ := off.Uint32(optV6OnlyPref); v != 1800 || !off.YIAddr.IsUnspecified() {
		t.Errorf("v6-only %+v", off)
	}
	off, _ = ts.send(withType(Discover))
	if _, ok := off.Options[optV6OnlyPref]; ok || off.YIAddr.IsUnspecified() {
		t.Errorf("108 to a client that didn't ask: %+v", off)
	}
	req := &Packet4{Op: bootRequest, HType: 1, HLen: 6, CHAddr: macA}
	req.Set(optMessageType, []byte{Inform})
	src := netip.MustParseAddrPort("192.168.1.30:68")
	r, dst := ts.Handle4("lan", req, src)
	if r.Type() != Ack || dst != src || r.Options[optLeaseTime] != nil {
		t.Errorf("inform %+v to %v", r, dst)
	}
}

func TestStoreReopen(t *testing.T) {
	ts := newTestServer(t, testConfig())
	a := ts.bind(macA)
	ts.store.Close()
	st, err := OpenStore(ts.path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if l := st.Get(a); l == nil || l.MAC != macA.String() {
		t.Errorf("after reopen: %+v", l)
	}
	for i := range 3000 {
		st.Put(Lease{Addr: a, MAC: macA.String(), Expires: int64(i)}, false)
	}
	if st.lines > 2*len(st.leases)+1001 {
		t.Errorf("not compacted: %d lines", st.lines)
	}
}

// After a failover the new host has no record of a client's lease. A new
// client is not offered that address (its holder answers ARP), and the
// holder keeps it when it renews; another client asking for it doesn't
// get it.
func TestUnknownHolder(t *testing.T) {
	ts := newTestServer(t, testConfig())
	held := netip.MustParseAddr("192.168.1.100")
	ts.inUse[held] = macA
	off, _ := ts.send(withType(Discover), withMAC(macB))
	if off.YIAddr == held {
		t.Fatal("offered an address in use")
	}
	// The holder renews (ciaddr) and reboots (requested address).
	if r, _ := ts.send(withType(Request), withCIAddr(held.String())); r.Type() != Ack || r.YIAddr != held {
		t.Errorf("holder's renewal: %+v", r)
	}
	ts.store.Put(Lease{Addr: held}, false) // forget it again
	if r, _ := ts.send(withType(Request), withAddr(optRequestedIP, held.String())); r.Type() != Ack {
		t.Errorf("holder's init-reboot: %+v", r)
	}
	ts.store.Put(Lease{Addr: held}, false)
	// Someone else asks for it while the holder answers.
	if r, _ := ts.send(withType(Request), withMAC(net.HardwareAddr{2, 0, 0, 0, 0, 0xd}), withAddr(optRequestedIP, held.String())); r.Type() != Nak {
		t.Errorf("another client got a held address: %+v", r)
	}
	// The holder's DISCOVER asking for it is offered it.
	if r, _ := ts.send(withType(Discover), withAddr(optRequestedIP, held.String())); r.YIAddr != held {
		t.Errorf("holder's discover: %+v", r)
	}
}
