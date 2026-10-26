// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

func TestNewProber(t *testing.T) {
	in := &fwconfig.Instance{Name: "main", Interfaces: []fwconfig.Interface{{Name: "wan"}}}
	req := agentapi.ProbeRequest{Target: "192.0.2.1", Protocol: "tcp", Port: 443, Interface: "wan", Interval: 10, Timeout: 1 << 20}
	p, err := newProber(in, &req)
	if err != nil {
		t.Fatal(err)
	}
	if p.dev != "wan" || p.port != 443 || req.Interval != agentapi.ProbeMinInterval || req.Timeout != agentapi.ProbeMaxTimeout || req.Size != agentapi.ProbeDefaultSize {
		t.Errorf("%+v %+v", p, req)
	}
	for _, bad := range []agentapi.ProbeRequest{
		{Target: "example.com", Protocol: "icmp"},
		{Target: "fe80::1%eth0", Protocol: "icmp"},
		{Target: "192.0.2.1", Protocol: "sctp"},
		{Target: "192.0.2.1", Protocol: "udp"},
		{Target: "192.0.2.1", Protocol: "tcp", Port: 70000},
		{Target: "192.0.2.1", Protocol: "icmp", Interface: "nope"},
		{Target: "192.0.2.1", Protocol: "icmp", Count: -1},
	} {
		if _, err := newProber(in, &bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestParseICMPAnswer(t *testing.T) {
	marshal := func(m icmp.Message) []byte {
		b, err := m.Marshal(nil)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	v4 := netip.MustParseAddr("192.0.2.1")
	reply := marshal(icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: 77, Seq: 5}})
	if seq, a, ok := parseICMPAnswer(v4, 77, reply); !ok || seq != 5 || a.status != "ok" {
		t.Errorf("reply: %d %+v %v", seq, a, ok)
	}
	if _, _, ok := parseICMPAnswer(v4, 78, reply); ok {
		t.Error("another id's reply taken")
	}

	// A host unreachable quoting our echo: its IPv4 header, then the echo.
	echo := marshal(icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 77, Seq: 9}})
	hdr := make([]byte, 20)
	hdr[0], hdr[9] = 0x45, 1
	copy(hdr[16:], v4.AsSlice())
	unreach := marshal(icmp.Message{Type: ipv4.ICMPTypeDestinationUnreachable, Code: 1, Body: &icmp.DstUnreach{Data: append(hdr, echo[:8]...)}})
	if seq, a, ok := parseICMPAnswer(v4, 77, unreach); !ok || seq != 9 || a.status != "unreachable" || a.reason != "host unreachable" {
		t.Errorf("unreachable: %d %+v %v", seq, a, ok)
	}
	if _, _, ok := parseICMPAnswer(netip.MustParseAddr("192.0.2.2"), 77, unreach); ok {
		t.Error("an error about another target taken")
	}

	v6 := netip.MustParseAddr("2001:db8::1")
	echo6 := marshal(icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{ID: 77, Seq: 3}})
	hdr6 := make([]byte, 40)
	hdr6[0], hdr6[6] = 0x60, 58
	copy(hdr6[24:], v6.AsSlice())
	te := marshal(icmp.Message{Type: ipv6.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{Data: append(hdr6, echo6[:8]...)}})
	if seq, a, ok := parseICMPAnswer(v6, 77, te); !ok || seq != 3 || a.reason != "time to live exceeded" {
		t.Errorf("time exceeded: %d %+v %v", seq, a, ok)
	}
}

// TestProbeSockets probes local TCP and UDP sockets in the root namespace.
func TestProbeSockets(t *testing.T) {
	in := &fwconfig.Instance{Name: "main", Default: true} // the root namespace
	probe := func(proto string, port int) agentapi.ProbeEvent {
		p, err := newProber(in, &agentapi.ProbeRequest{Target: "127.0.0.1", Protocol: proto, Port: port, Timeout: 300, Payload: "hi"})
		if err != nil {
			t.Fatal(err)
		}
		return p.probe(t.Context(), 1)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if ev := probe("tcp", port); ev.Status != "ok" || ev.Seq != 1 {
		t.Errorf("tcp open: %+v", ev)
	}
	ln.Close()
	if ev := probe("tcp", port); ev.Status != "refused" {
		t.Errorf("tcp closed: %+v", ev)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port = pc.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 64)
		n, from, err := pc.ReadFrom(buf)
		if err == nil && string(buf[:n]) == "hi" {
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	if ev := probe("udp", port); ev.Status != "ok" {
		t.Errorf("udp answered: %+v", ev)
	}
	pc.Close()
	if ev := probe("udp", port); ev.Status != "refused" {
		t.Errorf("udp closed: %+v", ev)
	}
}

// TestProbeICMP pings loopback; it needs CAP_NET_RAW (run it as root, or
// in `unshare -rn` with lo up).
func TestProbeICMP(t *testing.T) {
	in := &fwconfig.Instance{Name: "main", Default: true}
	for _, target := range []string{"127.0.0.1", "::1"} {
		p, err := newProber(in, &agentapi.ProbeRequest{Target: target, Protocol: "icmp", Timeout: 500})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.listen(t.Context()); err != nil {
			t.Skip(err)
		}
		for seq := 1; seq <= 2; seq++ {
			if ev := p.probe(t.Context(), seq); ev.Status != "ok" || ev.Seq != seq {
				t.Errorf("%s: %+v", target, ev)
			}
		}
		p.conn.Close()
	}
}
