// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

func ipv4Header(proto byte, fragOff uint16, l4 []byte) []byte {
	n := 20 + len(l4)
	h := []byte{0x45, 0, byte(n >> 8), byte(n), 0, 0, byte(fragOff >> 8), byte(fragOff), 64, proto, 0, 0,
		192, 0, 2, 1, 198, 51, 100, 7}
	return append(h, l4...)
}

func ipv6Header(next byte, rest []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	h[4], h[5] = byte(len(rest)>>8), byte(len(rest))
	h[6] = next
	h[8], h[9], h[23] = 0x20, 0x01, 1   // 2001::1
	h[24], h[25], h[39] = 0x20, 0x01, 2 // 2001::2
	return append(h, rest...)
}

func TestParseLoggedPacket(t *testing.T) {
	tcpSyn := []byte{0xc3, 0x50, 0x01, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0}
	udp := []byte{0x00, 0x35, 0xd4, 0x31, 0, 8, 0, 0}
	for _, c := range []struct {
		name   string
		prefix string
		pkt    []byte
		want   agentapi.PacketLogEntry
	}{
		{"ipv4 tcp", "forward policy drop", ipv4Header(6, 0, tcpSyn), agentapi.PacketLogEntry{
			Chain: "forward", Builtin: "policy", Action: "drop", Family: "ipv4", Protocol: "tcp",
			Src: "192.0.2.1", Dst: "198.51.100.7", SrcPort: 50000, DstPort: 443, Info: "SYN", Length: 40,
		}},
		{"ipv4 icmp", "input rule 3 reject", ipv4Header(1, 0, []byte{8, 0, 0, 0}), agentapi.PacketLogEntry{
			Chain: "input", Rule: 3, Action: "reject", Family: "ipv4", Protocol: "icmp",
			Src: "192.0.2.1", Dst: "198.51.100.7", Info: "type 8 code 0", Length: 24,
		}},
		{"ipv4 later fragment", "input invalid drop", ipv4Header(17, 185, udp), agentapi.PacketLogEntry{
			Chain: "input", Builtin: "invalid", Action: "drop", Family: "ipv4", Protocol: "udp",
			Src: "192.0.2.1", Dst: "198.51.100.7", Length: 28,
		}},
		{"ipv6 hop-by-hop udp", "output rule 12 accept", ipv6Header(0, append([]byte{17, 0, 0, 0, 0, 0, 0, 0}, udp...)), agentapi.PacketLogEntry{
			Chain: "output", Rule: 12, Action: "accept", Family: "ipv6", Protocol: "udp",
			Src: "2001::1", Dst: "2001::2", SrcPort: 53, DstPort: 54321, Length: 56,
		}},
		{"ipv6 truncated", "input auto accept dns server", ipv6Header(6, []byte{1, 2}), agentapi.PacketLogEntry{
			Chain: "input", Builtin: "auto", Service: "dns server", Action: "accept", Family: "ipv6", Protocol: "tcp",
			Src: "2001::1", Dst: "2001::2", Length: 42,
		}},
	} {
		got, ok := parseLoggedPacket(c.prefix, c.pkt)
		if !ok || got != c.want {
			t.Errorf("%s: got %+v %v\nwant %+v", c.name, got, ok, c.want)
		}
	}
	for _, bad := range []struct{ prefix, pkt string }{
		{"fw rule 8 drop: ", string(ipv4Header(6, 0, tcpSyn))},
		{"input policy drop", ""},
		{"input policy drop", "\x45\x00"},
		{"input policy drop", "\x10\x00"},
	} {
		if e, ok := parseLoggedPacket(bad.prefix, []byte(bad.pkt)); ok {
			t.Errorf("%q %x parsed: %+v", bad.prefix, bad.pkt, e)
		}
	}
}

func TestLogsPackets(t *testing.T) {
	in := fwconfig.Instance{Rules: []fwconfig.Rule{{Chain: fwconfig.ChainInput, Action: fwconfig.ActionAccept}}}
	if logsPackets(&in) {
		t.Error("nothing logged")
	}
	in.Rules[0].Log = true
	if !logsPackets(&in) {
		t.Error("rule log")
	}
	in.Rules[0].Log = false
	for _, set := range []func(){
		func() { in.LogDrops = []string{fwconfig.ChainForward} },
		func() { in.LogInvalid = []string{fwconfig.ChainInput} },
		func() { in.LogAuto = []string{"dns server"} },
	} {
		in.LogDrops, in.LogInvalid, in.LogAuto = nil, nil, nil
		set()
		if !logsPackets(&in) {
			t.Errorf("not logging: %+v", in)
		}
	}
}

func TestPacketLogReconcileDryRun(t *testing.T) {
	p := newPacketLog(true)
	p.Reconcile(map[string]string{"main": "fw-main"})
	if len(p.listeners) != 0 {
		t.Errorf("dry-run listens: %v", p.listeners)
	}
	p.Stop()
}
