// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"encoding/binary"
	"net"
	"slices"
	"testing"
	"time"
)

func TestLLDPFrameRoundTrip(t *testing.T) {
	src := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	frame := lldpFrame(src, lldpLocal{
		SystemName:        "fw1/guest",
		SystemDescription: "Portitor firewall dev",
		PortID:            "ens19",
		PortDescription:   "LAN",
		TTL:               lldpTTL,
	})
	if len(frame) < 60 {
		t.Fatalf("frame is %d bytes, below the ethernet minimum", len(frame))
	}
	if !slices.Equal(frame[:6], lldpMulticast) {
		t.Fatalf("destination %x", frame[:6])
	}
	nb, ok := parseLLDP(frame)
	if !ok {
		t.Fatal("own frame did not parse")
	}
	want := LLDPNeighbour{
		SourceMAC:           "52:54:00:12:34:56",
		ChassisIDSubtype:    "local",
		ChassisID:           "fw1/guest",
		PortIDSubtype:       "interface name",
		PortID:              "ens19",
		TTL:                 120,
		PortDescription:     "LAN",
		SystemName:          "fw1/guest",
		SystemDescription:   "Portitor firewall dev",
		Capabilities:        []string{"router"},
		EnabledCapabilities: []string{"router"},
	}
	if !lldpEqual(nb, want) {
		t.Fatalf("got %+v\nwant %+v", nb, want)
	}
}

// switchFrame is what a switch might send: a MAC chassis id, a VLAN tag
// left in place, a management address and organizational TLVs.
func switchFrame() []byte {
	b := []byte{0x01, 0x80, 0xc2, 0, 0, 0x0e, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x81, 0x00, 0x00, 0x0a, 0x88, 0xcc}
	tlv := func(typ int, v ...byte) {
		b = binary.BigEndian.AppendUint16(b, uint16(typ)<<9|uint16(len(v)))
		b = append(b, v...)
	}
	tlv(1, 4, 0x00, 0x11, 0x22, 0x33, 0x44, 0x00)
	tlv(2, 5, 'G', 'i', '0', '/', '1')
	tlv(3, 0, 120)
	tlv(5, []byte("core-sw")...)
	tlv(7, 0x00, 0x14, 0x00, 0x04) // bridge+router, bridge enabled
	tlv(8, 5, 1, 192, 0, 2, 1, 2, 0, 0, 0, 1, 0)
	tlv(127, 0x00, 0x80, 0xc2, 1, 0x00, 0x0a)
	tlv(127, 0x00, 0x80, 0xc2, 3, 0x00, 0x0a, 6, 'o', 'f', 'f', 'i', 'c', 'e')
	tlv(127, 0x00, 0x12, 0x0f, 4, 0x05, 0xee)
	tlv(127, 0x00, 0x12, 0x0f, 1, 3, 0x6c, 0, 0x10, 0x00) // unknown: skipped
	tlv(0)
	return b
}

func TestParseLLDP(t *testing.T) {
	nb, ok := parseLLDP(switchFrame())
	if !ok {
		t.Fatal("not parsed")
	}
	want := LLDPNeighbour{
		SourceMAC:           "00:11:22:33:44:55",
		ChassisIDSubtype:    "mac",
		ChassisID:           "00:11:22:33:44:00",
		PortIDSubtype:       "interface name",
		PortID:              "Gi0/1",
		TTL:                 120,
		SystemName:          "core-sw",
		Capabilities:        []string{"bridge", "router"},
		EnabledCapabilities: []string{"bridge"},
		ManagementAddresses: []string{"192.0.2.1"},
		PortVLAN:            10,
		VLANNames:           []string{"10 office"},
		MaxFrame:            1518,
	}
	if !lldpEqual(nb, want) {
		t.Fatalf("got %+v\nwant %+v", nb, want)
	}

	for name, frame := range map[string][]byte{
		"short":      switchFrame()[:10],
		"not lldp":   append(append([]byte{}, switchFrame()[:12]...), 0x08, 0x00, 0, 0),
		"truncated":  switchFrame()[:30],
		"no chassis": {0x01, 0x80, 0xc2, 0, 0, 0x0e, 0, 1, 2, 3, 4, 5, 0x88, 0xcc, 0x04, 0x02, 5, 'x', 0x06, 0x02, 0, 1, 0, 0},
	} {
		if _, ok := parseLLDP(frame); ok {
			t.Errorf("%s: parsed", name)
		}
	}
}

func lldpEqual(a, b LLDPNeighbour) bool {
	return a.SourceMAC == b.SourceMAC && a.ChassisID == b.ChassisID && a.ChassisIDSubtype == b.ChassisIDSubtype &&
		a.PortID == b.PortID && a.PortIDSubtype == b.PortIDSubtype && a.TTL == b.TTL &&
		a.PortDescription == b.PortDescription && a.SystemName == b.SystemName && a.SystemDescription == b.SystemDescription &&
		slices.Equal(a.Capabilities, b.Capabilities) && slices.Equal(a.EnabledCapabilities, b.EnabledCapabilities) &&
		slices.Equal(a.ManagementAddresses, b.ManagementAddresses) && a.PortVLAN == b.PortVLAN &&
		slices.Equal(a.VLANNames, b.VLANNames) && a.MaxFrame == b.MaxFrame
}

func TestLLDPRecord(t *testing.T) {
	m := newLLDPManager(true)
	k := lldpKey{instance: "main", iface: "ens19"}
	m.ports[k] = &lldpPort{cancel: func() {}, neighbours: map[string]*LLDPNeighbour{}}
	nb, _ := parseLLDP(switchFrame())
	t0 := time.Now()
	m.record(k, nb, t0.Add(-time.Minute))
	m.record(k, nb, t0)
	_, got := m.Snapshot()
	if len(got) != 1 || got[0].Instance != "main" || got[0].Interface != "ens19" ||
		!got[0].FirstSeen.Equal(t0.Add(-time.Minute)) || !got[0].Expires.Equal(t0.Add(120*time.Second)) {
		t.Fatalf("got %+v", got)
	}

	// A shutdown forgets the neighbour.
	nb.TTL = 0
	m.record(k, nb, t0)
	if _, got := m.Snapshot(); len(got) != 0 {
		t.Fatalf("after shutdown: %+v", got)
	}

	// So does its TTL running out.
	nb.TTL = 1
	m.record(k, nb, t0.Add(-2*time.Second))
	if _, got := m.Snapshot(); len(got) != 0 {
		t.Fatalf("expired: %+v", got)
	}

	// Nor is anything recorded for an interface LLDP no longer runs on.
	nb.TTL = 120
	m.record(lldpKey{instance: "main", iface: "ens20"}, nb, t0)
	if ports, got := m.Snapshot(); len(got) != 0 || len(ports) != 1 {
		t.Fatalf("other port: %+v %+v", ports, got)
	}
}

func TestParseIPNeigh(t *testing.T) {
	data := []byte(`[
{"dst":"192.0.2.1","dev":"ens18","lladdr":"00:11:22:33:44:55","state":["REACHABLE"]},
{"dst":"192.0.2.9","dev":"ens18","state":["FAILED"]},
{"dst":"fe80::1","dev":"ens18","lladdr":"00:11:22:33:44:55","router":null,"state":["STALE"]}
]`)
	got := parseIPNeigh(data, true)
	want := []IPNeighbour{
		{Interface: "ens18", Family: "ipv6", Address: "192.0.2.1", MAC: "00:11:22:33:44:55", State: "reachable"},
		{Interface: "ens18", Family: "ipv6", Address: "192.0.2.9", State: "failed"},
		{Interface: "ens18", Family: "ipv6", Address: "fe80::1", MAC: "00:11:22:33:44:55", State: "stale", Router: true},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
	if parseIPNeigh(nil, false) != nil || parseIPNeigh([]byte("nope"), false) != nil {
		t.Fatal("bad input parsed")
	}
}
