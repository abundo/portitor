// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"

	"github.com/abundo/portitor/internal/fwconfig"
)

// haAnnounceAgain is when the announcements are sent the second time.
const haAnnounceAgain = time.Second

// onTakeover tells the network the host took over: the hosts keep the
// shared MAC addresses, but the switches must learn the new port. It runs
// after the gate opened, without waiting for an apply until it needs the
// document.
func (a *Agent) onTakeover() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	a.announce(ctx)
	// Its own context: this function returns first.
	go func() {
		time.Sleep(haAnnounceAgain)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		a.announce(ctx)
	}()

	a.mu.Lock()
	doc := a.applied
	a.mu.Unlock()
	if doc == nil {
		return
	}
	exp := doc.Expand()
	for i := range exp.Instances {
		in := &exp.Instances[i]
		for _, ifc := range in.Interfaces {
			if ifc.IPv4Mode == fwconfig.ModeDHCP && ifc.Enabled {
				a.dhcp.Takeover(in.Name, ifc.Name)
			}
		}
		// radvd sends an advertisement when it reloads.
		if len(in.RA) > 0 {
			if _, err := a.bg.Run(ctx, "", "systemctl", "reload-or-restart", a.cfg.Units.Radvd(in)); err != nil {
				slog.Warn("ha: takeover: radvd", "instance", in.Name, "err", err)
			}
		}
		// BGP would otherwise wait for its connect retry timer.
		if in.BGP != nil {
			if _, err := a.vtysh(ctx, in)("clear bgp *"); err != nil {
				slog.Warn("ha: takeover: BGP", "instance", in.Name, "err", err)
			}
		}
	}
}

// announce sends a gratuitous ARP and an unsolicited neighbour
// advertisement for each address of the host's interfaces but its own two
// links, in every namespace with a gate.
func (a *Agent) announce(ctx context.Context) {
	skip := a.ha.ownLinks()
	for _, ns := range a.gate.namespaces() {
		out, err := a.bg.Run(ctx, ns, "ip", "-j", "addr", "show")
		if err != nil {
			slog.Warn("ha: announce", "netns", ns, "err", err)
			continue
		}
		links, err := parseLinks(out)
		if err != nil {
			continue
		}
		err = withNetns(ns, func() error {
			for _, l := range links {
				if skip[l.Ifname] || l.Ifname == "lo" || !l.up() || l.Address == "" {
					continue
				}
				announceLink(l)
			}
			return nil
		})
		if err != nil {
			slog.Warn("ha: announce", "netns", ns, "err", err)
		}
	}
}

// announceLink sends the frames of one interface; the namespace is
// entered.
func announceLink(l ipLink) {
	mac, err := net.ParseMAC(l.Address)
	if err != nil || len(mac) != 6 {
		return
	}
	ifi, err := net.InterfaceByName(l.Ifname)
	if err != nil {
		return
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		slog.Warn("ha: announce", "interface", l.Ifname, "err", err)
		return
	}
	defer unix.Close(fd)
	for _, addr := range l.AddrInfo {
		ip, err := netip.ParseAddr(addr.Local)
		if err != nil || addr.Scope == "host" {
			continue
		}
		var frame []byte
		var dst [6]byte
		if ip.Is4() {
			frame, dst = garpFrame(mac, ip), [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		} else {
			frame, dst = naFrame(mac, ip), [6]byte{0x33, 0x33, 0, 0, 0, 1}
		}
		sa := &unix.SockaddrLinklayer{Ifindex: ifi.Index, Halen: 6}
		copy(sa.Addr[:], dst[:])
		if err := unix.Sendto(fd, frame, 0, sa); err != nil {
			slog.Warn("ha: announce", "interface", l.Ifname, "address", addr.Local, "err", err)
		}
	}
}

// garpFrame is a gratuitous ARP request: sender and target are ip.
func garpFrame(mac net.HardwareAddr, ip netip.Addr) []byte {
	f := make([]byte, 14+28)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], mac)
	binary.BigEndian.PutUint16(f[12:], unix.ETH_P_ARP)
	binary.BigEndian.PutUint16(f[14:], 1)             // Ethernet
	binary.BigEndian.PutUint16(f[16:], unix.ETH_P_IP) // IPv4
	f[18], f[19] = 6, 4                               // address lengths
	binary.BigEndian.PutUint16(f[20:], 1)             // request
	copy(f[22:28], mac)
	a := ip.As4()
	copy(f[28:32], a[:])
	copy(f[38:42], a[:])
	return f
}

// naFrame is an unsolicited neighbour advertisement for ip to all nodes,
// with the override flag and the target's link-layer address (RFC 4861
// section 7.2.6).
func naFrame(mac net.HardwareAddr, ip netip.Addr) []byte {
	const icmpLen = 32
	f := make([]byte, 14+40+icmpLen)
	copy(f[0:6], []byte{0x33, 0x33, 0, 0, 0, 1})
	copy(f[6:12], mac)
	binary.BigEndian.PutUint16(f[12:], unix.ETH_P_IPV6)
	ipv6 := f[14:54]
	ipv6[0] = 0x60
	binary.BigEndian.PutUint16(ipv6[4:], icmpLen)
	ipv6[6], ipv6[7] = unix.IPPROTO_ICMPV6, 255
	src, dst := ip.As16(), netip.MustParseAddr("ff02::1").As16()
	copy(ipv6[8:24], src[:])
	copy(ipv6[24:40], dst[:])
	icmp := f[54:]
	icmp[0] = 136  // neighbour advertisement
	icmp[4] = 0x20 // override
	copy(icmp[8:24], src[:])
	icmp[24], icmp[25] = 2, 1 // target link-layer address, 8 bytes
	copy(icmp[26:32], mac)
	binary.BigEndian.PutUint16(icmp[2:], icmp6Checksum(src, dst, icmp))
	return f
}

// icmp6Checksum is the ICMPv6 checksum over the pseudo header and data.
func icmp6Checksum(src, dst [16]byte, data []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for ; len(b) >= 2; b = b[2:] {
			sum += uint32(binary.BigEndian.Uint16(b))
		}
		if len(b) == 1 {
			sum += uint32(b[0]) << 8
		}
	}
	add(src[:])
	add(dst[:])
	sum += uint32(len(data)) + unix.IPPROTO_ICMPV6
	add(data)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
