// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcpd

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// probeWait is how long an address check waits for an answer.
const probeWait = 300 * time.Millisecond

// arpProbe asks on ifname who has a (an ARP probe, RFC 5227: sender
// address 0, so no one's cache learns anything) and returns the MAC
// address that answered, nil for none. It needs CAP_NET_RAW; an interface
// without ARP, or an error, reads as no answer.
func arpProbe(ifname string, a netip.Addr) net.HardwareAddr {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil || len(ifi.HardwareAddr) != 6 || ifi.Flags&net.FlagLoopback != 0 || !a.Is4() {
		return nil
	}
	proto := htons(unix.ETH_P_ARP)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(proto))
	if err != nil {
		return nil
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index}); err != nil {
		return nil
	}
	target := a.As4()
	req := make([]byte, 28)
	binary.BigEndian.PutUint16(req[0:], 1)      // Ethernet
	binary.BigEndian.PutUint16(req[2:], 0x0800) // IPv4
	req[4], req[5] = 6, 4
	binary.BigEndian.PutUint16(req[6:], 1) // request
	copy(req[8:14], ifi.HardwareAddr)
	copy(req[24:28], target[:])
	to := &unix.SockaddrLinklayer{Protocol: proto, Ifindex: ifi.Index, Halen: 6, Addr: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}
	if err := unix.Sendto(fd, req, 0, to); err != nil {
		return nil
	}
	deadline := time.Now().Add(probeWait)
	buf := make([]byte, 128)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return nil
		}
		tv := unix.NsecToTimeval(left.Nanoseconds())
		unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return nil
		}
		// A reply (2) from the address: someone has it.
		if n >= 28 && binary.BigEndian.Uint16(buf[6:]) == 2 && [4]byte(buf[14:18]) == target {
			return net.HardwareAddr(append([]byte(nil), buf[8:14]...))
		}
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
