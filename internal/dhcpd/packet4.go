// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcpd

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
)

// The DHCPv4 wire format (RFC 2131, 2132), read tolerantly and written the
// way clients expect, after Kea's and dnsmasq's handling of broken
// packets: a truncated option ends the options and keeps what came before,
// a missing End is accepted, repeated options are concatenated (RFC 3396),
// an empty hostname is dropped and a trailing NUL is cut off, and the
// overloaded file and sname fields (option 52) are read. A reply carries
// the message type first, is capped by the client's option 57 (576 bytes
// without) and padded to the BOOTP minimum of 300.

// DHCPv4 message types (option 53).
const (
	Discover = 1
	Offer    = 2
	Request  = 3
	Decline  = 4
	Ack      = 5
	Nak      = 6
	Release  = 7
	Inform   = 8
)

// Option codes.
const (
	optPad          = 0
	optSubnetMask   = 1
	optRouter       = 3
	optDNS          = 6
	optHostname     = 12
	optDomain       = 15
	optRequestedIP  = 50
	optLeaseTime    = 51
	optOverload     = 52
	optMessageType  = 53
	optServerID     = 54
	optParamRequest = 55
	optMessage      = 56
	optMaxSize      = 57
	optT1           = 58
	optT2           = 59
	optClientID     = 61
	optV6OnlyPref   = 108
	optEnd          = 255
)

const (
	bootRequest = 1
	bootReply   = 2
	// headerLen is the fixed part up to the magic cookie, which follows.
	headerLen = 236
	// minPacket is the smallest BOOTP message (RFC 951): replies are
	// padded to it, as some clients drop shorter ones.
	minPacket = 300
	// minMaxSize is the size every client takes (RFC 2131): the IP and
	// UDP headers, 28 bytes, come out of it.
	minMaxSize = 576
	ipUDPLen   = 28
)

var magic = [4]byte{99, 130, 83, 99}

// broadcastFlag is the B bit of flags.
const broadcastFlag = 0x8000

// Packet4 is a DHCPv4 message. Options keeps them by code, concatenated;
// Order is the order they are written in (a reply's), the rest after it.
type Packet4 struct {
	Op     byte
	HType  byte
	HLen   byte
	Hops   byte
	XID    uint32
	Secs   uint16
	Flags  uint16
	CIAddr netip.Addr
	YIAddr netip.Addr
	SIAddr netip.Addr
	GIAddr netip.Addr
	// CHAddr is the client's hardware address, HLen bytes of it.
	CHAddr  net.HardwareAddr
	Options map[byte][]byte
	Order   []byte
}

var errShort = errors.New("short packet")

// Parse4 reads a DHCPv4 message. Only a packet too short for the header
// and cookie, or without the cookie, is an error.
func Parse4(b []byte) (*Packet4, error) {
	if len(b) < headerLen+4 {
		return nil, errShort
	}
	if [4]byte(b[headerLen:headerLen+4]) != magic {
		return nil, errors.New("no DHCP magic cookie")
	}
	p := &Packet4{
		Op:      b[0],
		HType:   b[1],
		HLen:    b[2],
		Hops:    b[3],
		XID:     binary.BigEndian.Uint32(b[4:]),
		Secs:    binary.BigEndian.Uint16(b[8:]),
		Flags:   binary.BigEndian.Uint16(b[10:]),
		CIAddr:  netip.AddrFrom4([4]byte(b[12:16])),
		YIAddr:  netip.AddrFrom4([4]byte(b[16:20])),
		SIAddr:  netip.AddrFrom4([4]byte(b[20:24])),
		GIAddr:  netip.AddrFrom4([4]byte(b[24:28])),
		Options: map[byte][]byte{},
	}
	n := int(p.HLen)
	if n > 16 {
		n = 16
	}
	p.CHAddr = slices.Clone(b[28 : 28+n])
	readOptions(b[headerLen+4:], p.Options)
	// Option 52: the file field (1), sname (2) or both (3) hold more
	// options, read after the options field (RFC 2131 4.1).
	if ov := p.Options[optOverload]; len(ov) == 1 {
		if ov[0]&1 != 0 {
			readOptions(b[108:236], p.Options)
		}
		if ov[0]&2 != 0 {
			readOptions(b[44:108], p.Options)
		}
	}
	if h, ok := p.Options[optHostname]; ok {
		for len(h) > 0 && h[len(h)-1] == 0 {
			h = h[:len(h)-1]
		}
		if len(h) == 0 {
			delete(p.Options, optHostname)
		} else {
			p.Options[optHostname] = h
		}
	}
	return p, nil
}

// readOptions adds the options in b to opts, concatenating repeats. It
// stops at End, at the end of b, or at an option cut short, keeping what
// came before.
func readOptions(b []byte, opts map[byte][]byte) {
	for i := 0; i < len(b); {
		code := b[i]
		switch code {
		case optPad:
			i++
			continue
		case optEnd:
			return
		}
		if i+1 >= len(b) {
			return
		}
		n := int(b[i+1])
		if i+2+n > len(b) {
			return
		}
		opts[code] = append(opts[code], b[i+2:i+2+n]...)
		i += 2 + n
	}
}

// Type is the message type, 0 without one.
func (p *Packet4) Type() byte {
	if t := p.Options[optMessageType]; len(t) == 1 {
		return t[0]
	}
	return 0
}

// Addr is an option holding one IPv4 address.
func (p *Packet4) Addr(code byte) netip.Addr {
	if v := p.Options[code]; len(v) == 4 {
		return netip.AddrFrom4([4]byte(v))
	}
	return netip.Addr{}
}

// Uint32 is a 4-byte option, and whether it is there.
func (p *Packet4) Uint32(code byte) (uint32, bool) {
	if v := p.Options[code]; len(v) == 4 {
		return binary.BigEndian.Uint32(v), true
	}
	return 0, false
}

// Requested says whether the client asked for the option (option 55).
func (p *Packet4) Requested(code byte) bool {
	return slices.Contains(p.Options[optParamRequest], code)
}

// MaxSize is the largest reply the client takes, the IP and UDP headers
// included.
func (p *Packet4) MaxSize() int {
	if v := p.Options[optMaxSize]; len(v) == 2 {
		if n := int(binary.BigEndian.Uint16(v)); n > minMaxSize {
			return n
		}
	}
	return minMaxSize
}

// Set adds an option to be written in this order.
func (p *Packet4) Set(code byte, v []byte) {
	if p.Options == nil {
		p.Options = map[byte][]byte{}
	}
	if _, ok := p.Options[code]; !ok {
		p.Order = append(p.Order, code)
	}
	p.Options[code] = v
}

// SetAddrs sets an option of IPv4 addresses.
func (p *Packet4) SetAddrs(code byte, addrs ...netip.Addr) {
	var v []byte
	for _, a := range addrs {
		if a.Is4() {
			b := a.As4()
			v = append(v, b[:]...)
		}
	}
	if len(v) > 0 {
		p.Set(code, v)
	}
}

// SetUint32 sets a 4-byte option.
func (p *Packet4) SetUint32(code byte, n uint32) {
	p.Set(code, binary.BigEndian.AppendUint32(nil, n))
}

// Marshal writes the message, no larger than max bytes with the IP and
// UDP headers: options that don't fit are left out, the message type and
// server id never. It is padded to minPacket.
func (p *Packet4) Marshal(max int) []byte {
	if max < minMaxSize {
		max = minMaxSize
	}
	b := make([]byte, headerLen, minPacket)
	b[0], b[1], b[2], b[3] = p.Op, p.HType, p.HLen, p.Hops
	binary.BigEndian.PutUint32(b[4:], p.XID)
	binary.BigEndian.PutUint16(b[8:], p.Secs)
	binary.BigEndian.PutUint16(b[10:], p.Flags)
	for i, a := range []netip.Addr{p.CIAddr, p.YIAddr, p.SIAddr, p.GIAddr} {
		if a.Is4() {
			v := a.As4()
			copy(b[12+4*i:], v[:])
		}
	}
	copy(b[28:44], p.CHAddr)
	b = append(b, magic[:]...)
	limit := max - ipUDPLen - 1 // End
	order := slices.Clone(p.Order)
	var rest []byte
	for c := range p.Options {
		if !slices.Contains(order, c) {
			rest = append(rest, c)
		}
	}
	slices.Sort(rest)
	order = append(order, rest...)
	// The message type first: some clients look for it there.
	if i := slices.Index(order, optMessageType); i > 0 {
		order = append([]byte{optMessageType}, slices.Delete(order, i, i+1)...)
	}
	for _, c := range order {
		if c == optPad || c == optEnd {
			continue
		}
		enc := encodeOption(c, p.Options[c])
		if len(b)+len(enc) > limit && c != optMessageType && c != optServerID {
			continue
		}
		b = append(b, enc...)
	}
	b = append(b, optEnd)
	for len(b) < minPacket {
		b = append(b, optPad)
	}
	return b
}

// encodeOption writes an option, split into pieces of 255 bytes when
// longer (RFC 3396).
func encodeOption(code byte, v []byte) []byte {
	if len(v) == 0 {
		return []byte{code, 0}
	}
	var out []byte
	for len(v) > 0 {
		n := min(len(v), 255)
		out = append(out, code, byte(n))
		out = append(out, v[:n]...)
		v = v[n:]
	}
	return out
}
