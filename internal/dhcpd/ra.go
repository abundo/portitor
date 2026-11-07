// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcpd

// IPv6 router advertisements (RFC 4861), sent by the same process as the
// DHCP server: the message and the timing are pure functions here, the
// sockets in rarun.go.

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"time"
)

// RAConfig makes the server advertise the instance as the default router
// on Interface.
type RAConfig struct {
	Interface string `json:"interface"`
	// Managed (M flag): addresses from DHCPv6. Other (O flag): other
	// settings from DHCPv6.
	Managed  bool       `json:"managed,omitempty"`
	Other    bool       `json:"other,omitempty"`
	Prefixes []RAPrefix `json:"prefixes,omitempty"`
	// RDNSS and DNSSL: DNS servers and search domains (RFC 8106).
	RDNSS []netip.Addr `json:"rdnss,omitempty"`
	DNSSL []string     `json:"dnssl,omitempty"`
	// NAT64 is the PREF64 option's prefix (RFC 8781).
	NAT64 netip.Prefix `json:"nat64,omitzero"`
}

// RAPrefix is an on-link prefix; Autonomous lets clients configure their
// own addresses in it (SLAAC).
type RAPrefix struct {
	Prefix     netip.Prefix `json:"prefix"`
	Autonomous bool         `json:"autonomous,omitempty"`
}

// The protocol's constants (RFC 4861 section 10) and radvd's defaults.
const (
	raMaxInterval        = 600 * time.Second
	raMinInterval        = 198 * time.Second // 0.33 × raMaxInterval
	raInitialCount       = 3                 // MAX_INITIAL_RTR_ADVERTISEMENTS
	raMaxInitialInterval = 16 * time.Second  // MAX_INITIAL_RTR_ADVERT_INTERVAL
	raMinDelay           = 3 * time.Second   // MIN_DELAY_BETWEEN_RAS
	raMaxReplyDelay      = 500 * time.Millisecond
	raCurHopLimit        = 64
	raRouterLifetime     = 1800 // s, 3 × raMaxInterval
	raValidLifetime      = 86400
	raPreferredLifetime  = 14400
	// RFC 8106 asks for at least 3 × raMaxInterval; PREF64 takes the same.
	raDNSLifetime = 1800
	// raDeprecate is how long a prefix taken out of the config is still
	// advertised, with a preferred lifetime of 0, so clients stop using
	// their addresses in it (a new delegated prefix, RFC 8978). Clients
	// lower its valid lifetime to two hours (RFC 4862 5.5.3 e).
	raDeprecate = 2 * time.Hour
)

const (
	icmpRouterSolicitation  = 133
	icmpRouterAdvertisement = 134

	optSourceLLA = 1
	optPrefix    = 3
	optRDNSS     = 25
	optDNSSL     = 31
	optPREF64    = 38
)

// gonePrefix is a prefix taken out of the config, advertised as
// deprecated until its deadline.
type gonePrefix struct {
	Prefix netip.Prefix
	Until  time.Time
}

// marshalRA is the advertisement for c, sent from an interface with the
// MAC address mac (nil leaves the source link-layer option out). final
// is the last one, as the interface stops advertising: router lifetime
// 0 and every lifetime 0. The checksum is left to the kernel (RFC 3542).
func marshalRA(c *RAConfig, mac net.HardwareAddr, gone []gonePrefix, now time.Time, final bool) []byte {
	b := make([]byte, 16, 256)
	b[0] = icmpRouterAdvertisement
	b[4] = raCurHopLimit
	if c.Managed {
		b[5] |= 0x80
	}
	if c.Other {
		b[5] |= 0x40
	}
	life := func(v uint32) uint32 {
		if final {
			return 0
		}
		return v
	}
	binary.BigEndian.PutUint16(b[6:], uint16(life(raRouterLifetime)))
	// Reachable time and retrans timer: 0, unspecified.
	if len(mac) == 6 {
		b = append(b, optSourceLLA, 1)
		b = append(b, mac...)
	}
	for _, p := range c.Prefixes {
		b = appendPrefix(b, p.Prefix, p.Autonomous, life(raValidLifetime), life(raPreferredLifetime))
	}
	for _, g := range gone {
		left := g.Until.Sub(now)
		if left <= 0 {
			continue
		}
		b = appendPrefix(b, g.Prefix, true, life(uint32(left/time.Second)), 0)
	}
	if len(c.RDNSS) > 0 {
		b = append(b, optRDNSS, byte(1+2*len(c.RDNSS)), 0, 0)
		b = binary.BigEndian.AppendUint32(b, life(raDNSLifetime))
		for _, a := range c.RDNSS {
			a16 := a.As16()
			b = append(b, a16[:]...)
		}
	}
	if len(c.DNSSL) > 0 {
		var names []byte
		for _, d := range c.DNSSL {
			names = appendDomain(names, d)
		}
		for (8+len(names))%8 != 0 {
			names = append(names, 0)
		}
		b = append(b, optDNSSL, byte((8+len(names))/8), 0, 0)
		b = binary.BigEndian.AppendUint32(b, life(raDNSLifetime))
		b = append(b, names...)
	}
	if plc, ok := pref64PLC(c.NAT64.Bits()); ok && c.NAT64.Addr().Is6() {
		// Lifetime in units of 8 s, at most 8191, in the top 13 bits.
		scaled := min((life(raDNSLifetime)+7)/8, 8191)
		b = append(b, optPREF64, 2)
		b = binary.BigEndian.AppendUint16(b, uint16(scaled<<3|plc))
		a16 := c.NAT64.Addr().As16()
		b = append(b, a16[:12]...)
	}
	return b
}

// appendPrefix appends a prefix information option, on-link.
func appendPrefix(b []byte, p netip.Prefix, autonomous bool, valid, preferred uint32) []byte {
	flags := byte(0x80)
	if autonomous {
		flags |= 0x40
	}
	b = append(b, optPrefix, 4, byte(p.Bits()), flags)
	b = binary.BigEndian.AppendUint32(b, valid)
	b = binary.BigEndian.AppendUint32(b, preferred)
	b = append(b, 0, 0, 0, 0)
	a16 := p.Masked().Addr().As16()
	return append(b, a16[:]...)
}

// appendDomain appends a domain name in DNS wire format (labels checked
// by fwconfig's validation).
func appendDomain(b []byte, d string) []byte {
	for _, l := range strings.Split(strings.TrimSuffix(d, "."), ".") {
		if l == "" || len(l) > 63 {
			continue
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

// pref64PLC is RFC 8781's prefix length code.
func pref64PLC(bits int) (uint32, bool) {
	switch bits {
	case 96:
		return 0, true
	case 64:
		return 1, true
	case 56:
		return 2, true
	case 48:
		return 3, true
	case 40:
		return 4, true
	case 32:
		return 5, true
	}
	return 0, false
}

// validRS checks a router solicitation (RFC 4861 6.1.1) received with
// hop limit hops from src; the kernel has checked the ICMPv6 checksum.
func validRS(msg []byte, hops int, src netip.Addr) bool {
	if hops != 255 || len(msg) < 8 || msg[0] != icmpRouterSolicitation || msg[1] != 0 {
		return false
	}
	for o := msg[8:]; len(o) > 0; {
		if len(o) < 2 || o[1] == 0 || int(o[1])*8 > len(o) {
			return false
		}
		// One from the unspecified address carries no link-layer address.
		if o[0] == optSourceLLA && src.IsUnspecified() {
			return false
		}
		o = o[int(o[1])*8:]
	}
	return true
}

// raSched decides when an interface's advertisements go out: unsolicited
// ones to all nodes at a random interval (the first raInitialCount sooner),
// and replies to solicitations after a random delay, to the solicitor or,
// when several asked, to all nodes. Multicast ones are at least raMinDelay
// apart.
type raSched struct {
	initial   int
	next      time.Time
	lastMcast time.Time
	// reply is when a solicitation is answered (zero: none), to replyTo
	// (invalid: all nodes).
	reply   time.Time
	replyTo netip.Addr
}

// burst starts over with the initial advertisements, the first at once:
// a new config, the interface come up, an HA takeover.
func (s *raSched) burst(now time.Time) {
	s.initial = raInitialCount
	s.next = now
}

// solicit takes a solicitation from src, answered after delay.
func (s *raSched) solicit(now time.Time, src netip.Addr, delay time.Duration) {
	dst := src.WithZone("")
	if !dst.IsValid() || dst.IsUnspecified() {
		dst = netip.Addr{}
	}
	if !s.reply.IsZero() {
		if s.replyTo != dst {
			s.replyTo = netip.Addr{}
		}
		return
	}
	s.reply, s.replyTo = now.Add(delay), dst
}

func (s *raSched) mcastAt(t time.Time) time.Time {
	if m := s.lastMcast.Add(raMinDelay); !s.lastMcast.IsZero() && m.After(t) {
		return m
	}
	return t
}

func (s *raSched) replyAt() time.Time {
	if s.replyTo.IsValid() {
		return s.reply
	}
	return s.mcastAt(s.reply)
}

// wake is when due has something to send.
func (s *raSched) wake() time.Time {
	t := s.mcastAt(s.next)
	if !s.reply.IsZero() && s.replyAt().Before(t) {
		t = s.replyAt()
	}
	return t
}

// due says what to send now: to all nodes, and/or to one solicitor. The
// caller reports a multicast one with sent.
func (s *raSched) due(now time.Time) (mcast bool, ucast netip.Addr) {
	if !s.reply.IsZero() && !now.Before(s.replyAt()) {
		if s.replyTo.IsValid() {
			ucast = s.replyTo
		} else {
			mcast = true
		}
		s.reply = time.Time{}
	}
	if !now.Before(s.mcastAt(s.next)) {
		mcast = true
	}
	if mcast {
		// It answers a pending solicitation too.
		s.reply = time.Time{}
	}
	return mcast, ucast
}

// sent records the multicast advertisement due asked for: ok, the next
// after interval (shortened while initial ones remain); failed (no
// usable link-local address yet), again in a second.
func (s *raSched) sent(now time.Time, ok bool, interval time.Duration) {
	if !ok {
		s.next = now.Add(time.Second)
		return
	}
	s.lastMcast = now
	if s.initial > 0 {
		s.initial--
	}
	if s.initial > 0 && interval > raMaxInitialInterval {
		interval = raMaxInitialInterval
	}
	s.next = now.Add(interval)
}

// deprecate updates the prefixes advertised as deprecated when the config
// changes from old to cur.
func deprecate(gone []gonePrefix, old, cur *RAConfig, now time.Time) []gonePrefix {
	in := func(c *RAConfig, p netip.Prefix) bool {
		if c == nil {
			return false
		}
		for _, q := range c.Prefixes {
			if q.Prefix.Masked() == p.Masked() {
				return true
			}
		}
		return false
	}
	var out []gonePrefix
	for _, g := range gone {
		if g.Until.After(now) && !in(cur, g.Prefix) {
			out = append(out, g)
		}
	}
	if old != nil {
		for _, p := range old.Prefixes {
			if !in(cur, p.Prefix) && p.Autonomous {
				out = append(out, gonePrefix{Prefix: p.Prefix, Until: now.Add(raDeprecate)})
			}
		}
	}
	return out
}
