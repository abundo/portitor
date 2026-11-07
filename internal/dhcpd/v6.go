// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcpd

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
)

// DHCPv6 (RFC 8415), stateful addresses (IA_NA) and stateless
// configuration, for directly connected clients. Leases are by DUID and
// IAID. A reservation is by MAC, which DHCPv6 doesn't carry: it is taken
// from the neighbour table, then from a DUID of type 1 or 3, then from an
// EUI-64 link-local source address.

// client6 is who a DHCPv6 request is from.
type client6 struct {
	duid string
	iaid uint32
}

func (c client6) owns(l *Lease) bool {
	return !l.Declined && l.ClientID == c.duid && l.IAID == c.iaid
}

func (c client6) key() string {
	return "duid:" + c.duid + "/" + hex.EncodeToString([]byte{byte(c.iaid >> 24), byte(c.iaid >> 16), byte(c.iaid >> 8), byte(c.iaid)})
}

// serverDUID is the config's DUID.
func (s *Server) serverDUID() dhcpv6.DUID {
	b, err := hex.DecodeString(s.cfg.DUID)
	if err != nil || len(b) < 2 {
		return nil
	}
	d, err := dhcpv6.DUIDFromBytes(b)
	if err != nil {
		return &dhcpv6.DUIDOpaque{Type: dhcpv6.DUIDType(uint16(b[0])<<8 | uint16(b[1])), Data: b[2:]}
	}
	return d
}

func (s *Server) subnets6(ifname string) []*Subnet6 {
	var out []*Subnet6
	for i := range s.cfg.Subnets6 {
		if s.cfg.Subnets6[i].Interface == ifname {
			out = append(out, &s.cfg.Subnets6[i])
		}
	}
	return out
}

func subnet6Of(subs []*Subnet6, a netip.Addr) *Subnet6 {
	for _, s := range subs {
		if s.Prefix.Contains(a) {
			return s
		}
	}
	return nil
}

func inPool6(sub *Subnet6, a netip.Addr) bool {
	if a == sub.Prefix.Masked().Addr() {
		return false
	}
	for _, r := range sub.Pools {
		if r.Contains(a) {
			return true
		}
	}
	return false
}

// NeedsMAC6 says whether a request on ifname needs the client's MAC
// address: only when a subnet there has reservations.
func (s *Server) NeedsMAC6(ifname string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sub := range s.subnets6(ifname) {
		if len(sub.Reservations) > 0 {
			return true
		}
	}
	return false
}

// MACFromDUID is the MAC address in a DUID of type 1 (LLT) or 3 (LL) of
// an Ethernet interface, nil for others.
func MACFromDUID(d []byte) net.HardwareAddr {
	switch {
	case len(d) == 14 && d[0] == 0 && d[1] == 1 && d[2] == 0 && d[3] == 1:
		return net.HardwareAddr(bytes.Clone(d[8:14]))
	case len(d) == 10 && d[0] == 0 && d[1] == 3 && d[2] == 0 && d[3] == 1:
		return net.HardwareAddr(bytes.Clone(d[4:10]))
	}
	return nil
}

// MACFromEUI64 is the MAC address in an EUI-64 link-local address, nil
// for another (a random or stable private one).
func MACFromEUI64(a netip.Addr) net.HardwareAddr {
	if !a.Is6() || !a.IsLinkLocalUnicast() {
		return nil
	}
	b := a.As16()
	if b[11] != 0xff || b[12] != 0xfe {
		return nil
	}
	return net.HardwareAddr{b[8] ^ 2, b[9], b[10], b[13], b[14], b[15]}
}

func (s *Server) reservation6(subs []*Subnet6, mac string) *Reservation {
	if mac == "" {
		return nil
	}
	for _, sub := range subs {
		for i := range sub.Reservations {
			if strings.EqualFold(sub.Reservations[i].MAC, mac) {
				return &sub.Reservations[i]
			}
		}
	}
	return nil
}

func reservedTo6(subs []*Subnet6, a netip.Addr) string {
	for _, sub := range subs {
		for _, r := range sub.Reservations {
			if r.Addr == a {
				return strings.ToLower(r.MAC)
			}
		}
	}
	return ""
}

func (s *Server) free6(subs []*Subnet6, c client6, mac string, a netip.Addr, now time.Time) bool {
	if m := reservedTo6(subs, a); m != "" && m != strings.ToLower(mac) {
		return false
	}
	if l := s.store.Get(a); l != nil && l.Valid(now) && !c.owns(l) {
		return false
	}
	if h, ok := s.offers[a]; ok && h.until.After(now) && h.client != c.key() {
		return false
	}
	return true
}

// allocate6 picks an address as allocate does, without the check.
func (s *Server) allocate6(subs []*Subnet6, c client6, mac string, hint netip.Addr, now time.Time) netip.Addr {
	if r := s.reservation6(subs, mac); r != nil {
		if s.free6(subs, c, mac, r.Addr, now) {
			return r.Addr
		}
		return netip.Addr{}
	}
	var mine *Lease
	s.store.Each(func(l *Lease) bool {
		if l.Addr.Is6() && c.owns(l) && subnet6Of(subs, l.Addr) != nil && (mine == nil || l.Expires > mine.Expires) {
			mine = l
		}
		return true
	})
	if mine != nil {
		if sub := subnet6Of(subs, mine.Addr); inPool6(sub, mine.Addr) && s.free6(subs, c, mac, mine.Addr, now) {
			return mine.Addr
		}
	}
	if sub := subnet6Of(subs, hint); sub != nil && inPool6(sub, hint) && s.free6(subs, c, mac, hint, now) {
		return hint
	}
	var expired []*Lease
	for _, sub := range subs {
		for _, p := range sub.Pools {
			n := 0
			for a := p.Start; a.IsValid() && a.Compare(p.End) <= 0 && n < maxPoolSearch; a, n = a.Next(), n+1 {
				if !inPool6(sub, a) {
					continue
				}
				if l := s.store.Get(a); l != nil {
					if !l.Valid(now) {
						expired = append(expired, l)
					}
					continue
				}
				if s.free6(subs, c, mac, a, now) {
					return a
				}
			}
		}
	}
	var best *Lease
	for _, l := range expired {
		if (best == nil || l.Expires < best.Expires) && s.free6(subs, c, mac, l.Addr, now) {
			best = l
		}
	}
	if best != nil {
		return best.Addr
	}
	return netip.Addr{}
}

// times6 are the lifetimes: valid, preferred, T1, T2.
func (s *Server) times6() (valid, preferred, t1, t2 time.Duration) {
	v := time.Duration(s.cfg.LeaseTime) * time.Second
	return v, v * 3 / 4, v / 2, v * 4 / 5
}

// Handle6 answers a DHCPv6 message from src on ifname; mac is the
// client's MAC address as far as known.
func (s *Server) Handle6(ifname string, msg *dhcpv6.Message, src netip.AddrPort, mac string) *dhcpv6.Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.waitFor = 0
	return s.answer6(ifname, msg, src, mac)
}

// Serve6 is Handle6 for a client: a reply with a new binding waits until
// the standby has it, for at most ackWait.
func (s *Server) Serve6(ifname string, msg *dhcpv6.Message, src netip.AddrPort, mac string) *dhcpv6.Message {
	s.mu.Lock()
	s.waitFor = 0
	r := s.answer6(ifname, msg, src, mac)
	seq := s.waitFor
	s.mu.Unlock()
	if r != nil {
		s.waitAck(seq)
	}
	return r
}

func (s *Server) answer6(ifname string, msg *dhcpv6.Message, src netip.AddrPort, mac string) *dhcpv6.Message {
	subs := s.subnets6(ifname)
	sid := s.serverDUID()
	if len(subs) == 0 || sid == nil {
		return nil
	}
	cid := msg.Options.ClientID()
	theirs := msg.Options.ServerID()
	switch msg.MessageType {
	case dhcpv6.MessageTypeSolicit, dhcpv6.MessageTypeRebind, dhcpv6.MessageTypeConfirm:
		// Sent to all servers: one naming a server is broken.
		if theirs != nil || cid == nil {
			return nil
		}
	case dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline:
		if cid == nil || theirs == nil || !theirs.Equal(sid) {
			return nil
		}
	case dhcpv6.MessageTypeInformationRequest:
		if theirs != nil && !theirs.Equal(sid) {
			return nil
		}
	default:
		return nil
	}
	typ := dhcpv6.MessageTypeReply
	if msg.MessageType == dhcpv6.MessageTypeSolicit {
		typ = dhcpv6.MessageTypeAdvertise
	}
	r, err := dhcpv6.NewMessage()
	if err != nil {
		return nil
	}
	r.MessageType = typ
	r.TransactionID = msg.TransactionID
	r.Options.Add(dhcpv6.OptServerID(sid))
	if cid != nil {
		r.Options.Add(dhcpv6.OptClientID(cid))
	}
	now := s.now()
	var duid string
	if cid != nil {
		duid = hex.EncodeToString(cid.ToBytes())
	}
	if mac == "" && cid != nil {
		if m := MACFromDUID(cid.ToBytes()); m != nil {
			mac = m.String()
		} else if m := MACFromEUI64(src.Addr().WithZone("")); m != nil {
			mac = m.String()
		}
	}

	switch msg.MessageType {
	case dhcpv6.MessageTypeSolicit, dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind:
		bind := msg.MessageType != dhcpv6.MessageTypeSolicit
		for _, ia := range msg.Options.IANA() {
			r.Options.Add(s.answerIA(subs, client6{duid, binaryIAID(ia.IaId)}, mac, ia, msg.MessageType, bind, now))
		}
	case dhcpv6.MessageTypeConfirm:
		code := iana.StatusSuccess
		for _, ia := range msg.Options.IANA() {
			for _, a := range ia.Options.Addresses() {
				if addr, ok := netip.AddrFromSlice(a.IPv6Addr); !ok || subnet6Of(subs, addr) == nil {
					code = iana.StatusNotOnLink
				}
			}
		}
		r.Options.Add(&dhcpv6.OptStatusCode{StatusCode: code})
	case dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline:
		for _, ia := range msg.Options.IANA() {
			c := client6{duid, binaryIAID(ia.IaId)}
			for _, a := range ia.Options.Addresses() {
				addr, _ := netip.AddrFromSlice(a.IPv6Addr)
				l := s.store.Get(addr)
				if l == nil || !l.Valid(now) || !c.owns(l) {
					continue
				}
				e := *l
				if msg.MessageType == dhcpv6.MessageTypeDecline {
					e.Declined = true
					e.Expires = now.Add(declineHold).Unix()
					slog.Warn("dhcpv6: address declined", "interface", ifname, "address", addr)
				} else {
					e.Expires = now.Unix()
				}
				s.put(e, false, false)
			}
		}
		r.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusSuccess})
	}
	// Configuration: the DNS servers of the interface's first subnet with
	// some, and the domain.
	for _, sub := range subs {
		if len(sub.DNS) > 0 {
			var ips []net.IP
			for _, a := range sub.DNS {
				ips = append(ips, net.IP(a.AsSlice()))
			}
			r.Options.Add(dhcpv6.OptDNS(ips...))
			break
		}
	}
	if s.cfg.Domain != "" {
		r.Options.Add(dhcpv6.OptDomainSearchList(&rfc1035label.Labels{Labels: []string{s.cfg.Domain}}))
	}
	return r
}

func binaryIAID(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// answerIA answers one IA_NA: an address for it, offered (bind false) or
// bound. A renewal keeps the client's address while it may have it, the
// store knowing it or not (after a failover the record may not have
// reached this host); an address it may not keep is sent back with
// lifetimes 0, and it gets another.
func (s *Server) answerIA(subs []*Subnet6, c client6, mac string, ia *dhcpv6.OptIANA, typ dhcpv6.MessageType, bind bool, now time.Time) *dhcpv6.OptIANA {
	valid, pref, t1, t2 := s.times6()
	out := &dhcpv6.OptIANA{IaId: ia.IaId, T1: t1, T2: t2}
	var asked []netip.Addr
	for _, a := range ia.Options.Addresses() {
		if addr, ok := netip.AddrFromSlice(a.IPv6Addr); ok {
			asked = append(asked, addr.Unmap())
		}
	}
	res := s.reservation6(subs, mac)
	var got netip.Addr
	if typ == dhcpv6.MessageTypeRenew || typ == dhcpv6.MessageTypeRebind {
		for _, a := range asked {
			sub := subnet6Of(subs, a)
			ok := sub != nil && s.free6(subs, c, mac, a, now) &&
				(res != nil && res.Addr == a || res == nil && inPool6(sub, a))
			if ok && !got.IsValid() {
				got = a
				continue
			}
			out.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.IP(a.AsSlice())})
		}
	}
	if !got.IsValid() {
		var hint netip.Addr
		if len(asked) > 0 {
			hint = asked[0]
		}
		got = s.allocate6(subs, c, mac, hint, now)
	}
	if !got.IsValid() {
		out.T1, out.T2 = 0, 0
		out.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusNoAddrsAvail, StatusMessage: "no addresses available"})
		return out
	}
	if !bind {
		s.offers[got] = hold{client: c.key(), until: now.Add(offerHold)}
	} else {
		old := s.store.Get(got)
		fresh := old == nil || !old.Valid(now) || !c.owns(old)
		l := Lease{Addr: got, MAC: mac, ClientID: c.duid, IAID: c.iaid, Expires: now.Add(valid).Unix()}
		if res != nil {
			l.Hostname, _, _ = strings.Cut(strings.TrimSuffix(res.Hostname, "."), ".")
		}
		seq, err := s.put(l, fresh, fresh)
		if seq > s.waitFor {
			s.waitFor = seq
		}
		if err != nil {
			slog.Error("dhcpv6: lease not stored", "address", got, "err", err)
			out.T1, out.T2 = 0, 0
			out.Options.Add(&dhcpv6.OptStatusCode{StatusCode: iana.StatusUnspecFail})
			return out
		}
		delete(s.offers, got)
		var older []Lease
		s.store.Each(func(o *Lease) bool {
			if o.Addr != got && o.Addr.Is6() && o.Valid(now) && c.owns(o) && subnet6Of(subs, o.Addr) != nil {
				e := *o
				e.Expires = now.Unix()
				older = append(older, e)
			}
			return true
		})
		for _, e := range older {
			s.put(e, false, false)
		}
		if fresh {
			slog.Info("dhcpv6: lease", "interface", subs[0].Interface, "address", got, "duid", c.duid, "mac", mac)
		}
	}
	out.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.IP(got.AsSlice()), PreferredLifetime: pref, ValidLifetime: valid})
	return out
}
