// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcpd

import (
	"encoding/hex"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Server answers DHCPv4 and DHCPv6 requests from its config and store.
// Its handlers are pure but for the store, the clock and the address
// check, so the packet tests drive them directly.
type Server struct {
	mu    sync.Mutex
	cfg   *Config
	store *Store
	now   func() time.Time
	// jitter returns a random duration in [0, n).
	jitter func(n int64) int64
	// probe returns the MAC address that answers for an address on the
	// interface (ARP), nil for none; a nil probe checks nothing.
	probe func(ifname string, a netip.Addr) net.HardwareAddr
	// offers hold addresses offered to a client for a while, so another
	// client isn't offered the same one.
	offers map[netip.Addr]hold
	// conflicts are addresses found in use by a check.
	conflicts map[netip.Addr]time.Time
	// probed counts the checks of the current second, which stop under
	// load.
	probed   int
	probedAt int64
	// r is the replication to an HA pair's standby (repl.go); waitFor is
	// the change the current reply waits for.
	r       repl
	waitFor uint64
}

type hold struct {
	client string
	until  time.Time
}

const (
	minLease      = 120
	offerHold     = time.Minute
	conflictHold  = 10 * time.Minute
	declineHold   = 24 * time.Hour
	maxProbesSec  = 5
	maxPoolSearch = 1 << 16
)

// NewServer serves cfg from store.
func NewServer(cfg *Config, store *Store) *Server {
	return &Server{
		cfg:       cfg,
		store:     store,
		now:       time.Now,
		jitter:    func(n int64) int64 { return rand.Int64N(n) },
		offers:    map[netip.Addr]hold{},
		conflicts: map[netip.Addr]time.Time{},
		r:         newRepl(),
	}
}

// SetConfig replaces the config; leases and holds stay.
func (s *Server) SetConfig(cfg *Config) {
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
}

// Leases is every lease in the store.
func (s *Server) Leases() []Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.All()
}

// Flush writes the store's pending lines to disk.
func (s *Server) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.Flush()
}

// client4 is who a DHCPv4 request is from: its client id (option 61) and
// MAC address.
type client4 struct {
	id  string
	mac string
}

func (c client4) key() string {
	if c.id != "" {
		return "id:" + c.id
	}
	return "mac:" + c.mac
}

// owns says whether a lease is the client's: by client id when both have
// one, else by MAC, so a client that stops sending its id keeps its
// lease (and the lease its id).
func (c client4) owns(l *Lease) bool {
	if l.Declined {
		return false
	}
	if c.id != "" && l.ClientID != "" {
		return c.id == l.ClientID
	}
	return c.mac != "" && c.mac == l.MAC
}

// Handle4 answers a DHCPv4 request that came in on ifname from src: the
// reply and where it goes, or nil.
func (s *Server) Handle4(ifname string, req *Packet4, src netip.AddrPort) (*Packet4, netip.AddrPort) {
	r, dst, _ := s.handle4(ifname, req, src)
	return r, dst
}

// Serve4 is Handle4 for a client: a reply to a new binding waits until the
// standby has it, for at most ackWait.
func (s *Server) Serve4(ifname string, req *Packet4, src netip.AddrPort) (*Packet4, netip.AddrPort) {
	r, dst, seq := s.handle4(ifname, req, src)
	if r != nil {
		s.waitAck(seq)
	}
	return r, dst
}

func (s *Server) handle4(ifname string, req *Packet4, src netip.AddrPort) (*Packet4, netip.AddrPort, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.waitFor = 0
	r, dst := s.answer4(ifname, req, src)
	return r, dst, s.waitFor
}

func (s *Server) answer4(ifname string, req *Packet4, src netip.AddrPort) (*Packet4, netip.AddrPort) {
	if req.Op != bootRequest || req.HLen == 0 || req.HLen > 16 {
		return nil, netip.AddrPort{}
	}
	// Only directly connected clients: Portitor runs no relays.
	if req.GIAddr.IsValid() && !req.GIAddr.IsUnspecified() {
		return nil, netip.AddrPort{}
	}
	var subs []*Subnet4
	for i := range s.cfg.Subnets4 {
		if s.cfg.Subnets4[i].Interface == ifname {
			subs = append(subs, &s.cfg.Subnets4[i])
		}
	}
	if len(subs) == 0 {
		return nil, netip.AddrPort{}
	}
	c := client4{mac: net.HardwareAddr(req.CHAddr).String()}
	if id := req.Options[optClientID]; len(id) > 0 {
		c.id = hex.EncodeToString(id)
	}
	// ciaddr means nothing in a DISCOVER, nor beside a requested address
	// (some clients fill it in anyway), and a reply would go there.
	if req.Type() == Discover || req.Type() == Request && req.Addr(optRequestedIP).IsValid() {
		req.CIAddr = netip.AddrFrom4([4]byte{})
	}
	now := s.now()
	var r *Packet4
	switch req.Type() {
	case Discover:
		r = s.discover(subs, c, req, now)
	case Request:
		r = s.request(subs, c, req, now)
	case Decline:
		s.decline(subs, c, req, now)
	case Release:
		s.release(subs, c, req, now)
	case Inform:
		r = s.inform(subs, req, src)
	}
	if r == nil {
		return nil, netip.AddrPort{}
	}
	return r, destination4(req, r, src)
}

// destination4 is where a reply goes (RFC 2131 4.1): a NAK and a reply to
// a client without an address are broadcast, the rest goes to ciaddr; an
// INFORM without ciaddr is answered to its source.
func destination4(req, r *Packet4, src netip.AddrPort) netip.AddrPort {
	bcast := netip.AddrPortFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), 68)
	switch {
	case r.Type() == Nak:
		return bcast
	case req.CIAddr.IsValid() && !req.CIAddr.IsUnspecified():
		return netip.AddrPortFrom(req.CIAddr, 68)
	case req.Type() == Inform && src.Addr().IsValid() && !src.Addr().IsUnspecified():
		return src
	}
	return bcast
}

// subnetOf is the subnet holding a.
func subnetOf(subs []*Subnet4, a netip.Addr) *Subnet4 {
	for _, s := range subs {
		if s.Prefix.Contains(a) {
			return s
		}
	}
	return nil
}

// dynamic says whether a may be handed out from a pool: never the
// network or broadcast address, nor one ending in .0 or .255, which some
// clients refuse.
func dynamic(sub *Subnet4, a netip.Addr) bool {
	if a == sub.Prefix.Masked().Addr() || a == lastAddr(sub.Prefix) {
		return false
	}
	b := a.As4()
	return b[3] != 0 && b[3] != 255
}

func inPool(sub *Subnet4, a netip.Addr) bool {
	for _, r := range sub.Pools {
		if r.Contains(a) {
			return dynamic(sub, a)
		}
	}
	return false
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// reservation is the client's reservation in subs.
func reservation(subs []*Subnet4, mac string) (*Reservation, *Subnet4) {
	for _, s := range subs {
		for i := range s.Reservations {
			if strings.EqualFold(s.Reservations[i].MAC, mac) {
				return &s.Reservations[i], s
			}
		}
	}
	return nil, nil
}

// reservedTo is the MAC an address is reserved for, "" for none.
func reservedTo(subs []*Subnet4, a netip.Addr) string {
	for _, s := range subs {
		for _, r := range s.Reservations {
			if r.Addr == a {
				return strings.ToLower(r.MAC)
			}
		}
	}
	return ""
}

// free says whether the client may have a: reserved for no one else, no
// valid lease of another client or declined, and not offered to another.
func (s *Server) free(subs []*Subnet4, c client4, a netip.Addr, now time.Time) bool {
	if m := reservedTo(subs, a); m != "" && m != c.mac {
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

// offerable says whether a may be offered to the client: free, and not
// found in use by a check. A host found on an address may be its client
// holding a lease this host doesn't know (after a failover): that client
// asking for it gets it (request), anyone else another one.
func (s *Server) offerable(subs []*Subnet4, c client4, a netip.Addr, now time.Time) bool {
	if t, ok := s.conflicts[a]; ok && t.After(now) {
		return false
	}
	return s.free(subs, c, a, now)
}

// leaseOf is the client's lease in subs, the latest if several.
func (s *Server) leaseOf(subs []*Subnet4, c client4) *Lease {
	var best *Lease
	s.store.Each(func(l *Lease) bool {
		if l.Addr.Is4() && subnetOf(subs, l.Addr) != nil && c.owns(l) && (best == nil || l.Expires > best.Expires) {
			best = l
		}
		return true
	})
	return best
}

// holder checks who answers for an address, within the load limit: nil
// for no one or no check.
func (s *Server) holder(ifname string, a netip.Addr, now time.Time) net.HardwareAddr {
	if s.probe == nil {
		return nil
	}
	if sec := now.Unix(); sec != s.probedAt {
		s.probedAt, s.probed = sec, 0
	}
	if s.probed >= maxProbesSec {
		return nil
	}
	s.probed++
	return s.probe(ifname, a)
}

// inUse checks an address before it is offered to the client, and
// remembers one another host holds.
func (s *Server) inUse(ifname string, c client4, a netip.Addr, now time.Time) bool {
	m := s.holder(ifname, a, now)
	if m == nil || m.String() == c.mac {
		return false
	}
	slog.Warn("dhcp: address in use, not offered", "interface", ifname, "address", a, "by", m.String())
	s.conflicts[a] = now.Add(conflictHold)
	return true
}

// allocate picks the client's address: its reservation, its lease, the
// address it asked for, a never used one, then the one that ran out
// longest ago.
func (s *Server) allocate(subs []*Subnet4, c client4, requested netip.Addr, now time.Time) netip.Addr {
	if r, _ := reservation(subs, c.mac); r != nil {
		if s.free(subs, c, r.Addr, now) {
			return r.Addr
		}
		return netip.Addr{}
	}
	if l := s.leaseOf(subs, c); l != nil {
		if sub := subnetOf(subs, l.Addr); sub != nil && inPool(sub, l.Addr) && s.free(subs, c, l.Addr, now) {
			return l.Addr
		}
	}
	ifname := subs[0].Interface
	// The address it asks for is checked again even when found in use:
	// the client itself may be the one using it.
	if sub := subnetOf(subs, requested); sub != nil && inPool(sub, requested) && s.free(subs, c, requested, now) && !s.inUse(ifname, c, requested, now) {
		return requested
	}
	var expired []*Lease
	for _, sub := range subs {
		for _, p := range sub.Pools {
			n := 0
			for a := p.Start; a.IsValid() && a.Compare(p.End) <= 0 && n < maxPoolSearch; a, n = a.Next(), n+1 {
				if !dynamic(sub, a) {
					continue
				}
				if l := s.store.Get(a); l != nil {
					if !l.Valid(now) {
						expired = append(expired, l)
					}
					continue
				}
				if s.offerable(subs, c, a, now) && !s.inUse(ifname, c, a, now) {
					return a
				}
			}
		}
	}
	var best *Lease
	for _, l := range expired {
		if (best == nil || l.Expires < best.Expires) && s.offerable(subs, c, l.Addr, now) {
			best = l
		}
	}
	if best != nil && !s.inUse(ifname, c, best.Addr, now) {
		return best.Addr
	}
	return netip.Addr{}
}

// leaseTime is the lease the client gets: the config's, or less if it
// asked for less, but at least minLease.
func (s *Server) leaseTime(req *Packet4) uint32 {
	t := uint32(s.cfg.LeaseTime)
	if want, ok := req.Uint32(optLeaseTime); ok && want < t {
		t = max(want, minLease)
	}
	return t
}

// reply4 starts a reply of type typ.
func reply4(req *Packet4, typ byte, sub *Subnet4) *Packet4 {
	r := &Packet4{
		Op:     bootReply,
		HType:  req.HType,
		HLen:   req.HLen,
		XID:    req.XID,
		Flags:  req.Flags,
		GIAddr: req.GIAddr,
		CHAddr: req.CHAddr,
	}
	r.Set(optMessageType, []byte{typ})
	r.SetAddrs(optServerID, sub.ServerID)
	return r
}

// configure adds the subnet's options; with lease, the lease times too.
func (s *Server) configure(r, req *Packet4, sub *Subnet4, lease uint32, host string) {
	if lease > 0 {
		t1 := int64(lease) / 2
		if j := int64(lease) / 16; j > 0 {
			t1 -= s.jitter(j)
		}
		r.SetUint32(optLeaseTime, lease)
		r.SetUint32(optT1, uint32(t1))
		r.SetUint32(optT2, lease*7/8)
	}
	mask := net.CIDRMask(sub.Prefix.Bits(), 32)
	r.Set(optSubnetMask, mask)
	if sub.Router.IsValid() {
		r.SetAddrs(optRouter, sub.Router)
	}
	r.SetAddrs(optDNS, sub.DNS...)
	if s.cfg.Domain != "" {
		r.Set(optDomain, []byte(s.cfg.Domain))
	}
	if host != "" && (req.Requested(optHostname) || len(req.Options[optHostname]) > 0) {
		r.Set(optHostname, []byte(host))
	}
	if sub.V6OnlyPreferred > 0 && req.Requested(optV6OnlyPref) {
		r.SetUint32(optV6OnlyPref, uint32(sub.V6OnlyPreferred))
	}
	if id := req.Options[optClientID]; len(id) > 0 {
		// RFC 6842: the client id is echoed.
		r.Set(optClientID, id)
	}
}

// hostOf is the name a lease records: the reservation's host (its first
// label, without the domain), else what the client sent.
func hostOf(res *Reservation, req *Packet4) string {
	if res != nil && res.Hostname != "" {
		h, _, _ := strings.Cut(strings.TrimSuffix(res.Hostname, "."), ".")
		return h
	}
	return cleanHostname(string(req.Options[optHostname]))
}

// cleanHostname keeps a client's host name if it is a plain label.
func cleanHostname(h string) string {
	h = strings.TrimSuffix(h, ".")
	if len(h) > 63 {
		h = h[:63]
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_') {
			return ""
		}
	}
	return h
}

func (s *Server) discover(subs []*Subnet4, c client4, req *Packet4, now time.Time) *Packet4 {
	// RFC 8925: a client that can do without IPv4 is told to, and gets
	// no address.
	for _, sub := range subs {
		if sub.V6OnlyPreferred > 0 && req.Requested(optV6OnlyPref) {
			r := reply4(req, Offer, sub)
			r.SetUint32(optV6OnlyPref, uint32(sub.V6OnlyPreferred))
			if id := req.Options[optClientID]; len(id) > 0 {
				r.Set(optClientID, id)
			}
			return r
		}
	}
	a := s.allocate(subs, c, req.Addr(optRequestedIP), now)
	if !a.IsValid() {
		slog.Warn("dhcp: no address to offer", "interface", subs[0].Interface, "mac", c.mac)
		return nil
	}
	sub := subnetOf(subs, a)
	s.offers[a] = hold{client: c.key(), until: now.Add(offerHold)}
	res, _ := reservation(subs, c.mac)
	r := reply4(req, Offer, sub)
	r.YIAddr = a
	s.configure(r, req, sub, s.leaseTime(req), hostOf(res, req))
	return r
}

func nak(req *Packet4, sub *Subnet4, msg string) *Packet4 {
	r := reply4(req, Nak, sub)
	r.Set(optMessage, []byte(msg))
	if id := req.Options[optClientID]; len(id) > 0 {
		r.Set(optClientID, id)
	}
	return r
}

func (s *Server) request(subs []*Subnet4, c client4, req *Packet4, now time.Time) *Packet4 {
	if sid := req.Addr(optServerID); sid.IsValid() {
		ours := false
		for _, sub := range subs {
			ours = ours || sub.ServerID == sid
		}
		if !ours {
			// The client took another server's offer.
			for a, h := range s.offers {
				if h.client == c.key() {
					delete(s.offers, a)
				}
			}
			return nil
		}
	}
	want := req.Addr(optRequestedIP)
	if !want.IsValid() && req.CIAddr.IsValid() && !req.CIAddr.IsUnspecified() {
		want = req.CIAddr
	}
	if !want.IsValid() {
		// Neither a requested address nor ciaddr: some clients skip the
		// DISCOVER. They get an address.
		want = s.allocate(subs, c, netip.Addr{}, now)
		if !want.IsValid() {
			return nil
		}
	}
	sub := subnetOf(subs, want)
	if sub == nil {
		return nak(req, subs[0], "wrong network")
	}
	res, _ := reservation(subs, c.mac)
	switch {
	case res != nil && res.Addr != want:
		return nak(req, sub, "address reserved elsewhere")
	case res == nil && !inPool(sub, want):
		return nak(req, sub, "address not available")
	case !s.free(subs, c, want, now):
		return nak(req, sub, "address in use")
	}
	// A renewal of an address the store doesn't know, but free, is
	// granted: after a failover the record may not have reached the new
	// host. Unless offered to this client (and checked then), the address
	// is checked first: the client may answer for it itself, another host
	// may not.
	lease := s.leaseTime(req)
	old := s.store.Get(want)
	fresh := old == nil || !old.Valid(now) || !c.owns(old)
	if h, ok := s.offers[want]; fresh && !(ok && h.client == c.key() && h.until.After(now)) && s.inUse(sub.Interface, c, want, now) {
		return nak(req, sub, "address in use")
	}
	l := Lease{
		Addr:     want,
		MAC:      c.mac,
		ClientID: c.id,
		Hostname: hostOf(res, req),
		Expires:  now.Unix() + int64(lease),
	}
	if old != nil && c.owns(old) && l.ClientID == "" {
		l.ClientID = old.ClientID
	}
	if l.Hostname == "" && old != nil && c.owns(old) {
		l.Hostname = old.Hostname
	}
	seq, err := s.put(l, fresh, fresh)
	if err != nil {
		slog.Error("dhcp: lease not stored", "address", want, "err", err)
		return nil
	}
	s.waitFor = seq
	delete(s.offers, want)
	// One lease per client: an older one in these subnets ends now.
	var older []Lease
	s.store.Each(func(o *Lease) bool {
		if o.Addr != want && o.Addr.Is4() && o.Valid(now) && c.owns(o) && subnetOf(subs, o.Addr) != nil {
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
		slog.Info("dhcp: lease", "interface", sub.Interface, "address", want, "mac", c.mac, "host", l.Hostname)
	}
	r := reply4(req, Ack, sub)
	r.YIAddr = want
	if req.CIAddr.IsValid() {
		r.CIAddr = req.CIAddr
	}
	s.configure(r, req, sub, lease, hostOf(res, req))
	return r
}

func (s *Server) decline(subs []*Subnet4, c client4, req *Packet4, now time.Time) {
	a := req.Addr(optRequestedIP)
	l := s.store.Get(a)
	// Only for the client's own valid lease, or anyone could take
	// addresses away.
	if l == nil || !l.Valid(now) || !c.owns(l) {
		return
	}
	d := *l
	d.Declined = true
	d.Expires = now.Add(declineHold).Unix()
	s.put(d, false, false)
	slog.Warn("dhcp: address declined", "interface", subs[0].Interface, "address", a, "mac", c.mac)
}

func (s *Server) release(subs []*Subnet4, c client4, req *Packet4, now time.Time) {
	l := s.store.Get(req.CIAddr)
	if l == nil || !l.Valid(now) || !c.owns(l) {
		return
	}
	r := *l
	r.Expires = now.Unix()
	s.put(r, false, false)
}

func (s *Server) inform(subs []*Subnet4, req *Packet4, src netip.AddrPort) *Packet4 {
	a := req.CIAddr
	if !a.IsValid() || a.IsUnspecified() {
		a = src.Addr()
	}
	sub := subnetOf(subs, a)
	if sub == nil {
		return nil
	}
	r := reply4(req, Ack, sub)
	r.CIAddr = req.CIAddr
	s.configure(r, req, sub, 0, "")
	return r
}
