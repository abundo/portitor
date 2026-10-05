// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/nclient6"
	"github.com/insomniacslk/dhcp/iana"

	"github.com/abundo/portitor/internal/fwconfig"
)

// dhcp6Key is one DHCPv6 client; pd asks for a delegated prefix, of pdLen
// bits when not 0 (changing either restarts the client).
type dhcp6Key struct {
	instance, netns, iface string
	pd                     bool
	pdLen                  int
}

// dhcp6Manager runs one DHCPv6 client goroutine per interface with
// DHCPv6 on. It adds the leased address (a /128: the on-link prefix comes
// from router advertisements) and an unreachable route for the delegated
// prefix, so traffic to its unused parts does not loop back upstream.
type dhcp6Manager struct {
	run      Runner
	dryRun   bool
	dir      string                // saved leases; "" saves none
	onChange func(instance string) // called when a delegated prefix changes

	mu      sync.Mutex
	clients map[dhcp6Key]context.CancelCauseFunc
	wake    map[dhcp6Key]chan struct{} // Renew asks the client to renew now
	leases  map[dhcp6Key]*Lease
	pds     map[dhcp6Key]netip.Prefix
	// restored are the unexpired leases saved by the last run, until the
	// first Reconcile hands them to their clients.
	restored map[leaseID]*lease6
	wg       sync.WaitGroup
	stopped  atomic.Bool // no onChange while the agent stops
}

func newDHCP6Manager(run Runner, dryRun bool, dir string, onChange func(string)) *dhcp6Manager {
	m := &dhcp6Manager{
		run:      run,
		dryRun:   dryRun,
		dir:      dir,
		onChange: onChange,
		restored: map[leaseID]*lease6{},
		clients:  map[dhcp6Key]context.CancelCauseFunc{},
		wake:     map[dhcp6Key]chan struct{}{},
		leases:   map[dhcp6Key]*Lease{},
		pds:      map[dhcp6Key]netip.Prefix{},
	}
	if dryRun {
		m.dir = ""
	}
	for id, s := range savedLeases(m.dir) {
		if l := lease6FromSaved(s); l != nil {
			m.restored[id] = l
		} else {
			dropLease(m.dir, id)
		}
	}
	return m
}

// lease6FromSaved parses a saved lease; nil when it is broken or expired.
func lease6FromSaved(s savedLease) *lease6 {
	r, err := dhcpv6.MessageFromBytes(s.Reply)
	if err != nil {
		return nil
	}
	l, err := parseReply6(r, s.Obtained)
	if err != nil || !time.Now().Before(l.expires) {
		return nil
	}
	return l
}

// Reconcile starts clients for new keys and stops removed ones. A new
// client starts from the lease the last run saved for its interface, when
// it asked for what the key asks for (a prefix or not).
func (m *dhcp6Manager) Reconcile(want []dhcp6Key) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, cancel := range m.clients {
		if !slices.Contains(want, k) {
			cancel(nil)
			delete(m.clients, k)
			delete(m.wake, k)
			delete(m.leases, k)
		}
	}
	for _, k := range want {
		if _, ok := m.clients[k]; ok {
			continue
		}
		ctx, cancel := context.WithCancelCause(context.Background())
		m.clients[k] = cancel
		wake := make(chan struct{}, 1)
		m.wake[k] = wake
		ls := &Lease{Instance: k.instance, Interface: k.iface, Family: "ipv6", State: "requesting"}
		id := leaseID{k.instance, k.iface}
		saved := m.restored[id]
		delete(m.restored, id)
		if saved != nil && saved.pd.IsValid() != k.pd {
			dropLease(m.dir, id)
			saved = nil
		}
		if saved != nil {
			lease6Status(ls, saved)
			if saved.pd.IsValid() {
				m.pds[k] = saved.pd
			}
		}
		m.leases[k] = ls
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.loop(ctx, k, saved, wake)
		}()
	}
	// A saved lease no client took is for an interface without DHCPv6.
	for id := range m.restored {
		dropLease(m.dir, id)
	}
	clear(m.restored)
}

// Renew wakes the DHCPv6 client of the instance's interface, which then
// renews its lease (or asks for one) at once; false when there is none.
func (m *dhcp6Manager) Renew(instance, iface string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, wake := range m.wake {
		if k.instance == instance && k.iface == iface {
			select {
			case wake <- struct{}{}:
			default:
			}
			return true
		}
	}
	return false
}

// Stop stops the clients and keeps their leases (errStopping).
func (m *dhcp6Manager) Stop() {
	m.stopped.Store(true)
	m.mu.Lock()
	for k, cancel := range m.clients {
		cancel(errStopping)
		delete(m.clients, k)
		delete(m.wake, k)
	}
	m.mu.Unlock()
	m.wg.Wait()
}

// Leases returns a snapshot of all leases.
func (m *dhcp6Manager) Leases() []Lease {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Lease, 0, len(m.leases))
	for _, l := range m.leases {
		out = append(out, *l)
	}
	return out
}

// Prefixes returns the delegated prefixes per instance and interface;
// before the first Reconcile, those of the leases the last run saved.
func (m *dhcp6Manager) Prefixes() fwconfig.DelegatedPrefixes {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := fwconfig.DelegatedPrefixes{}
	for id, l := range m.restored {
		if !l.pd.IsValid() {
			continue
		}
		if out[id.instance] == nil {
			out[id.instance] = map[string]netip.Prefix{}
		}
		out[id.instance][id.iface] = l.pd
	}
	for k, p := range m.pds {
		if out[k.instance] == nil {
			out[k.instance] = map[string]netip.Prefix{}
		}
		out[k.instance][k.iface] = p
	}
	return out
}

func (m *dhcp6Manager) update(k dhcp6Key, fn func(l *Lease)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.leases[k]; ok {
		fn(l)
	}
}

// setPD records k's delegated prefix (invalid: none) and reports whether
// it changed.
func (m *dhcp6Manager) setPD(k dhcp6Key, pd netip.Prefix) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, had := m.pds[k]
	if !pd.IsValid() {
		delete(m.pds, k)
		return had
	}
	m.pds[k] = pd
	return !had || old != pd
}

func (m *dhcp6Manager) changed(k dhcp6Key) {
	if m.onChange != nil && !m.stopped.Load() {
		go m.onChange(k.instance)
	}
}

// loop runs k's client, starting from saved (nil: none) with a Renew.
// Cancelled with errStopping it keeps the lease; otherwise it releases it
// and removes the address and the prefix's route.
func (m *dhcp6Manager) loop(ctx context.Context, k dhcp6Key, saved *lease6, wake <-chan struct{}) {
	log := slog.With("instance", k.instance, "interface", k.iface)
	if m.dryRun {
		log.Info("dry-run: not starting DHCPv6 client")
		m.update(k, func(l *Lease) { l.State = "dry-run" })
		return
	}
	backoff := 5 * time.Second
	current := saved
	var client *nclient6.Client
	id := leaseID{k.instance, k.iface}
	defer func() {
		if errors.Is(context.Cause(ctx), errStopping) {
			if client != nil {
				client.Close()
			}
			return
		}
		if current != nil {
			if client != nil {
				m.release(client, current)
			}
			m.removeLease(k, current)
		}
		if client != nil {
			client.Close()
		}
		dropLease(m.dir, id)
		if m.setPD(k, netip.Prefix{}) {
			m.changed(k)
		}
	}()

	for ctx.Err() == nil {
		if client == nil {
			c, err := newClient6InNetns(k.netns, k.iface)
			if err != nil {
				m.fail(k, log, m.explainBind(ctx, k, err))
				if !sleepWake(ctx, backoff, wake) {
					return
				}
				continue
			}
			client = c
		}

		var reply *dhcpv6.Message
		var err error
		reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if current != nil {
			reply, err = m.exchange(reqCtx, client, dhcpv6.MessageTypeRenew, current.reply)
		}
		if current == nil || err != nil {
			reply, err = m.solicit(reqCtx, client, k)
		}
		cancel()
		var l *lease6
		if err == nil {
			l, err = parseReply6(reply, time.Now())
		}
		if err != nil {
			m.fail(k, log, err)
			if current != nil && time.Now().After(current.expires) {
				m.removeLease(k, current)
				dropLease(m.dir, id)
				current = nil
			}
			// The interface may have gone away (moved namespace); reopen.
			client.Close()
			client = nil
			if !sleepWake(ctx, backoff, wake) {
				return
			}
			continue
		}

		if err := m.installLease(ctx, k, current, l); err != nil {
			m.fail(k, log, err)
		}
		current = l
		saveLease(m.dir, id, savedLease{Reply: l.reply.ToBytes(), Obtained: l.obtained})
		log.Info("dhcpv6 lease bound", "address", l.addr, "prefix", l.pd, "renew", l.renew)
		if !sleepWake(ctx, l.renew, wake) {
			return
		}
	}
}

func (m *dhcp6Manager) fail(k dhcp6Key, log *slog.Logger, err error) {
	log.Warn("dhcpv6 client", "err", err)
	m.update(k, func(l *Lease) {
		l.LastError = err.Error()
		if l.State != "bound" {
			l.State = "error"
		}
	})
}

// clientID is a DUID-LL from the interface's MAC, stable across restarts
// so the server keeps handing out the same address and prefix.
func clientID(hw net.HardwareAddr) dhcpv6.DUID {
	return &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: hw}
}

// iaid is the identity association id, from the MAC's last 4 bytes.
func iaid(hw net.HardwareAddr) [4]byte {
	var id [4]byte
	if len(hw) >= 4 {
		copy(id[:], hw[len(hw)-4:])
	}
	return id
}

func newMessage6(t dhcpv6.MessageType, hw net.HardwareAddr) (*dhcpv6.Message, error) {
	msg, err := dhcpv6.NewMessage()
	if err != nil {
		return nil, err
	}
	msg.MessageType = t
	msg.AddOption(dhcpv6.OptClientID(clientID(hw)))
	msg.AddOption(dhcpv6.OptElapsedTime(0))
	msg.AddOption(dhcpv6.OptRequestedOption(dhcpv6.OptionDNSRecursiveNameServer, dhcpv6.OptionDomainSearchList))
	return msg, nil
}

// solicit asks for an address and, with k.pd, a prefix: Solicit,
// Advertise, Request, Reply.
func (m *dhcp6Manager) solicit(ctx context.Context, c *nclient6.Client, k dhcp6Key) (*dhcpv6.Message, error) {
	hw := c.InterfaceAddr()
	sol, err := newMessage6(dhcpv6.MessageTypeSolicit, hw)
	if err != nil {
		return nil, err
	}
	id := iaid(hw)
	dhcpv6.WithIAID(id)(sol)
	if k.pd {
		var hint []*dhcpv6.OptIAPrefix
		if k.pdLen > 0 {
			hint = append(hint, &dhcpv6.OptIAPrefix{Prefix: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(k.pdLen, 128)}})
		}
		dhcpv6.WithIAPD(id, hint...)(sol)
	}
	adv, err := c.SendAndRead(ctx, c.RemoteAddr(), sol, nclient6.IsMessageType(dhcpv6.MessageTypeAdvertise))
	if err != nil {
		return nil, fmt.Errorf("solicit: %w", err)
	}
	return m.exchange(ctx, c, dhcpv6.MessageTypeRequest, adv)
}

// exchange sends a Request (from an Advertise), Renew or Release (from
// the current Reply) carrying from's server id and identity associations,
// and waits for the Reply.
func (m *dhcp6Manager) exchange(ctx context.Context, c *nclient6.Client, t dhcpv6.MessageType, from *dhcpv6.Message) (*dhcpv6.Message, error) {
	msg, err := newMessage6(t, c.InterfaceAddr())
	if err != nil {
		return nil, err
	}
	sid := from.Options.ServerID()
	if sid == nil {
		return nil, errors.New("no server id")
	}
	msg.AddOption(dhcpv6.OptServerID(sid))
	if ia := from.Options.OneIANA(); ia != nil {
		msg.AddOption(ia)
	}
	if ia := from.Options.OneIAPD(); ia != nil {
		msg.AddOption(ia)
	}
	reply, err := c.SendAndRead(ctx, c.RemoteAddr(), msg, nclient6.IsMessageType(dhcpv6.MessageTypeReply))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", t, err)
	}
	return reply, nil
}

func (m *dhcp6Manager) release(c *nclient6.Client, l *lease6) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = m.exchange(ctx, c, dhcpv6.MessageTypeRelease, l.reply)
}

// lease6 is what a Reply gave: an address, a delegated prefix, or both.
type lease6 struct {
	reply         *dhcpv6.Message
	addr          netip.Addr
	addrValid     time.Duration
	addrPreferred time.Duration
	pd            netip.Prefix
	obtained      time.Time
	expires       time.Time
	renew, rebind time.Duration
	dns, search   []string
	server        string
}

// infinite is the DHCPv6 lifetime 0xffffffff.
const infinite = time.Duration(0xffffffff) * time.Second

// parseReply6 reads a Reply. It fails when the server refused, or gave
// neither an address nor a prefix.
func parseReply6(r *dhcpv6.Message, now time.Time) (*lease6, error) {
	if st := r.Options.Status(); st != nil && st.StatusCode != iana.StatusSuccess {
		return nil, fmt.Errorf("server: %s %s", st.StatusCode, st.StatusMessage)
	}
	l := &lease6{reply: r, obtained: now}
	var valid, t1, t2 time.Duration
	shortest := func(cur *time.Duration, d time.Duration) {
		if d > 0 && (*cur == 0 || d < *cur) {
			*cur = d
		}
	}
	if ia := r.Options.OneIANA(); ia != nil {
		if a := ia.Options.OneAddress(); a != nil && a.ValidLifetime > 0 {
			if addr, ok := netip.AddrFromSlice(a.IPv6Addr.To16()); ok {
				l.addr, l.addrValid, l.addrPreferred = addr, a.ValidLifetime, a.PreferredLifetime
				shortest(&valid, a.ValidLifetime)
				shortest(&t1, ia.T1)
				shortest(&t2, ia.T2)
			}
		}
	}
	if ia := r.Options.OneIAPD(); ia != nil {
		for _, p := range ia.Options.Prefixes() {
			if p.Prefix == nil || p.ValidLifetime == 0 {
				continue
			}
			ones, _ := p.Prefix.Mask.Size()
			addr, ok := netip.AddrFromSlice(p.Prefix.IP.To16())
			if !ok || ones > 64 {
				continue
			}
			l.pd = netip.PrefixFrom(addr, ones).Masked()
			shortest(&valid, p.ValidLifetime)
			shortest(&t1, ia.T1)
			shortest(&t2, ia.T2)
			break
		}
	}
	if !l.addr.IsValid() && !l.pd.IsValid() {
		return nil, errors.New("the server gave neither an address nor a delegated prefix")
	}
	// RFC 8415 21.4: T1 0 leaves the time to the client; half the
	// lifetime, renewing at least once a day and at most every minute.
	if t1 == 0 || t1 > valid {
		t1 = valid / 2
	}
	l.renew = min(max(t1, time.Minute), 24*time.Hour)
	if t2 == 0 || t2 > valid {
		t2 = valid * 4 / 5
	}
	l.rebind = t2
	l.expires = now.Add(valid)
	for _, ip := range r.Options.DNS() {
		l.dns = append(l.dns, ip.String())
	}
	slices.Sort(l.dns)
	if s := r.Options.DomainSearchList(); s != nil {
		l.search = slices.Clone(s.Labels)
	}
	if sid := r.Options.ServerID(); sid != nil {
		l.server = sid.String()
	}
	return l, nil
}

// lft is a lifetime for ip(8): seconds, or forever.
func lft(d time.Duration) string {
	if d >= infinite {
		return "forever"
	}
	return strconv.Itoa(int(d.Seconds()))
}

func (m *dhcp6Manager) installLease(ctx context.Context, k dhcp6Key, old, l *lease6) error {
	if old != nil && old.addr.IsValid() && old.addr != l.addr {
		m.delAddr(k, old.addr)
	}
	if old != nil && old.pd.IsValid() && old.pd != l.pd {
		m.delPD(k, old.pd)
	}
	if l.addr.IsValid() {
		if _, err := m.run.Run(ctx, k.netns, "ip", "-6", "addr", "replace", netip.PrefixFrom(l.addr, 128).String(),
			"dev", k.iface, "valid_lft", lft(l.addrValid), "preferred_lft", lft(l.addrPreferred)); err != nil {
			return err
		}
	}
	if l.pd.IsValid() {
		if _, err := m.run.Run(ctx, k.netns, "ip", "-6", "route", "replace", "unreachable", l.pd.String(), "proto", "dhcp"); err != nil {
			return err
		}
	}
	m.update(k, func(ls *Lease) { lease6Status(ls, l) })
	if m.setPD(k, l.pd) {
		m.changed(k)
	}
	return nil
}

// lease6Status fills ls, bound, from l.
func lease6Status(ls *Lease, l *lease6) {
	ls.Address = ""
	if l.addr.IsValid() {
		ls.Address = netip.PrefixFrom(l.addr, 128).String()
	}
	ls.Prefixes = nil
	if l.pd.IsValid() {
		ls.Prefixes = []string{l.pd.String()}
	}
	ls.DNS, ls.Search, ls.Server = l.dns, l.search, l.server
	ls.Obtained, ls.Expires = l.obtained, l.expires
	ls.RenewAfter, ls.RebindAfter = l.obtained.Add(l.renew), l.obtained.Add(l.rebind)
	ls.State, ls.LastError = "bound", ""
}

func (m *dhcp6Manager) delAddr(k dhcp6Key, a netip.Addr) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = m.run.Run(ctx, k.netns, "ip", "-6", "addr", "del", netip.PrefixFrom(a, 128).String(), "dev", k.iface)
}

func (m *dhcp6Manager) delPD(k dhcp6Key, p netip.Prefix) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = m.run.Run(ctx, k.netns, "ip", "-6", "route", "del", "unreachable", p.String(), "proto", "dhcp")
}

func (m *dhcp6Manager) removeLease(k dhcp6Key, l *lease6) {
	if l.addr.IsValid() {
		m.delAddr(k, l.addr)
	}
	if l.pd.IsValid() {
		m.delPD(k, l.pd)
	}
	m.update(k, func(ls *Lease) {
		*ls = Lease{Instance: ls.Instance, Interface: ls.Interface, Family: ls.Family, State: "requesting", LastError: ls.LastError}
	})
	if m.setPD(k, netip.Prefix{}) {
		m.changed(k)
	}
}

// explainBind names, when the client's port is taken, the process that
// holds it: usually the system's own DHCPv6 client on the interface.
func (m *dhcp6Manager) explainBind(ctx context.Context, k dhcp6Key, err error) error {
	if !errors.Is(err, syscall.EADDRINUSE) {
		return err
	}
	owner := "another program"
	if out, serr := m.run.Run(ctx, k.netns, "ss", "-H", "-u", "-l", "-n", "-p", "sport", "=", ":546"); serr == nil {
		if users := portUsers(string(out)); len(users) > 0 {
			owner = strings.Join(users, ", ")
		}
	}
	return fmt.Errorf("%w (%s holds the DHCPv6 client port 546: another DHCPv6 client, such as "+
		"systemd-networkd/netplan, NetworkManager or dhclient, is probably managing %s; turn IPv6 off there)", err, owner, k.iface)
}

// portUsers extracts the process names from ss -p output
// (users:(("NetworkManager",pid=1,fd=2))).
func portUsers(ss string) []string {
	var out []string
	for _, m := range ssUserRe.FindAllStringSubmatch(ss, -1) {
		if !slices.Contains(out, m[1]) {
			out = append(out, m[1])
		}
	}
	return out
}

var ssUserRe = regexp.MustCompile(`[(,]\("([^"]+)",pid=`)

// newClient6InNetns opens the DHCPv6 client's socket (UDP port 546 on
// the interface's link-local address) inside the named network namespace.
// It fails while the link-local address is missing or tentative.
func newClient6InNetns(nsName, iface string) (*nclient6.Client, error) {
	var c *nclient6.Client
	err := withNetns(nsName, func() error {
		var err error
		c, err = nclient6.New(iface, nclient6.WithTimeout(5*time.Second), nclient6.WithRetry(3))
		return err
	})
	return c, err
}
