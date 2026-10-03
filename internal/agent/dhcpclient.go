// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/vishvananda/netns"
)

// dhcpKey is one client; noRoute leaves out the default route (changing
// it restarts the client).
type dhcpKey struct {
	instance, netns, iface string
	noRoute                bool
}

// dhcpManager runs one DHCPv4 client goroutine per WAN interface.
type dhcpManager struct {
	run      Runner
	dryRun   bool
	dir      string                // saved leases; "" saves none
	onChange func(instance string) // called when a lease's DNS servers change

	mu      sync.Mutex
	clients map[dhcpKey]context.CancelCauseFunc
	leases  map[dhcpKey]*Lease
	// restored are the unexpired leases saved by the last run, until the
	// first Reconcile hands them to their clients.
	restored map[leaseID]*nclient4.Lease
	wg       sync.WaitGroup
}

func newDHCPManager(run Runner, dryRun bool, dir string, onChange func(string)) *dhcpManager {
	m := &dhcpManager{
		run:      run,
		dryRun:   dryRun,
		dir:      dir,
		onChange: onChange,
		clients:  map[dhcpKey]context.CancelCauseFunc{},
		leases:   map[dhcpKey]*Lease{},
		restored: map[leaseID]*nclient4.Lease{},
	}
	if dryRun {
		m.dir = ""
	}
	for id, s := range savedLeases(m.dir) {
		if l := lease4FromSaved(s); l != nil {
			m.restored[id] = l
		} else {
			dropLease(m.dir, id)
		}
	}
	return m
}

// lease4FromSaved parses a saved lease; nil when it is broken or expired.
func lease4FromSaved(s savedLease) *nclient4.Lease {
	offer, err := dhcpv4.FromBytes(s.Offer)
	if err != nil {
		return nil
	}
	ack, err := dhcpv4.FromBytes(s.ACK)
	if err != nil {
		return nil
	}
	l := &nclient4.Lease{Offer: offer, ACK: ack, CreationTime: s.Obtained}
	if !leasePrefix(l).IsValid() || !time.Now().Before(leaseExpiry(l)) {
		return nil
	}
	return l
}

func leaseExpiry(l *nclient4.Lease) time.Time {
	return l.CreationTime.Add(l.ACK.IPAddressLeaseTime(time.Hour))
}

// Reconcile starts clients for new keys and stops removed ones. A new
// client starts from the lease the last run saved for its interface.
func (m *dhcpManager) Reconcile(want []dhcpKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, cancel := range m.clients {
		if !slices.Contains(want, k) {
			cancel(nil)
			delete(m.clients, k)
			delete(m.leases, k)
		}
	}
	for _, k := range want {
		if _, ok := m.clients[k]; ok {
			continue
		}
		ctx, cancel := context.WithCancelCause(context.Background())
		m.clients[k] = cancel
		l := &Lease{Instance: k.instance, Interface: k.iface, State: "requesting"}
		id := leaseID{k.instance, k.iface}
		saved := m.restored[id]
		delete(m.restored, id)
		if saved != nil {
			leaseStatus(l, saved)
		}
		m.leases[k] = l
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.loop(ctx, k, saved)
		}()
	}
	// A saved lease no client took is for an interface no longer in DHCP
	// mode.
	for id := range m.restored {
		dropLease(m.dir, id)
	}
	clear(m.restored)
}

// Stop stops the clients and keeps their leases (errStopping).
func (m *dhcpManager) Stop() {
	m.mu.Lock()
	for k, cancel := range m.clients {
		cancel(errStopping)
		delete(m.clients, k)
	}
	m.mu.Unlock()
	m.wg.Wait()
}

// Leases returns a snapshot of all leases.
func (m *dhcpManager) Leases() []Lease {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Lease, 0, len(m.leases))
	for _, l := range m.leases {
		out = append(out, *l)
	}
	slices.SortFunc(out, func(a, b Lease) int {
		if a.Instance != b.Instance {
			if a.Instance < b.Instance {
				return -1
			}
			return 1
		}
		if a.Interface < b.Interface {
			return -1
		}
		return 1
	})
	return out
}

// DNSServers returns DNS servers learned per instance and interface;
// before the first Reconcile, those of the leases the last run saved.
func (m *dhcpManager) DNSServers() map[string]map[string][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]map[string][]string{}
	for id, saved := range m.restored {
		var l Lease
		leaseStatus(&l, saved)
		if len(l.DNS) > 0 {
			if out[id.instance] == nil {
				out[id.instance] = map[string][]string{}
			}
			out[id.instance][id.iface] = l.DNS
		}
	}
	for k, l := range m.leases {
		if len(l.DNS) == 0 {
			continue
		}
		if out[k.instance] == nil {
			out[k.instance] = map[string][]string{}
		}
		out[k.instance][k.iface] = slices.Clone(l.DNS)
	}
	return out
}

func (m *dhcpManager) update(k dhcpKey, fn func(l *Lease)) (dnsChanged bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok := m.leases[k]
	if !ok {
		return false
	}
	before := slices.Clone(l.DNS)
	fn(l)
	return !slices.Equal(before, l.DNS)
}

// loop runs k's client, starting from saved (nil: none) with a Renew.
// Cancelled with errStopping it keeps the lease; otherwise it releases it
// and removes the address.
func (m *dhcpManager) loop(ctx context.Context, k dhcpKey, saved *nclient4.Lease) {
	log := slog.With("instance", k.instance, "interface", k.iface)
	if m.dryRun {
		log.Info("dry-run: not starting DHCP client")
		m.update(k, func(l *Lease) { l.State = "dry-run" })
		return
	}
	backoff := 5 * time.Second
	current := saved
	var client *nclient4.Client
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
				_ = client.Release(current)
			}
			m.removeLease(k, current)
		}
		if client != nil {
			client.Close()
		}
		dropLease(m.dir, id)
	}()

	for ctx.Err() == nil {
		if client == nil {
			c, err := newClientInNetns(k.netns, k.iface)
			if err != nil {
				m.fail(k, log, err)
				if !sleepCtx(ctx, backoff) {
					return
				}
				continue
			}
			client = c
		}

		var lease *nclient4.Lease
		var err error
		reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if current != nil {
			lease, err = client.Renew(reqCtx, current)
		}
		if current == nil || err != nil {
			lease, err = client.Request(reqCtx)
		}
		cancel()
		if err != nil {
			m.fail(k, log, m.explain(ctx, k, current, err))
			if current != nil && time.Now().After(leaseExpiry(current)) {
				m.removeLease(k, current)
				dropLease(m.dir, id)
				current = nil
			}
			// The interface may have gone away (moved namespace); reopen.
			client.Close()
			client = nil
			if !sleepCtx(ctx, backoff) {
				return
			}
			continue
		}

		if err := m.installLease(ctx, k, current, lease); err != nil {
			m.fail(k, log, err)
		}
		current = lease
		saveLease(m.dir, id, savedLease{Offer: lease.Offer.ToBytes(), ACK: lease.ACK.ToBytes(), Obtained: lease.CreationTime})
		leaseTime := lease.ACK.IPAddressLeaseTime(time.Hour)
		renew := lease.ACK.IPAddressRenewalTime(leaseTime / 2)
		if renew <= 0 || renew > leaseTime {
			renew = leaseTime / 2
		}
		log.Info("dhcp lease bound", "address", lease.ACK.YourIPAddr, "lease", leaseTime, "renew", renew)
		if !sleepCtx(ctx, renew) {
			return
		}
	}
}

func (m *dhcpManager) fail(k dhcpKey, log *slog.Logger, err error) {
	log.Warn("dhcp client", "err", err)
	m.update(k, func(l *Lease) {
		l.LastError = err.Error()
		if l.State != "bound" {
			l.State = "error"
		}
	})
}

// explain adds to a failed request the dynamic addresses on the interface
// that the agent did not set: another DHCP client there usually is why
// the server does not answer.
func (m *dhcpManager) explain(ctx context.Context, k dhcpKey, current *nclient4.Lease, err error) error {
	out, lerr := m.run.Run(ctx, k.netns, "ip", "-j", "-4", "addr", "show", "dev", k.iface)
	if lerr != nil {
		return err
	}
	links, lerr := parseLinks(out)
	if lerr != nil || len(links) != 1 {
		return err
	}
	var own netip.Prefix
	if current != nil {
		own = leasePrefix(current)
	}
	foreign := foreignDHCPAddrs(links[0], own)
	if len(foreign) == 0 {
		return err
	}
	return fmt.Errorf("%w (%s has dynamic address %s that portitor did not set: "+
		"another DHCP client, such as systemd-networkd/netplan, NetworkManager or dhclient, "+
		"is probably managing it)", err, k.iface, strings.Join(foreign, ", "))
}

// leasePrefix is the lease's address and prefix length; invalid when it
// has no IPv4 address.
func leasePrefix(lease *nclient4.Lease) netip.Prefix {
	ack := lease.ACK
	mask := ack.SubnetMask()
	if mask == nil {
		mask = ack.YourIPAddr.DefaultMask()
	}
	ones, _ := mask.Size()
	addr, ok := netip.AddrFromSlice(ack.YourIPAddr.To4())
	if !ok {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(addr, ones)
}

func (m *dhcpManager) installLease(ctx context.Context, k dhcpKey, old, lease *nclient4.Lease) error {
	ack := lease.ACK
	pfx := leasePrefix(lease)
	if !pfx.IsValid() {
		return fmt.Errorf("lease without IPv4 address")
	}
	leaseTime := ack.IPAddressLeaseTime(time.Hour)
	lft := strconv.Itoa(int(leaseTime.Seconds()))

	if old != nil && !old.ACK.YourIPAddr.Equal(ack.YourIPAddr) {
		m.removeLease(k, old)
	}
	if _, err := m.run.Run(ctx, k.netns, "ip", "addr", "replace", pfx.String(), "dev", k.iface,
		"valid_lft", lft, "preferred_lft", lft); err != nil {
		return err
	}
	var router string
	if routers := ack.Router(); len(routers) > 0 {
		router = routers[0].String()
	}
	if router != "" && !k.noRoute {
		if _, err := m.run.Run(ctx, k.netns, "ip", "route", "replace", "default", "via", router,
			"dev", k.iface, "proto", "dhcp", "metric", strconv.Itoa(DHCPRouteMetric)); err != nil {
			return err
		}
	}
	changed := m.update(k, func(l *Lease) { leaseStatus(l, lease) })
	if changed && m.onChange != nil {
		go m.onChange(k.instance)
	}
	return nil
}

// leaseStatus fills l, bound, from lease.
func leaseStatus(l *Lease, lease *nclient4.Lease) {
	ack := lease.ACK
	leaseTime := ack.IPAddressLeaseTime(time.Hour)
	l.Address = leasePrefix(lease).String()
	l.Router = ""
	if routers := ack.Router(); len(routers) > 0 {
		l.Router = routers[0].String()
	}
	l.DNS = nil
	for _, ip := range ack.DNS() {
		l.DNS = append(l.DNS, ip.String())
	}
	slices.Sort(l.DNS)
	l.Server = ""
	if s := ack.ServerIdentifier(); s != nil {
		l.Server = s.String()
	}
	l.Obtained = lease.CreationTime
	l.Expires = lease.CreationTime.Add(leaseTime)
	l.RenewAfter = lease.CreationTime.Add(ack.IPAddressRenewalTime(leaseTime / 2))
	l.RebindAfter = lease.CreationTime.Add(ack.IPAddressRebindingTime(leaseTime * 7 / 8))
	l.State = "bound"
	l.LastError = ""
	leaseDetails(l, ack)
}

// leaseDetails copies into l, for display, the options of ack the agent
// does not act on, and every option decoded.
func leaseDetails(l *Lease, ack *dhcpv4.DHCPv4) {
	l.Domain = ack.DomainName()
	l.Search = nil
	if s := ack.DomainSearch(); s != nil {
		l.Search = slices.Clone(s.Labels)
	}
	l.NTP = nil
	for _, ip := range ack.NTPServers() {
		l.NTP = append(l.NTP, ip.String())
	}
	l.MTU = 0
	if b := ack.GetOneOption(dhcpv4.OptionInterfaceMTU); len(b) == 2 {
		l.MTU = int(b[0])<<8 | int(b[1])
	}
	l.Routes = nil
	for _, r := range ack.ClasslessStaticRoute() {
		l.Routes = append(l.Routes, fmt.Sprintf("%s via %s", r.Dest, r.Router))
	}
	l.Options = nil
	codes := slices.Sorted(maps.Keys(ack.Options))
	for _, c := range codes {
		// Summary prints "    <name>: <value>\n".
		s := strings.TrimSpace(dhcpv4.Options{c: ack.Options[c]}.Summary(nil))
		name, value, _ := strings.Cut(s, ": ")
		l.Options = append(l.Options, DHCPOption{Code: int(c), Name: name, Value: value})
	}
}

func (m *dhcpManager) removeLease(k dhcpKey, lease *nclient4.Lease) {
	pfx := leasePrefix(lease)
	if !pfx.IsValid() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = m.run.Run(ctx, k.netns, "ip", "addr", "del", pfx.String(), "dev", k.iface)
	changed := m.update(k, func(l *Lease) {
		*l = Lease{Instance: l.Instance, Interface: l.Interface, State: "requesting", LastError: l.LastError}
	})
	if changed && m.onChange != nil {
		go m.onChange(k.instance)
	}
}

// newClientInNetns opens the DHCP client's raw socket inside the named
// network namespace.
func newClientInNetns(nsName, iface string) (*nclient4.Client, error) {
	var c *nclient4.Client
	err := withNetns(nsName, func() error {
		var err error
		c, err = nclient4.New(iface, nclient4.WithTimeout(5*time.Second), nclient4.WithRetry(3))
		return err
	})
	return c, err
}

// withNetns runs fn with the calling thread in the named network namespace
// ("" is the root namespace, where the agent runs: fn runs directly).
// A socket stays in the namespace it was created in, so fn only has to
// create its sockets there. It runs on a throwaway goroutine that never
// unlocks its OS thread: when it exits, the Go runtime destroys the thread
// instead of reusing it in the wrong namespace.
func withNetns(nsName string, fn func() error) error {
	if nsName == "" {
		return fn()
	}
	ch := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		target, err := netns.GetFromName(nsName)
		if err != nil {
			ch <- fmt.Errorf("netns %s: %w", nsName, err)
			return
		}
		defer target.Close()
		if err := netns.Set(target); err != nil {
			ch <- err
			return
		}
		ch <- fn()
	}()
	return <-ch
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
