// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/vishvananda/netns"
)

type dhcpKey struct{ instance, netns, iface string }

// dhcpManager runs one DHCPv4 client goroutine per WAN interface.
type dhcpManager struct {
	run      Runner
	dryRun   bool
	onChange func(instance string) // called when a lease's DNS servers change

	mu      sync.Mutex
	clients map[dhcpKey]context.CancelFunc
	leases  map[dhcpKey]*Lease
	wg      sync.WaitGroup
}

func newDHCPManager(run Runner, dryRun bool, onChange func(string)) *dhcpManager {
	return &dhcpManager{
		run:      run,
		dryRun:   dryRun,
		onChange: onChange,
		clients:  map[dhcpKey]context.CancelFunc{},
		leases:   map[dhcpKey]*Lease{},
	}
}

// Reconcile starts clients for new keys and stops removed ones.
func (m *dhcpManager) Reconcile(want []dhcpKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, cancel := range m.clients {
		if !slices.Contains(want, k) {
			cancel()
			delete(m.clients, k)
			delete(m.leases, k)
		}
	}
	for _, k := range want {
		if _, ok := m.clients[k]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		m.clients[k] = cancel
		m.leases[k] = &Lease{Instance: k.instance, Interface: k.iface, State: "requesting"}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.loop(ctx, k)
		}()
	}
}

func (m *dhcpManager) Stop() {
	m.Reconcile(nil)
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

// DNSServers returns DNS servers learned per instance.
func (m *dhcpManager) DNSServers() map[string][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string][]string{}
	for k, l := range m.leases {
		for _, d := range l.DNS {
			if !slices.Contains(out[k.instance], d) {
				out[k.instance] = append(out[k.instance], d)
			}
		}
	}
	for _, v := range out {
		slices.Sort(v)
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

func (m *dhcpManager) loop(ctx context.Context, k dhcpKey) {
	log := slog.With("instance", k.instance, "interface", k.iface)
	if m.dryRun {
		log.Info("dry-run: not starting DHCP client")
		m.update(k, func(l *Lease) { l.State = "dry-run" })
		return
	}
	backoff := 5 * time.Second
	var current *nclient4.Lease
	var client *nclient4.Client
	defer func() {
		if client != nil {
			if current != nil {
				_ = client.Release(current)
				m.removeLease(k, current)
			}
			client.Close()
		}
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
			m.fail(k, log, err)
			if current != nil && time.Now().After(current.CreationTime.Add(current.ACK.IPAddressLeaseTime(time.Hour))) {
				m.removeLease(k, current)
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

func (m *dhcpManager) installLease(ctx context.Context, k dhcpKey, old, lease *nclient4.Lease) error {
	ack := lease.ACK
	mask := ack.SubnetMask()
	if mask == nil {
		mask = ack.YourIPAddr.DefaultMask()
	}
	ones, _ := mask.Size()
	addr, ok := netip.AddrFromSlice(ack.YourIPAddr.To4())
	if !ok {
		return fmt.Errorf("lease without IPv4 address")
	}
	pfx := netip.PrefixFrom(addr, ones)
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
		if _, err := m.run.Run(ctx, k.netns, "ip", "route", "replace", "default", "via", router,
			"dev", k.iface, "proto", "dhcp", "metric", strconv.Itoa(DHCPRouteMetric)); err != nil {
			return err
		}
	}
	var dns []string
	for _, ip := range ack.DNS() {
		dns = append(dns, ip.String())
	}
	slices.Sort(dns)
	var server string
	if s := ack.ServerIdentifier(); s != nil {
		server = s.String()
	}
	changed := m.update(k, func(l *Lease) {
		l.Address = pfx.String()
		l.Router = router
		l.DNS = dns
		l.Server = server
		l.Obtained = lease.CreationTime
		l.Expires = lease.CreationTime.Add(leaseTime)
		l.RenewAfter = time.Now().Add(ack.IPAddressRenewalTime(leaseTime / 2))
		l.State = "bound"
		l.LastError = ""
	})
	if changed && m.onChange != nil {
		go m.onChange(k.instance)
	}
	return nil
}

func (m *dhcpManager) removeLease(k dhcpKey, lease *nclient4.Lease) {
	ack := lease.ACK
	ones, _ := ack.SubnetMask().Size()
	if ack.SubnetMask() == nil {
		ones, _ = ack.YourIPAddr.DefaultMask().Size()
	}
	addr, ok := netip.AddrFromSlice(ack.YourIPAddr.To4())
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = m.run.Run(ctx, k.netns, "ip", "addr", "del", netip.PrefixFrom(addr, ones).String(), "dev", k.iface)
	changed := m.update(k, func(l *Lease) {
		l.Address, l.Router, l.DNS, l.State = "", "", nil, "requesting"
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
