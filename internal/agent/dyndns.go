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
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/abundo/portitor/internal/dyndns"
	"github.com/abundo/portitor/internal/fwconfig"
)

type dyndnsKey struct{ instance, name string }

// dyndnsItem is a client as the applied document declares it.
type dyndnsItem struct {
	instance, netns string
	cfg             fwconfig.DynDNS
}

// dyndnsManager runs one DNS update client per DynDNS entry. RFC 2136
// updates are sent from its instance's network namespace.
type dyndnsManager struct {
	dryRun bool

	mu      sync.Mutex
	clients map[dyndnsKey]*dyndnsRun
	wg      sync.WaitGroup
}

type dyndnsRun struct {
	item   dyndnsItem
	cancel context.CancelFunc
	// client is nil when it was not started (dry-run, bad config); state
	// and err say why.
	client     *dyndns.Client
	state, err string
}

func newDyndnsManager(dryRun bool) *dyndnsManager {
	return &dyndnsManager{dryRun: dryRun, clients: map[dyndnsKey]*dyndnsRun{}}
}

// Reconcile starts clients for new entries, restarts changed ones and
// stops removed ones. Unchanged clients keep running.
func (m *dyndnsManager) Reconcile(want []dyndnsItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := map[dyndnsKey]bool{}
	for _, it := range want {
		k := dyndnsKey{it.instance, it.cfg.Name}
		keep[k] = true
		if r, ok := m.clients[k]; ok {
			if reflect.DeepEqual(r.item, it) {
				continue
			}
			r.cancel()
		}
		m.clients[k] = m.start(it)
	}
	for k, r := range m.clients {
		if !keep[k] {
			r.cancel()
			delete(m.clients, k)
		}
	}
}

func (m *dyndnsManager) Stop() {
	m.Reconcile(nil)
	m.wg.Wait()
}

func (m *dyndnsManager) start(it dyndnsItem) *dyndnsRun {
	ctx, cancel := context.WithCancel(context.Background())
	r := &dyndnsRun{item: it, cancel: cancel}
	log := slog.With("instance", it.instance, "dyndns", it.cfg.Name, "interface", it.cfg.Interface)
	if m.dryRun {
		log.Info("dry-run: not starting DNS update client")
		r.state = "dry-run"
		return r
	}
	cfg, err := dyndns.NewConfig(it.cfg)
	if err != nil {
		log.Error("DNS update client", "err", err)
		r.state, r.err = "error", err.Error()
		return r
	}
	// A provider's API is called from the host, like IP list downloads.
	client, err := dyndns.New(cfg, dyndns.Env{
		Addrs: func() (net.IP, net.IP, error) { return globalAddrs(it.netns, it.cfg.Interface) },
		// The nameserver is reached from the instance, through its routes
		// and firewall.
		Exchange: func(c *dns.Client, msg *dns.Msg, addr string) (resp *dns.Msg, err error) {
			err = withNetns(it.netns, func() error {
				var e error
				resp, _, e = c.Exchange(msg, addr)
				return e
			})
			return resp, err
		},
		// A nameserver given by name is resolved in the instance too.
		Resolve: func(ctx context.Context, host string) (netip.Addr, error) {
			if len(host) > 253 || !dnsName.MatchString(host) {
				return netip.Addr{}, fmt.Errorf("%q is not a DNS name", host)
			}
			return resolveName(ctx, it.netns, host, "")
		},
		Log: log,
	})
	if err != nil {
		log.Error("DNS update client", "err", err)
		r.state, r.err = "error", err.Error()
		return r
	}
	r.client = client
	changed := make(chan struct{}, 1)
	m.wg.Add(2)
	go func() {
		defer m.wg.Done()
		watchAddrs(ctx, it.netns, it.cfg.Interface, changed, log)
	}()
	go func() {
		defer m.wg.Done()
		r.client.Run(ctx, changed)
	}()
	return r
}

// Status returns every client's state, by instance and name.
func (m *dyndnsManager) Status() []DynDNSStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]DynDNSStatus, 0, len(m.clients))
	for k, r := range m.clients {
		s := DynDNSStatus{Instance: k.instance, Name: k.name, Interface: r.item.cfg.Interface}
		if r.client != nil {
			s.Status = r.client.Status()
		} else {
			s.State, s.LastError = r.state, r.err
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b DynDNSStatus) int {
		if c := strings.Compare(a.Instance, b.Instance); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

// globalAddrs returns the first usable global IPv4 and IPv6 address of an
// interface in a namespace. Tentative, failed and deprecated IPv6
// addresses are skipped, so a renumbered prefix is published once the new
// address is usable.
func globalAddrs(nsName, iface string) (net.IP, net.IP, error) {
	h, err := netlinkHandle(nsName)
	if err != nil {
		return nil, nil, err
	}
	defer h.Close()
	link, err := h.LinkByName(iface)
	if err != nil {
		return nil, nil, err
	}
	addrs, err := h.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, nil, err
	}
	var v4, v6 net.IP
	for _, a := range addrs {
		if !a.IP.IsGlobalUnicast() || a.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED|unix.IFA_F_DEPRECATED) != 0 {
			continue
		}
		if ip4 := a.IP.To4(); ip4 != nil {
			if v4 == nil {
				v4 = ip4
			}
		} else if v6 == nil {
			v6 = a.IP
		}
	}
	return v4, v6, nil
}

func netlinkHandle(nsName string) (*netlink.Handle, error) {
	if nsName == "" {
		return netlink.NewHandle(unix.NETLINK_ROUTE)
	}
	ns, err := netns.GetFromName(nsName)
	if err != nil {
		return nil, err
	}
	defer ns.Close()
	return netlink.NewHandleAt(ns, unix.NETLINK_ROUTE)
}

// watchAddrs signals changed on every address change of iface in the
// namespace until ctx is done, subscribing again when the subscription
// fails.
func watchAddrs(ctx context.Context, nsName, iface string, changed chan<- struct{}, log *slog.Logger) {
	for {
		err := subscribeAddrs(ctx, nsName, iface, changed)
		if ctx.Err() != nil {
			return
		}
		log.Warn("dyndns address events", "err", err)
		if !sleepCtx(ctx, 5*time.Second) {
			return
		}
		notify(changed) // events may have been missed
	}
}

func subscribeAddrs(ctx context.Context, nsName, iface string, changed chan<- struct{}) error {
	h, err := netlinkHandle(nsName)
	if err != nil {
		return err
	}
	defer h.Close()
	var opts netlink.AddrSubscribeOptions
	if nsName != "" {
		ns, err := netns.GetFromName(nsName)
		if err != nil {
			return err
		}
		opts.Namespace = &ns
	}
	updates := make(chan netlink.AddrUpdate)
	done := make(chan struct{})
	err = netlink.AddrSubscribeWithOptions(updates, done, opts)
	if opts.Namespace != nil {
		opts.Namespace.Close() // only needed to open the socket
	}
	if err != nil {
		return err
	}
	defer func() {
		close(done)
		for range updates { // the reader closes it when it stops
		}
	}()
	// iface's index, looked up again for events of other indexes: the
	// interface may be created (again) after the subscription.
	index := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case u, ok := <-updates:
			if !ok {
				return errors.New("subscription closed")
			}
			if u.LinkIndex != index {
				link, err := h.LinkByName(iface)
				if err != nil || link.Attrs().Index != u.LinkIndex {
					continue
				}
				index = u.LinkIndex
			}
			notify(changed)
		}
	}
}

func notify(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
