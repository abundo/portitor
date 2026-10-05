// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

// TunnelBrokerURL is Hurricane Electric's endpoint update API (dyndns2:
// hostname is the tunnel id, myip the new IPv4 endpoint; without myip the
// request's source address).
var TunnelBrokerURL = "https://ipv4.tunnelbroker.net/nic/update"

// How often the endpoint is sent again: after a failure the broker may
// recover from, and unchanged, so an address the agent can't see (behind
// NAT) is corrected within a day. The broker blocks clients that update
// much more often.
const (
	tunnelBrokerRetry   = 5 * time.Minute
	tunnelBrokerRefresh = 24 * time.Hour
)

// tunnelBrokerItem is a 6in4 tunnel with a tunnel broker account, as the
// applied document declares it.
type tunnelBrokerItem struct {
	instance, netns, iface string
	tunnel                 fwconfig.Tunnel6in4
	broker                 fwconfig.TunnelBroker
}

// tunnelBrokerManager tells the tunnel broker each tunnel's IPv4 endpoint
// when the instance's addresses change. Requests are made from the
// instance's network namespace, so the broker sees its address.
type tunnelBrokerManager struct {
	dryRun bool
	run    Runner

	mu   sync.Mutex
	runs map[[2]string]*tunnelBrokerRun
	wg   sync.WaitGroup
}

type tunnelBrokerRun struct {
	item   tunnelBrokerItem
	cancel context.CancelFunc

	mu     sync.Mutex
	status TunnelBrokerStatus
}

func newTunnelBrokerManager(dryRun bool, run Runner) *tunnelBrokerManager {
	return &tunnelBrokerManager{dryRun: dryRun, run: run, runs: map[[2]string]*tunnelBrokerRun{}}
}

// Reconcile starts updating new tunnels, restarts changed ones and stops
// removed ones.
func (m *tunnelBrokerManager) Reconcile(want []tunnelBrokerItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := map[[2]string]bool{}
	for _, it := range want {
		k := [2]string{it.instance, it.iface}
		keep[k] = true
		if r, ok := m.runs[k]; ok {
			if reflect.DeepEqual(r.item, it) {
				continue
			}
			r.cancel()
		}
		m.runs[k] = m.start(it)
	}
	for k, r := range m.runs {
		if !keep[k] {
			r.cancel()
			delete(m.runs, k)
		}
	}
}

func (m *tunnelBrokerManager) Stop() {
	m.Reconcile(nil)
	m.wg.Wait()
}

func (m *tunnelBrokerManager) start(it tunnelBrokerItem) *tunnelBrokerRun {
	ctx, cancel := context.WithCancel(context.Background())
	r := &tunnelBrokerRun{item: it, cancel: cancel,
		status: TunnelBrokerStatus{Instance: it.instance, Interface: it.iface, State: "pending"}}
	if m.dryRun {
		r.status.State = "dry-run"
		return r
	}
	log := slog.With("instance", it.instance, "tunnel", it.iface)
	changed := make(chan struct{}, 1)
	m.wg.Add(2)
	go func() {
		defer m.wg.Done()
		watchNetnsAddrs(ctx, it.netns, changed, log)
	}()
	go func() {
		defer m.wg.Done()
		r.run(ctx, m.run, changed, log)
	}()
	return r
}

// Status returns every tunnel's state, by instance and interface.
func (m *tunnelBrokerManager) Status() []TunnelBrokerStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TunnelBrokerStatus, 0, len(m.runs))
	for _, r := range m.runs {
		r.mu.Lock()
		out = append(out, r.status)
		r.mu.Unlock()
	}
	slices.SortFunc(out, func(a, b TunnelBrokerStatus) int {
		if c := strings.Compare(a.Instance, b.Instance); c != 0 {
			return c
		}
		return strings.Compare(a.Interface, b.Interface)
	})
	return out
}

// run sends the endpoint at start, when the address towards the tunnel
// server changes, and again after tunnelBrokerRetry or
// tunnelBrokerRefresh.
func (r *tunnelBrokerRun) run(ctx context.Context, runner Runner, changed <-chan struct{}, log *slog.Logger) {
	it := r.item
	var sent netip.Addr // the source address of the last good update
	var last time.Time  // when the last update was tried
	wait := time.Duration(0)
	for {
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-changed:
				t.Stop()
				// Addresses settle in bursts (a DHCP renew).
				if !sleepCtx(ctx, 2*time.Second) {
					return
				}
			case <-t.C:
			}
		}
		src, err := tunnelSource(it.netns, it.tunnel)
		if err != nil {
			// No route to the server (yet): try when addresses change.
			r.setError(err)
			wait = tunnelBrokerRetry
			continue
		}
		if src == sent && time.Since(last) < tunnelBrokerRefresh {
			wait = time.Until(last.Add(tunnelBrokerRefresh))
			continue
		}
		last = time.Now()
		// The broker pings the endpoint before it takes it: answer pings
		// to the address for a while (render.TunnelBrokerPingSet).
		if _, err := runner.RunInput(ctx, it.netns, []byte(render.TunnelBrokerPingOpen(src.String())), "nft", "-f", "-"); err != nil {
			log.Warn("tunnel broker: answering ping", "err", err)
		}
		myip := tunnelMyIP(it.tunnel, src)
		addr, err := tunnelBrokerUpdate(ctx, it.netns, it.broker, myip)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Warn("tunnel broker update", "err", err)
			r.setError(err)
			sent = netip.Addr{}
			wait = tunnelBrokerRetry
			var perm permanentError
			if errors.As(err, &perm) {
				// Retrying won't help until the address or settings change.
				wait = tunnelBrokerRefresh
			}
			continue
		}
		log.Info("tunnel broker endpoint updated", "address", addr)
		r.mu.Lock()
		now := time.Now()
		r.status.State, r.status.Address, r.status.LastUpdate, r.status.LastError = "ok", addr, &now, ""
		r.mu.Unlock()
		sent = src
		wait = tunnelBrokerRefresh
	}
}

func (r *tunnelBrokerRun) setError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.State, r.status.LastError = "error", err.Error()
}

// tunnelSource is the instance's IPv4 address towards the tunnel server:
// the tunnel's local address, or the route's source.
func tunnelSource(nsName string, t fwconfig.Tunnel6in4) (netip.Addr, error) {
	if t.Local != "" {
		return netip.ParseAddr(t.Local)
	}
	h, err := netlinkHandle(nsName)
	if err != nil {
		return netip.Addr{}, err
	}
	defer h.Close()
	routes, err := h.RouteGet(net.ParseIP(t.Remote))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("no route to the tunnel server %s: %w", t.Remote, err)
	}
	for _, rt := range routes {
		if a, ok := netip.AddrFromSlice(rt.Src); ok && a.Unmap().Is4() {
			return a.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no IPv4 address towards the tunnel server %s", t.Remote)
}

// tunnelMyIP is the endpoint to tell the broker: the local address, or
// the source address when it is public. Behind NAT none, so the broker
// takes the address the request comes from.
func tunnelMyIP(t fwconfig.Tunnel6in4, src netip.Addr) string {
	if t.Local != "" {
		return t.Local
	}
	if src.IsValid() && src.IsGlobalUnicast() && !src.IsPrivate() && !cgnat.Contains(src) {
		return src.String()
	}
	return ""
}

// cgnat is the shared address space of carrier-grade NAT (RFC 6598).
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// permanentError is a broker answer that retrying won't change (wrong
// credentials, unknown tunnel).
type permanentError struct{ msg string }

func (e permanentError) Error() string { return e.msg }

// parseTunnelBrokerAnswer reads the broker's dyndns2 answer: the address
// it now has, or why it refused.
func parseTunnelBrokerAnswer(body string) (string, error) {
	body = strings.TrimSpace(body)
	f := strings.Fields(body)
	if len(f) == 0 {
		return "", errors.New("empty answer from the tunnel broker")
	}
	switch f[0] {
	case "good", "nochg":
		if len(f) > 1 {
			return f[1], nil
		}
		return "", nil
	case "badauth":
		return "", permanentError{"tunnel broker: wrong user name or update key"}
	case "nohost", "!yours", "notfqdn":
		return "", permanentError{"tunnel broker: no such tunnel id in this account"}
	case "abuse":
		return "", permanentError{"tunnel broker: updates blocked for abuse (too many)"}
	}
	// Anything else is a message, such as an endpoint that does not answer
	// ping ("-ERROR: IP is not ICMP pingable").
	if len(body) > 200 {
		body = body[:200]
	}
	return "", fmt.Errorf("tunnel broker: %s", body)
}

// tunnelBrokerUpdate sends the endpoint (myip, or none for the request's
// source) from the namespace and returns the address the broker has.
func tunnelBrokerUpdate(ctx context.Context, nsName string, tb fwconfig.TunnelBroker, myip string) (string, error) {
	q := url.Values{"hostname": {tb.TunnelID}}
	if myip != "" {
		q.Set("myip", myip)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, TunnelBrokerURL+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(tb.Username, tb.UpdateKey)
	req.Header.Set("User-Agent", "portitor-agent")
	client := &http.Client{Transport: netnsTransport(nsName), CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return "", permanentError{"tunnel broker: wrong user name or update key"}
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("tunnel broker: HTTP %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return parseTunnelBrokerAnswer(string(body))
}

// netnsTransport is an HTTP transport whose connections are IPv4, from the
// namespace (names resolved there too), without a proxy.
func netnsTransport(nsName string) *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				if len(host) > 253 || !dnsName.MatchString(host) {
					return nil, fmt.Errorf("%q is not a DNS name", host)
				}
				if ip, err = resolveName(ctx, nsName, host, "ipv4"); err != nil {
					return nil, err
				}
			}
			var conn net.Conn
			err = withNetns(nsName, func() error {
				var e error
				conn, e = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
				return e
			})
			return conn, err
		},
		TLSHandshakeTimeout: 15 * time.Second,
		DisableKeepAlives:   true,
	}
}

// watchNetnsAddrs signals changed on every address change in the
// namespace until ctx is done, subscribing again when the subscription
// fails.
func watchNetnsAddrs(ctx context.Context, nsName string, changed chan<- struct{}, log *slog.Logger) {
	for {
		err := subscribeNetnsAddrs(ctx, nsName, changed)
		if ctx.Err() != nil {
			return
		}
		log.Warn("tunnel broker address events", "err", err)
		if !sleepCtx(ctx, 5*time.Second) {
			return
		}
		notify(changed) // events may have been missed
	}
}

func subscribeNetnsAddrs(ctx context.Context, nsName string, changed chan<- struct{}) error {
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
	err := netlink.AddrSubscribeWithOptions(updates, done, opts)
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
	for {
		select {
		case <-ctx.Done():
			return nil
		case u, ok := <-updates:
			if !ok {
				return errors.New("subscription closed")
			}
			if u.LinkAddress.IP.To4() != nil {
				notify(changed)
			}
		}
	}
}
