// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dyndns

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/abundo/portitor/internal/fwconfig"
)

// fakeNS is an authoritative nameserver in memory: it answers queries from
// its RRsets and applies UPDATEs to them.
type fakeNS struct {
	mu      sync.Mutex
	rrsets  map[string][]dns.RR // "name type"
	updates []*dns.Msg
	refuse  int  // refuse this many more UPDATEs
	ignore  bool // accept UPDATEs without applying them
	down    bool // queries and updates time out
}

func newFakeNS() *fakeNS { return &fakeNS{rrsets: map[string][]dns.RR{}} }

func key(name string, t uint16) string { return strings.ToLower(name) + " " + dns.TypeToString[t] }

func (f *fakeNS) set(rr string) {
	r, err := dns.NewRR(rr)
	if err != nil {
		panic(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	k := key(r.Header().Name, r.Header().Rrtype)
	f.rrsets[k] = append(f.rrsets[k], r)
}

func (f *fakeNS) get(name string, t uint16) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, rr := range f.rrsets[key(name, t)] {
		out = append(out, strings.TrimPrefix(rr.String(), rr.Header().String()))
	}
	return out
}

func (f *fakeNS) updateCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.updates)
}

func (f *fakeNS) exchange(_ *dns.Client, m *dns.Msg, _ string) (*dns.Msg, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errors.New("i/o timeout")
	}
	r := new(dns.Msg)
	r.SetReply(m)
	if m.Opcode == dns.OpcodeUpdate {
		f.updates = append(f.updates, m)
		if f.refuse > 0 {
			f.refuse--
			r.Rcode = dns.RcodeRefused
			return r, nil
		}
		if f.ignore {
			return r, nil
		}
		for _, rr := range m.Ns {
			k := key(rr.Header().Name, rr.Header().Rrtype)
			if rr.Header().Class == dns.ClassANY {
				delete(f.rrsets, k)
			} else {
				f.rrsets[k] = append(f.rrsets[k], rr)
			}
		}
		return r, nil
	}
	q := m.Question[0]
	rrs := f.rrsets[key(q.Name, q.Qtype)]
	if len(rrs) == 0 {
		exists := false
		for k := range f.rrsets {
			exists = exists || strings.HasPrefix(k, strings.ToLower(q.Name)+" ")
		}
		if !exists {
			r.Rcode = dns.RcodeNameError
		}
	}
	r.Answer = append(r.Answer, rrs...)
	return r, nil
}

// iface is a fake interface whose addresses the test changes.
type iface struct {
	mu     sync.Mutex
	v4, v6 net.IP
}

func (i *iface) set(v4, v6 string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.v4, i.v6 = net.ParseIP(v4).To4(), net.ParseIP(v6)
}

func (i *iface) addrs() (net.IP, net.IP, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.v4, i.v6, nil
}

var fixedNow = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

func testClient(t *testing.T, records []fwconfig.DynDNSRecord) (*Client, *fakeNS, *iface) {
	t.Helper()
	cfg, err := NewConfig(fwconfig.DynDNS{Name: "t", Interface: "eth0", Server: "192.0.2.53", Zone: "example.com", Records: records})
	if err != nil {
		t.Fatal(err)
	}
	ns, ifc := newFakeNS(), &iface{}
	c, err := New(cfg, Env{
		Addrs:       ifc.addrs,
		Exchange:    ns.exchange,
		Log:         slog.New(slog.DiscardHandler),
		Now:         func() time.Time { return fixedNow },
		VerifyDelay: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, ns, ifc
}

func TestNewConfig(t *testing.T) {
	cfg, err := NewConfig(fwconfig.DynDNS{
		Server: "2001:db8::53", Zone: "Example.COM", RetryInterval: 60,
		TSIG: &fwconfig.TSIG{Name: "key.example.com", Algorithm: "hmac-sha512", Secret: "c2VjcmV0"},
		Records: []fwconfig.DynDNSRecord{
			{Name: "home", Type: "a"},
			{Name: "@", Type: "AAAA", Value: "2001:DB8::1", TTL: 60},
			{Name: "www.example.com.", Type: "CNAME", Value: "home"},
			{Name: "ext", Type: "CNAME", Value: "host.example.org."},
			{Name: "home", Type: "TXT"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server != "[2001:db8::53]:53" || cfg.Zone != "example.com." || cfg.TSIG.Name != "key.example.com." {
		t.Errorf("server/zone/tsig: %q %q %q", cfg.Server, cfg.Zone, cfg.TSIG.Name)
	}
	if cfg.RetryInterval != time.Minute || cfg.VerifyInterval != time.Hour {
		t.Errorf("intervals: %v %v", cfg.RetryInterval, cfg.VerifyInterval)
	}
	want := []Record{
		{"home.example.com.", "A", 300, ""},
		{"example.com.", "AAAA", 60, "2001:db8::1"},
		{"www.example.com.", "CNAME", 300, "home.example.com."},
		{"ext.example.com.", "CNAME", 300, "host.example.org."},
		{"home.example.com.", "TXT", 300, ""},
	}
	for i, w := range want {
		if cfg.Records[i] != w {
			t.Errorf("record %d: got %+v, want %+v", i, cfg.Records[i], w)
		}
	}
	if !cfg.Records[4].isTimestamp() || cfg.Records[4].isStatic() || cfg.Records[0].isStatic() || !cfg.Records[1].isStatic() {
		t.Error("record kinds")
	}

	for _, bad := range []fwconfig.DynDNSRecord{
		{Name: "h", Type: "MX", Value: "x"},
		{Name: "h", Type: "CNAME"},
		{Name: "h", Type: "A", Value: "2001:db8::1"},
		{Name: "h.example.org.", Type: "A"},
	} {
		if _, err := NewConfig(fwconfig.DynDNS{Server: "192.0.2.1", Zone: "example.com", Records: []fwconfig.DynDNSRecord{bad}}); err == nil {
			t.Errorf("%+v: expected error", bad)
		}
	}
}

func TestSyncUpdatesWhenIncorrect(t *testing.T) {
	c, ns, ifc := testClient(t, []fwconfig.DynDNSRecord{{Name: "home", Type: "A", TTL: 60}, {Name: "home", Type: "AAAA", TTL: 60}})
	ifc.set("198.51.100.7", "2001:db8::7")
	ns.set("home.example.com. 60 IN A 198.51.100.1")

	if err := c.Sync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if ns.updateCount() != 1 {
		t.Fatalf("updates = %d, want 1", ns.updateCount())
	}
	if got := ns.get("home.example.com.", dns.TypeA); len(got) != 1 || !strings.HasSuffix(got[0], "198.51.100.7") {
		t.Errorf("A = %v", got)
	}
	if got := ns.get("home.example.com.", dns.TypeAAAA); len(got) != 1 || !strings.HasSuffix(got[0], "2001:db8::7") {
		t.Errorf("AAAA = %v", got)
	}

	// Now correct: verified, no second UPDATE.
	if err := c.Sync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if ns.updateCount() != 1 {
		t.Fatalf("updates = %d after a matching sync, want 1", ns.updateCount())
	}
	// Forced: an UPDATE even though it matches.
	if err := c.Sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if ns.updateCount() != 2 {
		t.Fatalf("updates = %d after a forced sync, want 2", ns.updateCount())
	}
}

func TestSyncErrorsWhenNoAddress(t *testing.T) {
	c, ns, ifc := testClient(t, []fwconfig.DynDNSRecord{{Name: "home", Type: "AAAA"}})
	ifc.set("198.51.100.7", "")
	if err := c.Sync(context.Background(), false); err == nil || !strings.Contains(err.Error(), "no AAAA address") {
		t.Fatalf("err = %v", err)
	}
	if ns.updateCount() != 0 {
		t.Fatalf("an UPDATE was sent without an address")
	}
}

func TestSyncStaticRecordsAndTimestamp(t *testing.T) {
	c, ns, ifc := testClient(t, []fwconfig.DynDNSRecord{
		{Name: "home", Type: "A"},
		{Name: "home", Type: "TXT"},
		{Name: "www", Type: "CNAME", Value: "home"},
		{Name: "fixed", Type: "A", Value: "192.0.2.10"},
		{Name: "spf", Type: "TXT", Value: "v=spf1 -all"},
	})
	ifc.set("198.51.100.7", "")
	if err := c.Sync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		t    uint16
		want string
	}{
		{"home.example.com.", dns.TypeTXT, `"2026-09-28T12:00:00Z"`},
		{"www.example.com.", dns.TypeCNAME, "home.example.com."},
		{"fixed.example.com.", dns.TypeA, "192.0.2.10"},
		{"spf.example.com.", dns.TypeTXT, `"v=spf1 -all"`},
	} {
		if got := ns.get(tc.name, tc.t); len(got) != 1 || !strings.HasSuffix(got[0], tc.want) {
			t.Errorf("%s %s = %v, want %s", tc.name, dns.TypeToString[tc.t], got, tc.want)
		}
	}

	// An old timestamp alone does not cause an update.
	ns.mu.Lock()
	delete(ns.rrsets, key("home.example.com.", dns.TypeTXT))
	ns.mu.Unlock()
	ns.set(`home.example.com. 300 IN TXT "2020-01-01T00:00:00Z"`)
	if err := c.Sync(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if ns.updateCount() != 1 {
		t.Fatalf("updates = %d, want 1", ns.updateCount())
	}
	// A static record that drifted is fixed, and the timestamp rides along.
	ns.mu.Lock()
	delete(ns.rrsets, key("fixed.example.com.", dns.TypeA))
	ns.mu.Unlock()
	if err := c.reconcile(context.Background(), &lastIPs{}, true, scopeStatic, false); err != nil {
		t.Fatal(err)
	}
	last := ns.updates[len(ns.updates)-1]
	var names []string
	for _, rr := range last.Ns {
		if rr.Header().Class != dns.ClassANY {
			names = append(names, rr.Header().Name+" "+dns.TypeToString[rr.Header().Rrtype])
		}
	}
	if strings.Join(names, ",") != "home.example.com. TXT,www.example.com. CNAME,fixed.example.com. A,spf.example.com. TXT" {
		t.Errorf("static update holds %v", names)
	}
}

func TestUpdateNotVisibleIsRetriedThenFails(t *testing.T) {
	c, ns, ifc := testClient(t, []fwconfig.DynDNSRecord{{Name: "home", Type: "A"}})
	ifc.set("198.51.100.7", "")
	ns.ignore = true
	err := c.Sync(context.Background(), false)
	if err == nil || !strings.Contains(err.Error(), "not reflected") {
		t.Fatalf("err = %v", err)
	}
	if ns.updateCount() != maxUpdateAttempts {
		t.Fatalf("updates = %d, want %d", ns.updateCount(), maxUpdateAttempts)
	}
}

func TestUpdateRejected(t *testing.T) {
	c, ns, ifc := testClient(t, []fwconfig.DynDNSRecord{{Name: "home", Type: "A"}})
	ifc.set("198.51.100.7", "")
	ns.refuse = 1
	if err := c.Sync(context.Background(), false); err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("err = %v", err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRunFollowsAddressAndRetries(t *testing.T) {
	c, ns, ifc := testClient(t, []fwconfig.DynDNSRecord{{Name: "home", Type: "A"}})
	c.cfg.RetryInterval = 50 * time.Millisecond
	ifc.set("198.51.100.7", "")
	changed := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx, changed)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	hasA := func(ip string) func() bool {
		return func() bool {
			got := ns.get("home.example.com.", dns.TypeA)
			return len(got) == 1 && strings.HasSuffix(got[0], ip)
		}
	}
	waitFor(t, "initial update", hasA("198.51.100.7"))
	waitFor(t, "state ok", func() bool { return c.Status().State == "ok" })

	// An event without an address change sends nothing.
	changed <- struct{}{}
	time.Sleep(20 * time.Millisecond)
	if ns.updateCount() != 1 {
		t.Fatalf("updates = %d, want 1", ns.updateCount())
	}

	// The nameserver is down when the address changes: the update is
	// retried until it is back.
	ns.mu.Lock()
	ns.down = true
	ns.mu.Unlock()
	ifc.set("198.51.100.8", "")
	changed <- struct{}{}
	waitFor(t, "error state", func() bool { return c.Status().State == "error" && c.Status().NextRetry != nil })
	ns.mu.Lock()
	ns.down = false
	ns.mu.Unlock()
	waitFor(t, "retried update", hasA("198.51.100.8"))
	waitFor(t, "state ok", func() bool { return c.Status().State == "ok" })
	if s := c.Status(); s.IPv4 != "198.51.100.8" || s.LastError != "" || s.LastUpdate == nil {
		t.Errorf("status %+v", s)
	}
}

// TestTSIGAgainstServer sends a signed update over UDP to a server that
// checks the signature.
func TestTSIGAgainstServer(t *testing.T) {
	const keyName, secret = "ddns-key.example.com.", "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"
	got := make(chan string, 4)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		TsigSecret: map[string]string{keyName: secret},
		MsgAcceptFunc: func(dns.Header) dns.MsgAcceptAction {
			return dns.MsgAccept
		},
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			if r.Opcode == dns.OpcodeUpdate {
				if r.IsTsig() == nil || w.TsigStatus() != nil {
					m.Rcode = dns.RcodeNotAuth
				} else {
					got <- r.Ns[1].String()
				}
				m.SetTsig(keyName, dns.HmacSHA256, 300, time.Now().Unix())
			}
			_ = w.WriteMsg(m)
		}),
	}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	<-started

	cfg, err := NewConfig(fwconfig.DynDNS{
		Server: pc.LocalAddr().String(), Zone: "example.com",
		TSIG:    &fwconfig.TSIG{Name: "ddns-key.example.com", Algorithm: "hmac-sha256", Secret: secret},
		Records: []fwconfig.DynDNSRecord{{Name: "home", Type: "A", TTL: 60}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(cfg, Env{
		Addrs: func() (net.IP, net.IP, error) { return net.ParseIP("198.51.100.7").To4(), nil, nil },
		Log:   slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.performUpdate(t.Context(), cfg.Records, net.ParseIP("198.51.100.7").To4(), nil); err != nil {
		t.Fatal(err)
	}
	if rr := <-got; rr != "home.example.com.\t60\tIN\tA\t198.51.100.7" {
		t.Errorf("server got %q", rr)
	}

	// A wrong secret is refused.
	c.backend.(*rfc2136).tsig = &fwconfig.TSIG{Name: keyName, Algorithm: "hmac-sha256", Secret: "d3Jvbmc="}
	if err := c.performUpdate(t.Context(), cfg.Records, net.ParseIP("198.51.100.7").To4(), nil); err == nil {
		t.Fatal("update with a wrong key accepted")
	}
}

func TestServerByName(t *testing.T) {
	cfg, err := NewConfig(fwconfig.DynDNS{Name: "t", Interface: "eth0", Server: "NS1.example.net:5353", Zone: "example.com",
		Records: []fwconfig.DynDNSRecord{{Name: "home", Type: "A"}}})
	if err != nil {
		t.Fatal(err)
	}
	ns, ifc := newFakeNS(), &iface{}
	ifc.set("198.51.100.7", "")
	var addrs []string
	resolves, fail := 0, false
	now := fixedNow
	c, err := New(cfg, Env{
		Addrs: ifc.addrs,
		Exchange: func(cl *dns.Client, m *dns.Msg, addr string) (*dns.Msg, error) {
			addrs = append(addrs, addr)
			return ns.exchange(cl, m, addr)
		},
		Resolve: func(_ context.Context, host string) (netip.Addr, error) {
			resolves++
			if fail || host != "ns1.example.net" {
				return netip.Addr{}, errors.New("no such host")
			}
			return netip.MustParseAddr("192.0.2.53"), nil
		},
		Log: slog.New(slog.DiscardHandler), Now: func() time.Time { return now }, VerifyDelay: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 3 || slices.ContainsFunc(addrs, func(a string) bool { return a != "192.0.2.53:5353" }) || resolves != 1 {
		t.Errorf("exchanged with %v after %d lookups", addrs, resolves)
	}
	if s := c.Status(); s.Server != "192.0.2.53:5353" {
		t.Errorf("status server %q", s.Server)
	}

	// Looked up again once the address is old; a failure is an error.
	now, fail = now.Add(2*resolveTTL), true
	if err := c.Sync(t.Context(), false); err == nil || !strings.Contains(err.Error(), "resolve nameserver ns1.example.net") {
		t.Fatalf("err = %v", err)
	}
}
