// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/abundo/portitor/internal/fwconfig"
)

// TestDyndnsInNetns runs a client in a real network namespace against a
// nameserver listening inside it: address events, address reads and the
// update socket all have to be in the namespace. It changes the system,
// so it needs root and PORTITOR_NETNS_TEST=1, e.g. in throwaway
// namespaces:
//
//	PORTITOR_NETNS_TEST=1 unshare -rnm sh -c 'mount -t tmpfs none /run && go test -run InNetns ./internal/agent/'
func TestDyndnsInNetns(t *testing.T) {
	if os.Getenv("PORTITOR_NETNS_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root and PORTITOR_NETNS_TEST=1")
	}
	const ns = "fw-ddnstest"
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v %s", strings.Join(args, " "), err, out)
		}
	}
	ip("netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	ip("-n", ns, "link", "set", "lo", "up")
	ip("-n", ns, "link", "add", "wan0", "type", "dummy")
	ip("-n", ns, "link", "set", "wan0", "up")

	// The nameserver listens on the namespace's loopback, which is only
	// reachable from inside it.
	got := make(chan string, 16)
	var pc net.PacketConn
	if err := withNetns(ns, func() (err error) {
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	records := map[string]dns.RR{}
	srv := &dns.Server{PacketConn: pc, MsgAcceptFunc: func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			mu.Lock()
			defer mu.Unlock()
			m := new(dns.Msg)
			m.SetReply(r)
			if r.Opcode == dns.OpcodeUpdate {
				for _, rr := range r.Ns {
					if rr.Header().Class != dns.ClassANY {
						records[rr.Header().Name] = rr
						got <- rr.(*dns.A).A.String()
					}
				}
			} else if rr, ok := records[r.Question[0].Name]; ok {
				m.Answer = []dns.RR{rr}
			}
			_ = w.WriteMsg(m)
		})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	m := newDyndnsManager(false)
	defer m.Stop()
	m.Reconcile([]dyndnsItem{{instance: "test", netns: ns, cfg: fwconfig.DynDNS{
		Name: "home", Interface: "wan0", Server: pc.LocalAddr().String(), Zone: "example.com",
		Records: []fwconfig.DynDNSRecord{{Name: "home", Type: "A"}},
	}}})

	// No address yet: the client reports the error.
	deadline := time.Now().Add(10 * time.Second)
	for m.Status()[0].State != "error" {
		if time.Now().After(deadline) {
			t.Fatalf("status %+v", m.Status())
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Events of other interfaces are ignored: no new attempt (which
	// would move the next retry) before the retry interval.
	time.Sleep(200 * time.Millisecond) // wan0's own link-local events
	next := *m.Status()[0].NextRetry
	ip("-n", ns, "link", "add", "lan0", "type", "dummy")
	ip("-n", ns, "addr", "add", "192.168.1.1/24", "dev", "lan0")
	time.Sleep(200 * time.Millisecond)
	if again := *m.Status()[0].NextRetry; !again.Equal(next) {
		t.Fatalf("an event of another interface caused a new attempt (next retry %v, was %v)", again, next)
	}

	// The address event triggers the update at once.
	for _, addr := range []string{"198.51.100.7", "198.51.100.8"} {
		ip("-n", ns, "addr", "flush", "dev", "wan0")
		ip("-n", ns, "addr", "add", addr+"/24", "dev", "wan0")
		select {
		case a := <-got:
			if a != addr {
				t.Fatalf("published %s, want %s", a, addr)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("no update for %s; status %+v", addr, m.Status())
		}
	}
}
