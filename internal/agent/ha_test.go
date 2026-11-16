// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

// gateRunner fakes nft and ip for the gate: nft fails while refuse is set.
type gateRunner struct {
	refuse bool
	// noSecond: the namespace has no second layer (someone's nft took it).
	noSecond bool
	loads    []string
	cmds     []string
	links    string
	chains   string
}

func (r *gateRunner) Run(ctx context.Context, ns, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	switch {
	case name == "nft" && r.noSecond && slices.Contains(args, "inet"):
		return nil, errors.New("no such table")
	case name == "nft":
		return []byte(r.chains), nil
	case strings.HasPrefix(line, "ip -j link"):
		return []byte(r.links), nil
	}
	r.cmds = append(r.cmds, ns+": "+line)
	return nil, nil
}

func (r *gateRunner) RunInput(ctx context.Context, ns string, stdin []byte, name string, args ...string) ([]byte, error) {
	if name == "nft" {
		if r.refuse {
			return nil, errors.New("no such device")
		}
		r.loads = append(r.loads, string(stdin))
		return nil, nil
	}
	return r.Run(ctx, ns, name, args...)
}

func TestGateHeld(t *testing.T) {
	both := `{"nftables":[{"metainfo":{}},{"table":{"name":"portitor_gate"}},
		{"chain":{"name":"ingress","dev":["ens18","ens22"]}},{"chain":{"name":"egress","dev":["ens18","ens22"]}}]}`
	held, err := gateHeld([]byte(both))
	if err != nil || !held["ens18"] || !held["ens22"] {
		t.Errorf("list: %v %v", held, err)
	}
	// One device left is a string, as nft shows it.
	one := `{"nftables":[{"chain":{"name":"ingress","dev":"ens22"}},{"chain":{"name":"egress","dev":"ens22"}}]}`
	if held, err = gateHeld([]byte(one)); err != nil || held["ens18"] || !held["ens22"] {
		t.Errorf("string: %v %v", held, err)
	}
	// None: no dev at all.
	none := `{"nftables":[{"chain":{"name":"ingress"}},{"chain":{"name":"egress"}}]}`
	if held, err = gateHeld([]byte(none)); err != nil || len(held) != 0 {
		t.Errorf("none: %v %v", held, err)
	}
	// Held in one direction only isn't held.
	half := `{"nftables":[{"chain":{"name":"ingress","dev":"ens22"}},{"chain":{"name":"egress"}}]}`
	if held, err = gateHeld([]byte(half)); err != nil || len(held) != 0 {
		t.Errorf("half: %v %v", held, err)
	}
}

func TestGateCheck(t *testing.T) {
	r := &gateRunner{
		links:  `[{"ifname":"ens18","flags":["UP"]},{"ifname":"ens22","flags":["UP"]}]`,
		chains: `{"nftables":[{"chain":{"name":"ingress","dev":"ens22"}},{"chain":{"name":"egress","dev":"ens22"}}]}`,
	}
	g := newGate(r, filepath.Join(t.TempDir(), "gate.json"))
	if err := g.set(t.Context(), "", []string{"ens18", "ens22"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	r.loads = nil
	loose, err := g.check(t.Context())
	if err != nil || !slices.Equal(loose, []string{"ens18"}) {
		t.Fatalf("loose %v, err %v", loose, err)
	}
	// Down first, the gate again, and only then up.
	if !slices.Equal(r.cmds, []string{": ip link set dev ens18 down", ": ip link set dev ens18 up"}) || len(r.loads) != 1 {
		t.Errorf("cmds %q, %d loads", r.cmds, len(r.loads))
	}
	// A device that isn't there isn't loose, and an open gate isn't checked.
	r.cmds, r.links = nil, `[{"ifname":"ens22","flags":["UP"]}]`
	if loose, err = g.check(t.Context()); err != nil || len(loose) != 0 {
		t.Errorf("gone: %v %v", loose, err)
	}
	if err := g.setOpen(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	r.links = `[{"ifname":"ens18","flags":["UP"]},{"ifname":"ens22","flags":["UP"]}]`
	if loose, err = g.check(t.Context()); err != nil || len(loose) != 0 {
		t.Errorf("open: %v %v", loose, err)
	}
}

// A device the kernel took down by moving it comes back as the document
// has it: a standby must not take over with a dead interface.
func TestGateCheckBringsADeviceUpByTheDocument(t *testing.T) {
	r := &gateRunner{
		links:  `[{"ifname":"lan","flags":[]},{"ifname":"off","flags":[]}]`,
		chains: `{"nftables":[{"chain":{"name":"ingress"}},{"chain":{"name":"egress"}}]}`,
	}
	g := newGate(r, filepath.Join(t.TempDir(), "gate.json"))
	if err := g.set(t.Context(), "", []string{"lan", "off"}, nil, []string{"off"}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.check(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.cmds, ": ip link set dev lan up") || slices.Contains(r.cmds, ": ip link set dev off up") {
		t.Errorf("cmds %q", r.cmds)
	}
}

func TestGateClosesByDevicesWhenNftFails(t *testing.T) {
	r := &gateRunner{links: `[{"ifname":"ens18","flags":["UP"]}]`}
	g := newGate(r, filepath.Join(t.TempDir(), "gate.json"))
	if err := g.set(t.Context(), "", []string{"ens18"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	r.refuse = true
	if err := g.setOpen(t.Context(), false); err == nil {
		t.Error("no error from a gate that didn't load")
	}
	if !slices.Contains(r.cmds, ": ip link set dev ens18 down") {
		t.Errorf("not set down: %q", r.cmds)
	}
}

func TestGateRememberedAcrossRestarts(t *testing.T) {
	file := filepath.Join(t.TempDir(), "gate.json")
	r := &gateRunner{}
	g := newGate(r, file)
	if err := g.set(t.Context(), "fw-a", []string{"ens20"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	// A host that left its pair finds the gate it must take away.
	g = newGate(r, file)
	if got := g.namespaces(); !slices.Equal(got, []string{"fw-a"}) {
		t.Fatalf("namespaces %v", got)
	}
	r.loads = nil
	if err := g.remove(t.Context(), "fw-a", true); err != nil {
		t.Fatal(err)
	}
	if len(r.loads) != 1 || strings.Contains(r.loads[0], "chain") {
		t.Errorf("loads %q", r.loads)
	}
	if got := g.namespaces(); len(got) != 0 {
		t.Errorf("namespaces %v", got)
	}
}

// A host that leaves its pair while active must not reload an open gate
// when it joins one again: it would be open on the wire, as a standby.
func TestGateClosedAfterLeavingAPair(t *testing.T) {
	r := &gateRunner{}
	g := newGate(r, filepath.Join(t.TempDir(), "gate.json"))
	if err := g.set(t.Context(), "", []string{"ens18"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.setOpen(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if err := g.remove(t.Context(), "", true); err != nil {
		t.Fatal(err)
	}
	if g.isOpen() {
		t.Error("still open after leaving")
	}
	r.loads = nil
	if err := g.set(t.Context(), "", []string{"ens18"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(r.loads) != 1 || !strings.Contains(r.loads[0], "policy drop") {
		t.Errorf("joining: %q", r.loads)
	}
}

func TestPlanHARules(t *testing.T) {
	m := &haMgmt{dev: "ens21", gateway: "172.25.38.10", addrs: []netip.Prefix{netip.MustParsePrefix("172.25.38.1/24")}}
	lines := func(cmds []command) []string {
		var out []string
		for _, c := range cmds {
			out = append(out, strings.Join(c.Args, " "))
		}
		return out
	}
	got := lines(planHARules("-4", m, true, nil))
	want := []string{
		"-4 rule add pref 1000 from 172.25.38.1 lookup 6800 proto 99",
		"-4 rule add pref 1001 iif lo lookup main suppress_prefixlength 0 proto 99",
		"-4 rule add pref 1002 iif lo lookup 6800 proto 99",
	}
	if !slices.Equal(got, want) {
		t.Errorf("closed:\n%q\nwant\n%q", got, want)
	}
	// Opening drops the catch-all and keeps the source rule.
	have := []ipRule{
		{Priority: 1000, Src: "172.25.38.1", Table: "6800", Protocol: RouteProto},
		{Priority: 1001, Src: "all", Iif: "lo", Table: "main", Protocol: RouteProto},
		{Priority: 1002, Src: "all", Iif: "lo", Table: "6800", Protocol: RouteProto},
		{Priority: 1100, Src: "10.0.0.1", Iif: "lo", Table: "100", Protocol: RouteProto},
		{Priority: 1000, Src: "192.0.2.1", Table: "6800", Protocol: "static"},
	}
	got = lines(planHARules("-4", m, false, have))
	if !slices.Equal(got, []string{"-4 rule del pref 1001", "-4 rule del pref 1002"}) {
		t.Errorf("open: %q", got)
	}
	if got = lines(planHARules("-4", m, true, have)); len(got) != 0 {
		t.Errorf("in step: %q", got)
	}
	// A host that left its pair loses them all.
	if got = lines(planHARules("-4", nil, false, have)); len(got) != 3 {
		t.Errorf("left: %q", got)
	}
	// The other IP version wants none.
	if got = lines(planHARules("-6", m, true, nil)); len(got) != 0 {
		t.Errorf("ipv6: %q", got)
	}
	// With the peer as the gateway, the open host keeps none: its own
	// traffic leaves by its traffic interfaces.
	pm := *m
	pm.peer = true
	if got = lines(planHARules("-4", &pm, false, have)); len(got) != 3 {
		t.Errorf("peer gateway, open: %q", got)
	}
	if got = lines(planHARules("-4", &pm, true, nil)); !slices.Equal(got, want) {
		t.Errorf("peer gateway, closed: %q", got)
	}
}

func TestPlanHARoutes(t *testing.T) {
	m := &haMgmt{dev: "ens21", gateway: "172.25.38.10", addrs: []netip.Prefix{netip.MustParsePrefix("172.25.38.1/24")}}
	lines := func(cmds []command) []string {
		var out []string
		for _, c := range cmds {
			out = append(out, strings.Join(c.Args, " "))
		}
		return out
	}
	got := lines(planHARoutes("-4", m, nil))
	want := []string{
		"-4 route add 172.25.38.0/24 dev ens21 src 172.25.38.1 table 6800 proto 99",
		"-4 route add default via 172.25.38.10 dev ens21 src 172.25.38.1 table 6800 proto 99",
	}
	if !slices.Equal(got, want) {
		t.Errorf("new:\n%q\nwant\n%q", got, want)
	}
	have := []tableRoute{
		{Dst: "172.25.38.0/24", Dev: "ens21", Table: "6800"},
		{Dst: "default", Gateway: "172.25.38.10", Dev: "ens21", Table: "6800"},
		{Dst: "default", Gateway: "10.0.0.1", Dev: "ens18", Table: "main"},
	}
	if got = lines(planHARoutes("-4", m, have)); len(got) != 0 {
		t.Errorf("in step: %q", got)
	}
	m.gateway = "172.25.38.11"
	if got = lines(planHARoutes("-4", m, have)); len(got) != 2 || !strings.Contains(got[0], "route del default") {
		t.Errorf("new gateway: %q", got)
	}
	if got = lines(planHARoutes("-4", nil, have)); len(got) != 2 {
		t.Errorf("left: %q", got)
	}
}

func TestPlanLinkSettingsMAC(t *testing.T) {
	want := []fwconfig.Interface{{Name: "ens18", Kind: fwconfig.KindPhysical, Enabled: true, MAC: "02:11:22:33:44:55"}}
	lines := func(have map[string]ipLink) []string {
		var out []string
		for _, c := range planLinkSettings("", want, have) {
			out = append(out, strings.Join(c.Args, " "))
		}
		return out
	}
	got := lines(map[string]ipLink{"ens18": {Address: "bc:24:11:00:00:01", Flags: []string{"UP"}}})
	if !slices.Equal(got, []string{"link set dev ens18 down", "link set dev ens18 address 02:11:22:33:44:55", "link set dev ens18 up"}) {
		t.Errorf("up: %q", got)
	}
	if got = lines(map[string]ipLink{"ens18": {Address: "02:11:22:33:44:55", Flags: []string{"UP"}}}); len(got) != 0 {
		t.Errorf("in step: %q", got)
	}
}

func newTestHA(t *testing.T, node string) *haManager {
	t.Helper()
	dir := t.TempDir()
	h := newHAManager(newGate(&gateRunner{}, filepath.Join(dir, "gate.json")), &watchdog{dry: true}, &gateRunner{}, filepath.Join(dir, "term"))
	h.onActive, h.onTakeover = func() {}, func() {}
	h.cfg = &fwconfig.HA{Node: node}
	return h
}

func TestHAOpensAndCloses(t *testing.T) {
	h := newTestHA(t, fwconfig.HASecondary)
	h.tick(t.Context())
	if h.status().State != agentapi.HAFenced || h.gate.isOpen() {
		t.Fatalf("at start: %+v", h.status())
	}
	h.giveVote(4*time.Second, false)
	h.tick(t.Context())
	st := h.status()
	if st.State != agentapi.HAActive || !h.gate.isOpen() || st.Term != 1 {
		t.Fatalf("with a vote: %+v", st)
	}
	// The term survives a restart, so no two activations share one.
	again := newHAManager(h.gate, h.wd, h.run, h.termFile)
	if again.term != 1 {
		t.Errorf("term after a restart: %d", again.term)
	}
	h.giveVote(0, false)
	h.tick(t.Context())
	if st := h.status(); st.State == agentapi.HAActive || h.gate.isOpen() {
		t.Errorf("without leases: %+v", st)
	}
}

func TestHAPromises(t *testing.T) {
	standby := newTestHA(t, fwconfig.HASecondary)
	active := newTestHA(t, fwconfig.HAPrimary)
	active.active = true
	req := agentapi.HAHeartbeatRequest{Node: fwconfig.HAPrimary, Term: 3, Active: true}
	hb := standby.answer(req)
	if hb.PromiseMS != int(haPromise/time.Millisecond) || hb.Active {
		t.Fatalf("answer %+v", hb)
	}
	sent := time.Now()
	active.answered(sent, &hb)
	if !active.held.Equal(sent.Add(haPromise)) {
		t.Errorf("held from the send: %v", active.held.Sub(sent))
	}
	// The promise keeps the standby closed, whatever vote it gets.
	standby.giveVote(4*time.Second, false)
	standby.tick(t.Context())
	if standby.status().State == agentapi.HAActive {
		t.Error("opened with its promise running")
	}
	// An active host promises nothing.
	if hb := active.answer(agentapi.HAHeartbeatRequest{Node: fwconfig.HASecondary}); hb.PromiseMS != 0 || !hb.Active {
		t.Errorf("active's answer %+v", hb)
	}
}

func TestHAStale(t *testing.T) {
	h := newTestHA(t, fwconfig.HAPrimary)
	h.cfg.Epoch = 1
	h.answer(agentapi.HAHeartbeatRequest{Node: fwconfig.HAPrimary, Epoch: 2})
	h.giveVote(time.Hour, false)
	h.tick(t.Context())
	if st := h.status(); st.State != agentapi.HAStale {
		t.Errorf("state %s", st.State)
	}
	// The secondary's document ends it.
	h.setConfig(&fwconfig.HA{Node: fwconfig.HASecondary, Epoch: 2})
	if h.staleLocked() {
		t.Error("still stale")
	}
}

func TestAnnounceFrames(t *testing.T) {
	mac, _ := net.ParseMAC("02:11:22:33:44:55")
	f := garpFrame(mac, netip.MustParseAddr("192.0.2.1"))
	if len(f) != 42 || f[12] != 0x08 || f[13] != 0x06 || f[21] != 1 || !slices.Equal(f[28:32], f[38:42]) {
		t.Errorf("garp % x", f)
	}
	ip := netip.MustParseAddr("2001:db8::1")
	f = naFrame(mac, ip)
	if f[14+7] != 255 || f[54] != 136 || f[58]&0x20 == 0 {
		t.Errorf("na % x", f)
	}
	// A correct checksum sums to all ones.
	src, dst := ip.As16(), netip.MustParseAddr("ff02::1").As16()
	if icmp6Checksum(src, dst, f[54:]) != 0 {
		t.Error("na checksum")
	}
}

// haNode is a manager with the agent's heartbeat route, over TLS.
type haNode struct {
	h      *haManager
	srv    *httptest.Server
	cancel context.CancelFunc
}

func (n *haNode) url() string { return n.srv.URL }

func (n *haNode) fingerprint() string {
	sum := sha256.Sum256(n.srv.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

func newHANode(t *testing.T) *haNode {
	t.Helper()
	n := &haNode{}
	n.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !n.h.heartbeatAuth(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req agentapi.HAHeartbeatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/v1/ha/handover" {
			if err := n.h.takeHandover(req); err != nil {
				w.WriteHeader(http.StatusConflict)
				return
			}
			_, _ = w.Write([]byte("{}"))
			return
		}
		_ = json.NewEncoder(w).Encode(n.h.answer(req))
	}))
	t.Cleanup(n.srv.Close)
	return n
}

func (n *haNode) start(t *testing.T, node string, peer *haNode, secret string) {
	t.Helper()
	dir := t.TempDir()
	n.h = newHAManager(newGate(&gateRunner{}, filepath.Join(dir, "gate.json")), &watchdog{dry: true}, &gateRunner{}, filepath.Join(dir, "term"))
	n.h.onActive, n.h.onTakeover = func() {}, func() {}
	n.h.cfg = &fwconfig.HA{Node: node, Peer: peer.url(), PeerFingerprint: peer.fingerprint(), Secret: secret}
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	t.Cleanup(cancel)
	go n.h.loop(ctx)
}

func waitHAState(t *testing.T, n *haNode, state string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if n.h.status().State == state {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("not %s within %v: %+v", state, within, n.h.status())
}

// Two managers over real heartbeats: the healthy pair starts without a
// witness, the standby takes over only on a vote and after its promise,
// and a returning primary stays closed: no failback.
func TestHAPairOverHeartbeats(t *testing.T) {
	if testing.Short() {
		t.Skip("takes as long as the leases")
	}
	secret := strings.Repeat("s", 43)
	a, b := newHANode(t), newHANode(t)
	a.start(t, fwconfig.HAPrimary, b, secret)
	b.start(t, fwconfig.HASecondary, a, secret)

	// Rule 3: the primary opens on the secondary's promise alone.
	waitHAState(t, a, agentapi.HAActive, 3*time.Second)
	waitHAState(t, b, agentapi.HAStandby, 3*time.Second)
	// active is set before the gate opens (open runs outside the lock).
	for deadline := time.Now().Add(time.Second); !a.h.gate.isOpen() && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if !a.h.gate.isOpen() || b.h.gate.isOpen() {
		t.Fatalf("gates: %v %v", a.h.gate.isOpen(), b.h.gate.isOpen())
	}
	// A vote changes nothing while the standby hears the active host.
	b.h.giveVote(4*time.Second, false)
	time.Sleep(2 * haBeat)
	if b.h.status().State == agentapi.HAActive {
		t.Fatal("the standby opened while it heard the active host")
	}

	// The primary crashes: gone, as far as its peer can tell.
	a.cancel()
	a.srv.CloseClientConnections()
	a.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	})
	crashed := time.Now()
	for time.Since(crashed) < 2*haPromise {
		b.h.giveVote(4*time.Second, false)
		if b.h.status().State == agentapi.HAActive {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	waitHAState(t, b, agentapi.HAActive, 100*time.Millisecond)
	// Its last promise ran for haPromise from a beat up to haBeat old.
	if took := time.Since(crashed); took < haPromise-2*haBeat {
		t.Errorf("opened after %v, with a promise running", took)
	}
	if st := b.h.status(); st.Term != 2 {
		t.Errorf("term %d", st.Term)
	}

	// The primary returns, with no leases: it stays closed.
	b.h.mu.Lock()
	b.h.cfg.Peer = ""
	b.h.mu.Unlock()
	back := newHANode(t)
	back.start(t, fwconfig.HAPrimary, b, secret)
	b.h.mu.Lock()
	b.h.cfg = &fwconfig.HA{Node: fwconfig.HASecondary, Peer: back.url(), PeerFingerprint: back.fingerprint(), Secret: secret}
	b.h.mu.Unlock()
	for range 40 {
		b.h.giveVote(4*time.Second, false)
		if back.h.status().State == agentapi.HAActive {
			t.Fatal("the primary took back from an active secondary")
		}
		time.Sleep(50 * time.Millisecond)
	}
	waitHAState(t, back, agentapi.HAStandby, time.Second)
	if st := b.h.status(); st.State != agentapi.HAActive {
		t.Errorf("secondary: %+v", st)
	}

	// A switchover moves the traffic back at once, with no vote; the old
	// host's promise carries the new one until its heartbeats do.
	if err := b.h.switchover(); err != nil {
		t.Fatal(err)
	}
	moved := time.Now()
	waitHAState(t, back, agentapi.HAActive, time.Second)
	waitHAState(t, b, agentapi.HAStandby, time.Second)
	if took := time.Since(moved); took > 500*time.Millisecond {
		t.Errorf("the switchover took %v", took)
	}
	time.Sleep(2 * haPromise)
	if back.h.status().State != agentapi.HAActive || b.h.status().State != agentapi.HAStandby {
		t.Errorf("after: %+v, %+v", back.h.status(), b.h.status())
	}
}

func TestHAShouldHandOver(t *testing.T) {
	long := t0.Add(-time.Hour)
	cases := []struct {
		name string
		f    haHealth
		want bool
	}{
		{"better long enough", haHealth{own: 1, peer: 2, peerAlive: true, worseSince: t0.Add(-haMonitorHold)}, true},
		{"better too briefly", haHealth{own: 1, peer: 2, peerAlive: true, worseSince: t0.Add(-time.Second)}, false},
		{"equal", haHealth{own: 2, peer: 2, peerAlive: true, worseSince: long}, false},
		{"worse", haHealth{own: 2, peer: 1, peerAlive: true, worseSince: long}, false},
		{"peer gone", haHealth{own: 1, peer: 2, worseSince: long}, false},
		{"own unknown", haHealth{own: -1, peer: 2, peerAlive: true, worseSince: long}, false},
		{"peer unknown", haHealth{own: 0, peer: -1, peerAlive: true, worseSince: long}, false},
		{"damped", haHealth{own: 1, peer: 2, peerAlive: true, worseSince: long, lastMove: t0.Add(-30 * time.Second)}, false},
		{"damping over", haHealth{own: 1, peer: 2, peerAlive: true, worseSince: long, lastMove: t0.Add(-haDamping)}, true},
	}
	for _, c := range cases {
		c.f.now = t0
		if got := haShouldHandOver(c.f); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestHAPreempt(t *testing.T) {
	back := func(mod func(h *haManager)) *haManager {
		h := &haManager{cfg: &fwconfig.HA{Node: fwconfig.HASecondary, Preempt: true, Epoch: 3},
			peer: agentapi.HAHeartbeat{Node: fwconfig.HAPrimary, Epoch: 3}, health: 2, peerHealth: 2, primaryLost: true}
		if mod != nil {
			mod(h)
		}
		return h
	}
	// says heartbeats the peer from t0 to t0+d and asks at the end.
	says := func(h *haManager, d time.Duration) bool {
		var got bool
		for at := t0; !at.After(t0.Add(d)); at = at.Add(time.Second) {
			h.peerSeen = at
			got = h.preemptSays(at)
		}
		return got
	}
	cases := []struct {
		name string
		mod  func(h *haManager)
		d    time.Duration
		want bool
	}{
		{"back long enough", nil, haPreemptHold, true},
		{"back too briefly", nil, haPreemptHold - time.Second, false},
		{"off", func(h *haManager) { h.cfg.Preempt = false }, haPreemptHold, false},
		{"this is the primary", func(h *haManager) { h.cfg.Node = fwconfig.HAPrimary }, haPreemptHold, false},
		{"primary less healthy", func(h *haManager) { h.peerHealth = 1 }, haPreemptHold, false},
		{"primary healthier", func(h *haManager) { h.peerHealth = 3 }, haPreemptHold, true},
		{"other epoch", func(h *haManager) { h.peer.Epoch = 2 }, haPreemptHold, false},
		{"primary active", func(h *haManager) { h.peer.Active = true }, haPreemptHold, false},
		{"never lost: a switchover", func(h *haManager) { h.primaryLost = false }, time.Hour, false},
		{"health unknown", func(h *haManager) { h.health, h.peerHealth = -1, -1 }, haPreemptHold, false},
		{"damped", func(h *haManager) { h.lastMove = t0.Add(haPreemptHold - time.Second) }, haPreemptHold, false},
	}
	for _, c := range cases {
		if got := says(back(c.mod), c.d); got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
	// A gap in the heartbeats marks the primary lost and starts the hold
	// again.
	h := back(func(h *haManager) { h.primaryLost = false })
	h.peerSeen = t0
	h.preemptSays(t0)
	if h.preemptSays(t0.Add(haDeadAfter)) || !h.primaryLost {
		t.Fatal("primary unheard: not lost, or preempted")
	}
	if !says(h, haPreemptHold) {
		t.Error("primary back after a gap: no preempt")
	}
}

func TestPlanBlackhole(t *testing.T) {
	want := []fwconfig.Route{{Destination: "192.0.2.0/24", Metric: 2147483647, Blackhole: true}}
	lines := func(have []ipRoute) []string {
		var out []string
		for _, c := range planRoutes("", want, have, nil) {
			out = append(out, strings.Join(c.Args, " "))
		}
		return out
	}
	if got := lines(nil); len(got) != 1 || !strings.HasPrefix(got[0], "route replace blackhole 192.0.2.0/24 metric 2147483647") {
		t.Errorf("new: %q", got)
	}
	// There already: it isn't taken for a stale route.
	for _, l := range lines([]ipRoute{{Dst: "192.0.2.0/24", Metric: 2147483647}}) {
		if strings.Contains(l, "route del") {
			t.Errorf("kept: %q", l)
		}
	}
}

func TestPlanHASync(t *testing.T) {
	d := &fwconfig.HASync{Name: "ha-7", Parent: "ens20", Address: "fe80::7:1/64"}
	lines := func(cmds []command) []string {
		var out []string
		for _, c := range cmds {
			out = append(out, c.Netns+": "+strings.Join(c.Args, " "))
		}
		return out
	}
	want := []string{": link add link ens20 name ha-7 netns fw-a type macvlan mode bridge", "fw-a: link set dev ha-7 up", "fw-a: addr add fe80::7:1/64 dev ha-7 nodad"}
	if got := lines(planHASync("fw-a", d, nil)); !slices.Equal(got, want) {
		t.Errorf("new:\n%q", got)
	}
	kernel := ipAddr{Family: "inet6", Local: "fe80::a407:acff:fef3:1701", Prefixlen: 64}
	have := map[string]ipLink{"ha-7": {Flags: []string{"UP"}, AddrInfo: []ipAddr{{Family: "inet6", Local: "fe80::7:1", Prefixlen: 64}, kernel}}}
	if got := lines(planHASync("fw-a", d, have)); len(got) != 0 {
		t.Errorf("in step: %q", got)
	}
	// Promoted: the other node's address goes, and so does an old IPv4 one.
	have["ha-7"] = ipLink{Flags: []string{"UP"}, AddrInfo: []ipAddr{{Family: "inet6", Local: "fe80::7:2", Prefixlen: 64}, {Family: "inet", Local: "169.254.16.30", Prefixlen: 30}, kernel}}
	if got := lines(planHASync("fw-a", d, have)); !slices.Equal(got, []string{"fw-a: addr del fe80::7:2/64 dev ha-7", "fw-a: addr del 169.254.16.30/30 dev ha-7", "fw-a: addr add fe80::7:1/64 dev ha-7 nodad"}) {
		t.Errorf("swapped: %q", got)
	}
}

// The vote goes along, so the new host stays open if the old one stops,
// and the old host keeps none of it.
func TestHandoverCarriesTheVote(t *testing.T) {
	h := newTestHA(t, fwconfig.HASecondary)
	if err := h.takeHandover(agentapi.HAHeartbeatRequest{Node: fwconfig.HAPrimary, VoteMS: 3000}); err != nil {
		t.Fatal(err)
	}
	h.tick(t.Context())
	h.held = time.Time{} // the old host is gone
	h.tick(t.Context())
	if st := h.status(); st.State != agentapi.HAActive || st.VoteUntil == nil {
		t.Fatalf("after: %+v", st)
	}
	old := newTestHA(t, fwconfig.HAPrimary)
	old.active = true
	old.giveVote(4*time.Second, false)
	old.handOver(t.Context(), "test")
	if st := old.status(); st.VoteUntil != nil || st.State == agentapi.HAActive {
		t.Errorf("old host: %+v", st)
	}
}

// A host that gave its vote away takes none until its promise has ended:
// a witness that can't ask the new host would hand it straight back.
func TestNoVoteAfterHandover(t *testing.T) {
	old := newTestHA(t, fwconfig.HAPrimary)
	old.active = true
	old.giveVote(4*time.Second, false)
	old.handOver(t.Context(), "test")
	old.giveVote(4*time.Second, false)
	if st := old.status(); st.VoteUntil != nil {
		t.Errorf("took a vote: %+v", st)
	}
	// The console decides for itself.
	old.giveVote(4*time.Second, true)
	if st := old.status(); st.VoteUntil == nil {
		t.Errorf("refused the console: %+v", st)
	}
	// A restart may have forgotten a handover.
	h := newTestHA(t, fwconfig.HASecondary)
	h.boot(t.Context(), h.cfg, nil, nil)
	h.giveVote(4*time.Second, false)
	if st := h.status(); st.VoteUntil != nil {
		t.Errorf("took a vote after a restart: %+v", st)
	}
}

func TestHandoverRefused(t *testing.T) {
	h := newTestHA(t, fwconfig.HASecondary)
	if err := h.takeHandover(agentapi.HAHeartbeatRequest{Node: fwconfig.HAPrimary, Active: true}); err == nil {
		t.Error("from a peer that is still active")
	}
	h.wdKind = agentapi.HAWatchdogNone
	if err := h.takeHandover(agentapi.HAHeartbeatRequest{Node: fwconfig.HAPrimary}); err == nil {
		t.Error("without a watchdog")
	}
	h.wdKind = ""
	h.active = true
	if err := h.takeHandover(agentapi.HAHeartbeatRequest{Node: fwconfig.HAPrimary}); err == nil {
		t.Error("to an active host")
	}
	if err := newTestHA(t, fwconfig.HAPrimary).switchover(); err == nil {
		t.Error("a switchover from a closed host")
	}
}

// A handover opens the standby at once, with no vote, in spite of the
// promise it gave, and the old host stays closed.
func TestHandover(t *testing.T) {
	h := newTestHA(t, fwconfig.HASecondary)
	h.answer(agentapi.HAHeartbeatRequest{Node: fwconfig.HAPrimary, Active: true, Term: 4})
	h.tick(t.Context())
	if h.status().State == agentapi.HAActive {
		t.Fatal("opened on its own")
	}
	if err := h.takeHandover(agentapi.HAHeartbeatRequest{Node: fwconfig.HAPrimary, Term: 4}); err != nil {
		t.Fatal(err)
	}
	h.tick(t.Context())
	if st := h.status(); st.State != agentapi.HAActive || st.Term != 5 || st.PromiseUntil == nil || st.VoteUntil != nil {
		t.Fatalf("after: %+v", st)
	}
	h.tick(t.Context())
	if h.status().State != agentapi.HAActive {
		t.Error("closed again on the promise of the handover")
	}
}

// The standby takes the active peer's DHCP leases; the active host, or a
// sender of an older term, doesn't get them in.
func TestTakesLeases(t *testing.T) {
	h := &haManager{}
	if h.takesLeases(5) == nil {
		t.Error("took leases off a pair")
	}
	h.cfg = &fwconfig.HA{Node: fwconfig.HASecondary}
	h.term, h.peer.Term = 4, 7
	if err := h.takesLeases(7); err != nil {
		t.Errorf("standby refused the current term: %v", err)
	}
	if h.takesLeases(6) == nil {
		t.Error("took leases of an older term")
	}
	h.active = true
	if h.takesLeases(9) == nil {
		t.Error("the active host took leases")
	}
}

// A kernel that refuses the second layer still gets the netdev gate, and an
// open gate leaves no second layer behind to drop.
func TestGateFallsBackToNetdev(t *testing.T) {
	r := &secondRefuser{gateRunner: gateRunner{links: `[{"ifname":"ens18","flags":["UP"]}]`}}
	g := newGate(r, filepath.Join(t.TempDir(), "gate.json"))
	if err := g.set(t.Context(), "", []string{"ens18"}, []string{"ens18", "ens18.5"}, nil); err != nil {
		t.Fatalf("closing: %v", err)
	}
	if len(r.loads) == 0 || !strings.Contains(r.loads[len(r.loads)-1], "policy drop;") {
		t.Fatalf("no netdev gate: %q", r.loads)
	}
	r.loads = nil
	if err := g.setOpen(t.Context(), true); err != nil {
		t.Fatalf("opening: %v", err)
	}
	for _, fam := range []string{"inet", "arp", "bridge"} {
		if !slices.ContainsFunc(r.loads, func(l string) bool { return strings.Contains(l, "delete table "+fam+" portitor_gate") }) {
			t.Errorf("open leaves the %s table: %q", fam, r.loads)
		}
	}
}

// The second layer's names are remembered, and loaded with the gate.
func TestGateCoverRemembered(t *testing.T) {
	file := filepath.Join(t.TempDir(), "gate.json")
	r := &gateRunner{}
	g := newGate(r, file)
	if err := g.set(t.Context(), "fw-a", []string{"ens20"}, []string{"ens20", "br0"}, nil); err != nil {
		t.Fatal(err)
	}
	g = newGate(r, file)
	r.loads = nil
	if err := g.setOpen(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if len(r.loads) != 1 || !strings.Contains(r.loads[0], `iifname { "ens20", "br0" } drop`) {
		t.Errorf("loads %q", r.loads)
	}
}

// secondRefuser refuses any transaction with the second layer in it.
type secondRefuser struct{ gateRunner }

func (r *secondRefuser) RunInput(ctx context.Context, ns string, stdin []byte, name string, args ...string) ([]byte, error) {
	if name == "nft" && strings.Contains(string(stdin), "table inet portitor_gate {") {
		return nil, errors.New("not supported")
	}
	return r.gateRunner.RunInput(ctx, ns, stdin, name, args...)
}

// A second layer someone took away is loaded again, with no device down.
func TestGateCheckRestoresTheSecondLayer(t *testing.T) {
	r := &gateRunner{
		links:  `[{"ifname":"ens18","flags":["UP"]}]`,
		chains: `{"nftables":[{"chain":{"name":"ingress","dev":"ens18"}},{"chain":{"name":"egress","dev":"ens18"}}]}`,
	}
	g := newGate(r, filepath.Join(t.TempDir(), "gate.json"))
	if err := g.set(t.Context(), "", []string{"ens18"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	r.loads, r.noSecond = nil, true
	loose, err := g.check(t.Context())
	if err != nil || len(loose) != 0 {
		t.Fatalf("loose %v, err %v", loose, err)
	}
	if len(r.loads) != 1 || !strings.Contains(r.loads[0], "table inet portitor_gate {") {
		t.Errorf("loads %q", r.loads)
	}
	if len(r.cmds) != 0 {
		t.Errorf("commands %q", r.cmds)
	}
}

// Once the kernel refused the second layer, check doesn't try it each
// second; an apply does.
func TestGateRefusedSecondLayerNotRetried(t *testing.T) {
	r := &secondRefuser{gateRunner: gateRunner{links: `[{"ifname":"ens18","flags":["UP"]}]`, noSecond: true,
		chains: `{"nftables":[{"chain":{"name":"ingress","dev":"ens18"}},{"chain":{"name":"egress","dev":"ens18"}}]}`}}
	g := newGate(r, filepath.Join(t.TempDir(), "gate.json"))
	if err := g.set(t.Context(), "", []string{"ens18"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	r.loads = nil
	if _, err := g.check(t.Context()); err != nil || len(r.loads) != 0 {
		t.Errorf("err %v, loads %q", err, r.loads)
	}
}

// Devices lost while a re-apply runs get one more: the running one may
// have read them before they went.
func TestReapplyAgainWhileRunning(t *testing.T) {
	h := &haManager{}
	started, release := make(chan struct{}, 4), make(chan struct{})
	var runs atomic.Int32
	h.onLoose = func() {
		runs.Add(1)
		started <- struct{}{}
		<-release
	}
	h.reapply()
	<-started
	h.reapply() // lost again while the first runs
	h.reapply() // and again: still one more, not two
	release <- struct{}{}
	<-started
	release <- struct{}{}
	deadline := time.Now().Add(2 * time.Second)
	for h.reapplying.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if n := runs.Load(); n != 2 {
		t.Errorf("onLoose ran %d times, want 2", n)
	}
}
