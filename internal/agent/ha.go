// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/fwconfig"
)

// An HA host (fwconfig.HA) is active or closed: the gate (gate.go) opens
// or closes its traffic interfaces and nothing else changes, so the
// services keep running on the standby and a takeover starts nothing. The
// rules are haDecide's. The loop looks at the leases every haTick and acts
// itself, never through an apply: it takes no Agent lock, so closing
// doesn't wait for a commit. It alone feeds the watchdog.
//
// A primary whose peer answers as primary at a higher epoch was taken
// over: its secondary was promoted while it was away. It is stale and
// closed until it is given the document of the secondary it now is (by the
// new primary's portitor-config), and its own portitor-config copies the
// new primary's configuration.
const (
	// haMaxVote is the longest vote the witness or the console grants.
	haMaxVote = 24 * time.Hour
	// haGateCheck is how often a closed gate is checked.
	haGateCheck = time.Second
	// haActionTimeout bounds opening or closing the gate.
	haActionTimeout = time.Second
)

type haManager struct {
	gate     *gate
	wd       *watchdog
	run      Runner
	termFile string

	mu  sync.Mutex
	cfg *fwconfig.HA
	// active: the gate is open, or opening or closing. So a closing host
	// still answers as active.
	active bool
	term   int64
	// vote and forced are the witness's or the console's vote.
	vote   time.Time
	forced bool
	// held is the end of the peer's promise, given of this host's.
	held, given time.Time
	// noVoteUntil: this host gave its vote away, or may have before a
	// restart. Until then it takes none: the witness, if it can't ask the
	// peer, would hand back the vote the peer holds.
	noVoteUntil time.Time
	peerSeen    time.Time
	peer        agentapi.HAHeartbeat
	// clients are the two paths' agent clients, reused for their
	// connections.
	clients map[string]*agentclient.Client
	// wdKind is what watchdog this host has, once looked for.
	wdKind string
	// health and peerHealth are the monitored interfaces with a carrier,
	// -1 for not known; worseSince is since when the peer has been better,
	// and lastMove the last monitored handover.
	health, peerHealth int
	worseSince         time.Time
	lastMove           time.Time
	// monitored are the devices that count, by namespace.
	monitored map[string][]string
	// handover: the peer has closed and told this host to open.
	handover bool
	// switching asks tick to hand over; stopping ends it.
	switching, stopping bool
	// wake gets tick to look at once.
	wake chan struct{}
	// mgmt is what the routing for the host's own traffic is made from.
	mgmt *haMgmt
	own  map[string]bool
	// rules serialises changes to the management rules.
	rules sync.Mutex

	// onActive follows the host's state, onTakeover runs after it opened.
	onActive   func()
	onTakeover func()
	// syncCerts copies the peer's certificates, every haCertSync while
	// the host is closed.
	syncCerts func(context.Context, *fwconfig.HA)
}

func newHAManager(g *gate, wd *watchdog, run Runner, termFile string) *haManager {
	h := &haManager{gate: g, wd: wd, run: run, termFile: termFile, clients: map[string]*agentclient.Client{},
		health: -1, peerHealth: -1, wake: make(chan struct{}, 1)}
	if b, err := os.ReadFile(termFile); err == nil {
		h.term, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	return h
}

// isStandby tells whether the host leaves the DNS updates and the tunnel
// broker to its peer: any host in a pair that isn't active.
func (h *haManager) isStandby() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfg != nil && !h.active
}

// staleLocked tells whether the host is a primary taken over by its
// peer's promotion; h.mu held.
func (h *haManager) staleLocked() bool {
	return h.cfg != nil && h.cfg.Node == fwconfig.HAPrimary && h.peer.Node == fwconfig.HAPrimary && h.peer.Epoch > h.cfg.Epoch
}

// heard records the peer's word; h.mu held.
func (h *haManager) heard(now time.Time, node string, epoch, term int64, active bool, health int) {
	h.peerSeen = now
	h.peer.Node, h.peer.Epoch, h.peer.Term, h.peer.Active = node, epoch, term, active
	h.peerHealth = health
}

// boot closes a restarted host's gates: it has forgotten its leases, and
// waits out any promise it may have given, a handover's the longest.
func (h *haManager) boot(ctx context.Context, cfg *fwconfig.HA, devs map[string][]string) {
	h.mu.Lock()
	h.cfg = cfg
	if cfg != nil {
		h.given = time.Now().Add(haVoteMax)
		h.noVoteUntil = h.given
	}
	h.mu.Unlock()
	if cfg == nil {
		return
	}
	for ns, d := range devs {
		if err := h.gate.set(ctx, ns, d, nil); err != nil {
			slog.Error("ha: closing the gate at start", "netns", ns, "err", err)
		}
	}
}

// setConfig follows the applied document. A host leaving its pair is
// disarmed; apply takes its gates away.
func (h *haManager) setConfig(cfg *fwconfig.HA) {
	h.mu.Lock()
	left := cfg == nil && h.active
	h.cfg = cfg
	if left {
		h.active = false
	}
	h.mu.Unlock()
	if left {
		h.wd.disarm()
		go h.onActive()
	}
}

// epoch is the applied document's epoch, 0 outside a pair.
func (h *haManager) epoch() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil {
		return 0
	}
	return h.cfg.Epoch
}

// giveVote records the witness's vote, or the console's, for d.
func (h *haManager) giveVote(d time.Duration, forced bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if !forced && now.Before(h.noVoteUntil) {
		return
	}
	h.vote, h.forced = now.Add(min(d, haMaxVote)), forced
}

// facts is what haDecide needs; h.mu held.
func (h *haManager) facts(now time.Time) haFacts {
	return haFacts{now: now, primary: h.cfg.Node == fwconfig.HAPrimary, active: h.active, stale: h.staleLocked(),
		term: h.term, vote: h.vote, held: h.held, given: h.given, forced: h.forced,
		peerSeen: h.peerSeen, peerActive: h.peer.Active, peerTerm: h.peer.Term,
		noWatchdog: h.wdKind == agentapi.HAWatchdogNone, handover: h.handover}
}

// request is this host's heartbeat; h.mu held and h.cfg set.
func (h *haManager) request() agentapi.HAHeartbeatRequest {
	return agentapi.HAHeartbeatRequest{Node: h.cfg.Node, Epoch: h.cfg.Epoch, Term: h.term, Active: h.active, Health: h.health}
}

// tick looks at the leases and acts; it feeds the watchdog while active.
func (h *haManager) tick(ctx context.Context) {
	h.mu.Lock()
	if h.cfg == nil || h.stopping {
		h.mu.Unlock()
		return
	}
	now := time.Now()
	mv, why := haDecide(h.facts(now))
	switch mv {
	case haOpen:
		h.term = max(h.term, h.peer.Term) + 1
		h.active, h.handover = true, false
	case haClose:
		// active stays true until the gate is closed.
	default:
		if !h.active {
			h.mu.Unlock()
			return
		}
		hand := h.switching
		reason := "the console asked"
		if h.monitorSays(now) {
			hand, reason = true, "the standby has more monitored interfaces up"
			h.lastMove = now
		}
		h.switching = false
		h.mu.Unlock()
		if hand {
			hctx, cancel := context.WithTimeout(ctx, haActionTimeout)
			defer cancel()
			h.handOver(hctx, reason)
			return
		}
		h.wd.feed()
		return
	}
	term, forced := h.term, h.forced
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, haActionTimeout)
	defer cancel()
	if mv == haOpen {
		h.open(ctx, term, forced, why)
	} else {
		h.closeGate(ctx, why)
	}
}

// open opens the gate: the term is on disk first, so a restarted host
// can't use it twice, and the watchdog armed, so a hung one can't stay.
func (h *haManager) open(ctx context.Context, term int64, forced bool, why string) {
	err := atomicWrite(h.termFile, []byte(strconv.FormatInt(term, 10)+"\n"), 0o644)
	if err == nil {
		err = h.wd.arm()
		if err != nil && forced {
			slog.Warn("ha: opening without a watchdog, by the console's vote", "err", err)
			err = nil
		}
	}
	if err == nil {
		err = h.gate.setOpen(ctx, true)
	}
	if err != nil {
		slog.Error("ha: can't open", "err", err)
		h.closeGate(ctx, "opening failed")
		return
	}
	h.wd.feed()
	slog.Warn("ha: active", "term", term, "why", why)
	go h.onActive()
	go h.onTakeover()
}

// closeGate closes the gate. If neither that nor setting its devices down
// worked, the watchdog stays armed and unfed: the host resets, which
// closes it.
func (h *haManager) closeGate(ctx context.Context, why string) {
	err := h.gate.setOpen(ctx, false)
	if err != nil {
		slog.Error("ha: closing the gate, the host resets unless its devices went down", "err", err)
	} else {
		h.wd.disarm()
	}
	h.mu.Lock()
	h.active = false
	h.mu.Unlock()
	slog.Warn("ha: closed", "why", why)
	go h.onActive()
}

// monitorSays keeps track of the peer's health and tells whether to hand
// over now; h.mu held.
func (h *haManager) monitorSays(now time.Time) bool {
	f := haHealth{now: now, own: h.health, peer: h.peerHealth, peerAlive: now.Sub(h.peerSeen) < haDeadAfter,
		worseSince: h.worseSince, lastMove: h.lastMove}
	if !f.better() {
		h.worseSince = time.Time{}
		return false
	}
	if h.worseSince.IsZero() {
		h.worseSince = now
		return false
	}
	return haShouldHandOver(f)
}

// handOver closes this host and tells its peer to open. It promises to
// stay closed first, and again once the peer has answered, so the peer
// can count from when it got the word. Its vote goes along: this host may
// be stopping, and a peer with only a promise from a host that is gone
// would close again. It gives the vote up before it sends, and promises
// to stay closed for as long as that vote lasts: the witness may still
// renew this host's vote if it can't ask the peer, and this host must not
// open on it while the peer holds the one it was given. A peer that can't
// be told leaves the pair closed until the promise runs out, and then the
// witness decides.
func (h *haManager) handOver(ctx context.Context, why string) {
	h.mu.Lock()
	cfg := h.cfg
	now := time.Now()
	var left time.Duration
	if now.Before(h.vote) {
		left = min(h.vote.Sub(now), haVoteMax)
	}
	promise := max(haPromise, left)
	h.given = now.Add(promise)
	h.noVoteUntil = h.given
	h.vote, h.forced = time.Time{}, false
	var clients []*agentclient.Client
	if cfg != nil {
		for _, u := range []string{cfg.PeerLink, cfg.Peer} {
			if u == "" {
				continue
			}
			if c, err := h.client(cfg, u); err == nil {
				clients = append(clients, c)
			}
		}
	}
	h.mu.Unlock()
	h.closeGate(ctx, "handing over: "+why)
	h.mu.Lock()
	var req agentapi.HAHeartbeatRequest
	if h.cfg != nil {
		req = h.request()
		req.VoteMS = int(left / time.Millisecond)
	}
	h.mu.Unlock()
	var err error
	for _, c := range clients {
		if err = c.HAHandover(ctx, req); err == nil {
			break
		}
	}
	if err != nil {
		slog.Error("ha: the peer can't be told to take over", "err", err)
		return
	}
	h.mu.Lock()
	h.given = time.Now().Add(promise)
	h.noVoteUntil = h.given
	h.mu.Unlock()
}

// takeHandover is the peer's word that it has closed: this host opens at
// once, holding the promise that came with it.
func (h *haManager) takeHandover(req agentapi.HAHeartbeatRequest) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.cfg == nil:
		return errors.New("this host is not in an HA pair")
	case h.active:
		return errors.New("this host is active")
	case req.Active:
		return errors.New("the peer is still active")
	case h.staleLocked():
		return errors.New("this host was taken over by a promotion")
	case h.wdKind == agentapi.HAWatchdogNone:
		return errors.New("this host has no watchdog")
	}
	now := time.Now()
	h.heard(now, req.Node, req.Epoch, req.Term, false, req.Health)
	h.held = now.Add(haPromise)
	h.given, h.noVoteUntil = time.Time{}, time.Time{}
	h.handover = true
	if req.VoteMS > 0 {
		h.vote = now.Add(min(time.Duration(req.VoteMS)*time.Millisecond, haVoteMax))
	}
	select {
	case h.wake <- struct{}{}:
	default:
	}
	return nil
}

// switchover asks the active host to hand over.
func (h *haManager) switchover() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.cfg == nil:
		return errors.New("this host is not in an HA pair")
	case !h.active:
		return errors.New("this host is not active: run it on the active host")
	case time.Since(h.peerSeen) >= haDeadAfter:
		return errors.New("the standby isn't heard: nothing to hand over to")
	}
	h.switching = true
	select {
	case h.wake <- struct{}{}:
	default:
	}
	return nil
}

// shutdown leaves an active host closed for a clean stop, handing over to
// a peer it hears.
func (h *haManager) shutdown() {
	h.mu.Lock()
	h.stopping = true
	active, alive := h.active, time.Since(h.peerSeen) < haDeadAfter
	h.mu.Unlock()
	if !active {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if alive {
		h.handOver(ctx, "the agent is stopping")
		return
	}
	h.closeGate(ctx, "the agent is stopping")
}

// loop runs the HA manager until ctx is cancelled.
func (h *haManager) loop(ctx context.Context) {
	t := time.NewTicker(haTick)
	defer t.Stop()
	go h.beat(ctx, func(c *fwconfig.HA) string { return c.Peer })
	go h.beat(ctx, func(c *fwconfig.HA) string { return c.PeerLink })
	go h.checkGate(ctx)
	go h.copyCerts(ctx)
	go h.watchHealth(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-h.wake:
		}
		h.tick(ctx)
	}
}

// client is the agent client of one path; h.mu held.
func (h *haManager) client(cfg *fwconfig.HA, url string) (*agentclient.Client, error) {
	key := url + "|" + cfg.PeerFingerprint + "|" + cfg.Secret
	if c := h.clients[key]; c != nil {
		return c, nil
	}
	c, err := agentclient.New(url, cfg.Secret, cfg.PeerFingerprint)
	if err != nil {
		return nil, err
	}
	h.clients[key] = c
	return c, nil
}

// beat sends a heartbeat over one path every haBeat, until ctx is
// cancelled. Each path runs apart, so a dead one costs the other nothing.
func (h *haManager) beat(ctx context.Context, path func(*fwconfig.HA) string) {
	t := time.NewTicker(haBeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		h.mu.Lock()
		cfg := h.cfg
		var c *agentclient.Client
		var err error
		var req agentapi.HAHeartbeatRequest
		if cfg != nil && path(cfg) != "" {
			c, err = h.client(cfg, path(cfg))
			req = h.request()
		}
		h.mu.Unlock()
		if c == nil || err != nil {
			continue
		}
		// The lease is counted from before the request left.
		sent := time.Now()
		bctx, cancel := context.WithTimeout(ctx, haBeat)
		hb, err := c.HAHeartbeat(bctx, req)
		cancel()
		if err == nil {
			h.answered(sent, hb)
		}
	}
}

// answered records the peer's answer to a heartbeat sent at sent.
func (h *haManager) answered(sent time.Time, hb *agentapi.HAHeartbeat) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.heard(time.Now(), hb.Node, hb.Epoch, hb.Term, hb.Active, hb.Health)
	if hb.PromiseMS > 0 {
		if until := sent.Add(time.Duration(hb.PromiseMS) * time.Millisecond); until.After(h.held) {
			h.held = until
		}
	}
}

// answer is the host's answer to its peer's heartbeat, with its promise
// when it gives one.
func (h *haManager) answer(req agentapi.HAHeartbeatRequest) agentapi.HAHeartbeat {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil {
		return agentapi.HAHeartbeat{}
	}
	now := time.Now()
	h.heard(now, req.Node, req.Epoch, req.Term, req.Active, req.Health)
	out := agentapi.HAHeartbeat{Node: h.cfg.Node, Epoch: h.cfg.Epoch, Term: h.term, Active: h.active, Health: h.health}
	if haGives(h.active, h.cfg.Node == fwconfig.HAPrimary, req.Active, req.Node == fwconfig.HAPrimary) {
		if until := now.Add(haPromise); until.After(h.given) {
			h.given = until
		}
		out.PromiseMS = int(haPromise / time.Millisecond)
	}
	return out
}

// watchHealth counts the monitored interfaces with a carrier.
func (h *haManager) watchHealth(ctx context.Context) {
	t := time.NewTicker(haBeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		h.mu.Lock()
		want := h.monitored
		h.mu.Unlock()
		if want == nil {
			continue
		}
		health, ok := 0, true
		for ns, devs := range want {
			cctx, cancel := context.WithTimeout(ctx, haBeat)
			out, err := h.run.Run(cctx, ns, "ip", "-j", "link", "show")
			cancel()
			links, lerr := linkMap(out)
			if err != nil || lerr != nil {
				ok = false
				break
			}
			health += carriers(links, devs)
		}
		if ok {
			h.mu.Lock()
			h.health = health
			h.mu.Unlock()
		}
	}
}

// carriers counts the devices with a carrier.
func carriers(links map[string]ipLink, devs []string) int {
	n := 0
	for _, d := range devs {
		if l, ok := links[d]; ok && slices.Contains(l.Flags, "LOWER_UP") {
			n++
		}
	}
	return n
}

// setMonitored follows the applied document: the devices that count.
func (h *haManager) setMonitored(m map[string][]string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.monitored = m
}

// checkGate makes sure a closed gate holds its devices.
func (h *haManager) checkGate(ctx context.Context) {
	t := time.NewTicker(haGateCheck)
	defer t.Stop()
	var once bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		h.mu.Lock()
		cfg := h.cfg
		h.mu.Unlock()
		if cfg == nil {
			continue
		}
		if !once {
			once = true
			kind := h.wd.detect(ctx)
			h.mu.Lock()
			h.wdKind = kind
			h.mu.Unlock()
		}
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		loose, err := h.gate.check(cctx)
		cancel()
		if err != nil {
			slog.Error("ha: checking the gate", "err", err)
		}
		if len(loose) > 0 {
			slog.Error("ha: the closed gate had lost interfaces; closed them again", "interfaces", loose)
		}
	}
}

// copyCerts copies the peer's certificates while the host is closed.
func (h *haManager) copyCerts(ctx context.Context) {
	t := time.NewTicker(haCertSync)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		h.mu.Lock()
		cfg := h.cfg
		alive := cfg != nil && !h.active && time.Since(h.peerSeen) < haDeadAfter
		h.mu.Unlock()
		if alive && h.syncCerts != nil {
			h.syncCerts(ctx, cfg)
		}
	}
}

func (h *haManager) status() *agentapi.HAStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := &agentapi.HAStatus{}
	if h.cfg == nil {
		return st
	}
	now := time.Now()
	st.Node, st.Epoch, st.Term, st.Watchdog = h.cfg.Node, h.cfg.Epoch, max(h.term, h.peer.Term), h.wdKind
	st.Health, st.PeerHealth = h.health, h.peerHealth
	for _, d := range h.monitored {
		st.Monitored += len(d)
	}
	st.PeerAlive = now.Sub(h.peerSeen) < haDeadAfter
	if !h.peerSeen.IsZero() {
		seen := h.peerSeen
		st.PeerSeen = &seen
	}
	if now.Before(h.vote) {
		until := h.vote
		st.VoteUntil = &until
	}
	if now.Before(h.held) {
		until := h.held
		st.PromiseUntil = &until
	}
	switch {
	case h.active:
		st.State = agentapi.HAActive
	case h.staleLocked():
		st.State = agentapi.HAStale
	case st.PeerAlive || now.Before(h.vote):
		st.State = agentapi.HAStandby
	default:
		st.State = agentapi.HAFenced
	}
	return st
}

// heartbeatAuth checks the peer's heartbeat, which carries the pair's
// secret instead of the API token.
func (h *haManager) heartbeatAuth(r *http.Request) bool {
	h.mu.Lock()
	cfg := h.cfg
	h.mu.Unlock()
	if cfg == nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+cfg.Secret)) == 1
}

// witnessAuth lets an external witness, with the pair's witness secret,
// ask for the host's state and vote.
func (h *haManager) witnessAuth(r *http.Request) bool {
	h.mu.Lock()
	cfg := h.cfg
	h.mu.Unlock()
	if cfg == nil || cfg.WitnessSecret == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+cfg.WitnessSecret)) == 1
}

// peerConfig is where this host's portitor-config copies the pair's
// configuration from.
func (h *haManager) peerConfig() agentapi.HAPeerConfig {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil {
		return agentapi.HAPeerConfig{}
	}
	return agentapi.HAPeerConfig{Node: h.cfg.Node, Stale: h.staleLocked(), Epoch: h.cfg.Epoch,
		PeerAlive: time.Since(h.peerSeen) < haDeadAfter,
		URL:       h.cfg.PeerConfig, Fingerprint: h.cfg.PeerConfigFingerprint, Secret: h.cfg.Secret}
}

// onActiveChange starts or stops what only the active host runs, and
// routes what the host itself sends.
func (a *Agent) onActiveChange() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.ha.applyMgmt(ctx, a.bg); err != nil {
		slog.Error("ha: management routing", "err", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reconcileActive()
}

// reconcileActive runs the applied DHCP clients, DNS update clients and
// tunnel broker accounts, or none on an HA standby; a.mu held.
func (a *Agent) reconcileActive() {
	if a.ha.isStandby() {
		a.dhcp.Pause()
		a.dhcp6.Pause()
		a.ddns.Reconcile(nil)
		a.tbroker.Reconcile(nil)
		return
	}
	a.dhcp.Reconcile(a.dhcpWant)
	a.dhcp6.Reconcile(a.dhcp6Want)
	a.ddns.Reconcile(a.ddnsWant)
	a.tbroker.Reconcile(a.tbWant)
}

// gateDevices are the devices to gate per namespace, of an expanded
// document on an HA pair.
func gateDevices(exp *fwconfig.Document) map[string][]string {
	out := map[string][]string{}
	if exp.HA == nil {
		return out
	}
	for i := range exp.Instances {
		in := &exp.Instances[i]
		out[in.NetnsName()] = in.GateDevices()
	}
	return out
}

// monitoredDevices are the devices whose carrier counts, by namespace; nil
// off a pair.
func monitoredDevices(exp *fwconfig.Document) map[string][]string {
	if exp.HA == nil {
		return nil
	}
	out := map[string][]string{}
	for i := range exp.Instances {
		if d := exp.Instances[i].MonitoredDevices(); len(d) > 0 {
			out[exp.Instances[i].NetnsName()] = d
		}
	}
	return out
}

func (a *Agent) handleHAVote(w http.ResponseWriter, r *http.Request) {
	var req agentapi.HAVoteRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Seconds <= 0 {
		writeError(w, http.StatusBadRequest, errors.New("seconds must be positive"))
		return
	}
	if a.ha.status().Node == "" {
		writeError(w, http.StatusConflict, errors.New("this host is not in an HA pair"))
		return
	}
	console := r.RemoteAddr == "local socket"
	a.ha.giveVote(time.Duration(req.Seconds)*time.Second, console)
	if console {
		slog.Warn("ha: vote from the console", "seconds", req.Seconds)
	}
	writeJSONResponse(w, http.StatusOK, a.ha.status())
}
