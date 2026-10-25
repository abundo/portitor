// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/fwconfig"
)

// An HA host (fwconfig.HA) may be active only with a quorum of two of
// three: itself and its peer, which it hears every haBeat, or itself and
// the witness, whose vote portitor-web renews while it sees the host
// (POST /v1/ha/vote). Without one it is fenced: the document is applied
// again with render.Options.Fenced, which shuts its VRRP routers down
// and leaves out DHCP and router advertisements. It starts fenced after a
// restart, until it hears its peer or the witness.
//
// A primary whose peer answers as primary at a higher epoch was taken
// over: its secondary was promoted while it was away. It is stale: fenced
// and standby whatever its quorum, until it is given the document of the
// secondary it now is (by the new primary's portitor-config), and its
// own portitor-config copies the new primary's configuration.
const (
	haBeat = time.Second
	// haDeadAfter without an answer the peer counts as gone.
	haDeadAfter = 3 * time.Second
	// haMaxVote is the longest vote the witness or the console grants.
	haMaxVote = 24 * time.Hour
)

type haManager struct {
	mu        sync.Mutex
	cfg       *fwconfig.HA
	peerSeen  time.Time
	voteUntil time.Time
	fenced    bool
	// peer is the peer's last answer to the heartbeat.
	peer agentapi.HAHeartbeat
	// standby: a host in a pair that is fenced, or the secondary while it
	// hears the primary. It leaves the DNS updates and the tunnel broker
	// to the other, which would otherwise see the two publish their own
	// addresses in turn.
	standby bool
	// onChange applies the document again when fenced changes, onActive
	// follows standby.
	onChange func(fenced bool)
	onActive func()
	// syncCerts copies the peer's certificates, every haCertSync while
	// the host is standby.
	syncCerts func(context.Context, *fwconfig.HA)
}

func newHAManager(onChange func(bool), onActive func()) *haManager {
	return &haManager{onChange: onChange, onActive: onActive}
}

// isStandby tells whether the host leaves the DNS updates and the tunnel
// broker to its peer.
func (h *haManager) isStandby() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.standby
}

// setStandby records standby from the state under h.mu; it tells whether
// it changed.
func (h *haManager) setStandby(peerAlive bool) bool {
	s := h.cfg != nil && (h.fenced || h.staleLocked() || (h.cfg.Node == fwconfig.HASecondary && peerAlive))
	changed := s != h.standby
	h.standby = s
	return changed
}

// staleLocked tells whether the host is a primary taken over by its
// peer's promotion; h.mu held.
func (h *haManager) staleLocked() bool {
	return h.cfg != nil && h.cfg.Node == fwconfig.HAPrimary && h.peer.Node == fwconfig.HAPrimary && h.peer.Epoch > h.cfg.Epoch
}

// heard records the peer's answer; h.mu held.
func (h *haManager) heard(hb *agentapi.HAHeartbeat) {
	h.peerSeen = time.Now()
	h.peer = *hb
}

// boot fences a host whose last applied document puts it in a pair, before
// that document is applied again at start, unless its peer answers now
// (and has not taken it over): a restarted agent then doesn't take its
// VRRP routers down and up.
func (h *haManager) boot(ctx context.Context, cfg *fwconfig.HA) {
	var hb *agentapi.HAHeartbeat
	if cfg != nil {
		hb, _ = heartbeat(ctx, cfg)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cfg = cfg
	if hb != nil {
		h.heard(hb)
	}
	h.fenced = cfg != nil && (hb == nil || h.staleLocked())
	h.setStandby(hb != nil)
}

// setConfig follows the applied document. A host leaving its pair is no
// longer fenced; one joining has haDeadAfter to hear its peer before it
// counts as gone.
func (h *haManager) setConfig(cfg *fwconfig.HA) {
	h.mu.Lock()
	if h.cfg == nil && cfg != nil && !h.fenced {
		h.peerSeen = time.Now()
	}
	h.cfg = cfg
	changed := cfg == nil && h.fenced
	if changed {
		h.fenced = false
	}
	h.setStandby(time.Since(h.peerSeen) < haDeadAfter)
	h.mu.Unlock()
	if changed {
		go h.onChange(false)
	}
	// A document of another node or epoch may end staleness at once.
	if cfg != nil {
		h.decide()
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

func (h *haManager) isFenced() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fenced
}

// vote records the witness's vote (or the console's) for d.
func (h *haManager) vote(d time.Duration) {
	h.mu.Lock()
	h.voteUntil = time.Now().Add(min(d, haMaxVote))
	h.mu.Unlock()
	h.decide()
}

// decide fences the host, or lifts the fence, by its quorum now.
func (h *haManager) decide() {
	h.mu.Lock()
	if h.cfg == nil {
		h.mu.Unlock()
		return
	}
	now := time.Now()
	stale := h.staleLocked()
	quorum := (now.Sub(h.peerSeen) < haDeadAfter || now.Before(h.voteUntil)) && !stale
	changed := h.fenced == quorum
	h.fenced = !quorum
	fenced := h.fenced
	standbyChanged := h.setStandby(now.Sub(h.peerSeen) < haDeadAfter)
	epoch, peerEpoch := h.cfg.Epoch, h.peer.Epoch
	h.mu.Unlock()
	if standbyChanged {
		go h.onActive()
	}
	if changed {
		switch {
		case fenced && stale:
			slog.Warn("ha: the peer is primary at a later epoch (promoted): this host was taken over, fencing", "epoch", epoch, "peer_epoch", peerEpoch)
		case fenced:
			slog.Warn("ha: no quorum (neither the peer nor the witness), fencing")
		default:
			slog.Info("ha: quorum again, lifting the fence")
		}
		// An apply reads the state when it renders, so applies that
		// overtake each other end in the latest one.
		go h.onChange(fenced)
	}
}

// loop beats the peer and decides until ctx is cancelled.
func (h *haManager) loop(ctx context.Context) {
	t := time.NewTicker(haBeat)
	defer t.Stop()
	var lastSync time.Time
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
		hb, err := heartbeat(ctx, cfg)
		alive := err == nil
		if alive {
			h.mu.Lock()
			h.heard(hb)
			h.mu.Unlock()
		}
		h.decide()
		if alive && h.syncCerts != nil && h.isStandby() && time.Since(lastSync) >= haCertSync {
			lastSync = time.Now()
			h.syncCerts(ctx, cfg)
		}
	}
}

func heartbeat(ctx context.Context, cfg *fwconfig.HA) (*agentapi.HAHeartbeat, error) {
	c, err := agentclient.New(cfg.Peer, cfg.Secret, cfg.PeerFingerprint)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, haBeat)
	defer cancel()
	return c.HAHeartbeat(ctx)
}

func (h *haManager) status() *agentapi.HAStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := &agentapi.HAStatus{Fenced: h.fenced, Standby: h.standby}
	if h.cfg == nil {
		return st
	}
	now := time.Now()
	st.Node, st.Epoch, st.Stale = h.cfg.Node, h.cfg.Epoch, h.staleLocked()
	st.PeerAlive = now.Sub(h.peerSeen) < haDeadAfter
	if !h.peerSeen.IsZero() {
		seen := h.peerSeen
		st.PeerSeen = &seen
	}
	if now.Before(h.voteUntil) {
		until := h.voteUntil
		st.VoteUntil = &until
	}
	return st
}

// heartbeatAuth answers the peer's heartbeat, which carries the pair's
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
// ask for the quorum and vote.
func (h *haManager) witnessAuth(r *http.Request) bool {
	h.mu.Lock()
	cfg := h.cfg
	h.mu.Unlock()
	if cfg == nil || cfg.WitnessSecret == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+cfg.WitnessSecret)) == 1
}

// heartbeatAnswer is the host's answer to its peer's heartbeat.
func (h *haManager) heartbeatAnswer() agentapi.HAHeartbeat {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil {
		return agentapi.HAHeartbeat{}
	}
	return agentapi.HAHeartbeat{Node: h.cfg.Node, Epoch: h.cfg.Epoch}
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

// onActiveChange starts or stops the DNS updates and the tunnel broker
// as the host becomes the active one of its pair, or not.
func (a *Agent) onActiveChange() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reconcileActive()
}

// reconcileActive runs the applied DNS update clients and tunnel broker
// accounts, or none on an HA standby; a.mu held.
func (a *Agent) reconcileActive() {
	if a.ha.isStandby() {
		a.ddns.Reconcile(nil)
		a.tbroker.Reconcile(nil)
		return
	}
	a.ddns.Reconcile(a.ddnsWant)
	a.tbroker.Reconcile(a.tbWant)
}

// onFenceChange applies the current document again, fenced or not.
func (a *Agent) onFenceChange(fenced bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.applied == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	what := "lifting the fence"
	if fenced {
		what = "fencing"
	}
	a.log.Infof("ha: %s, applying generation %d again", what, a.applied.Generation)
	if err := a.applyLocked(ctx, *a.applied); err != nil {
		slog.Error("ha: apply", "fenced", fenced, "err", err)
		a.lastError = err.Error()
	}
	a.log.Take()
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
	a.ha.vote(time.Duration(req.Seconds) * time.Second)
	if r.RemoteAddr == "local socket" {
		slog.Warn("ha: vote from the console", "seconds", req.Seconds)
	}
	writeJSONResponse(w, http.StatusOK, a.ha.status())
}
