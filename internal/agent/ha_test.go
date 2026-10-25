// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

func TestHAQuorum(t *testing.T) {
	changes := make(chan bool, 10)
	h := newHAManager(func(f bool) { changes <- f }, func() {})
	cfg := &fwconfig.HA{Node: fwconfig.HAPrimary, Secret: strings.Repeat("s", 43)}

	// After a restart a host in a pair starts fenced, when its peer
	// doesn't answer (it has none here).
	h.boot(context.Background(), cfg)
	if !h.isFenced() {
		t.Fatal("not fenced at boot")
	}
	// Hearing the peer lifts the fence.
	h.peerSeen = time.Now()
	h.decide()
	if h.isFenced() || <-changes {
		t.Fatal("fenced with the peer alive")
	}
	// The peer gone and no vote: fenced.
	h.peerSeen = time.Now().Add(-haDeadAfter)
	h.decide()
	if !h.isFenced() || !<-changes {
		t.Fatal("not fenced without a quorum")
	}
	// The witness's vote is a quorum while it lasts.
	h.vote(time.Minute)
	if h.isFenced() || <-changes {
		t.Fatal("fenced with the witness's vote")
	}
	h.voteUntil = time.Now().Add(-time.Second)
	h.decide()
	if !h.isFenced() || !<-changes {
		t.Fatal("not fenced after the vote ended")
	}
	// Leaving the pair lifts the fence.
	h.setConfig(nil)
	if h.isFenced() || <-changes {
		t.Fatal("fenced outside a pair")
	}
	// Joining one gives the peer time to be heard.
	h.setConfig(cfg)
	h.decide()
	if h.isFenced() {
		t.Error("fenced at once on joining a pair")
	}
}

func TestHAHeartbeatRoute(t *testing.T) {
	a, _ := testAgent(t)
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	get := func(auth string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/ha/heartbeat", nil)
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	secret := strings.Repeat("k", 43)
	if code := get(secret); code != http.StatusUnauthorized {
		t.Errorf("heartbeat outside a pair: %d", code)
	}
	a.ha.setConfig(&fwconfig.HA{Node: fwconfig.HASecondary, Secret: secret})
	if code := get(secret); code != http.StatusOK {
		t.Errorf("heartbeat with the secret: %d", code)
	}
	if code := get("wrong"); code != http.StatusUnauthorized {
		t.Errorf("heartbeat with a wrong secret: %d", code)
	}
	// The secret opens nothing else.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/status", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status with the secret: %v %v", resp, err)
	}
}

func TestHAStandby(t *testing.T) {
	actives := make(chan struct{}, 10)
	h := newHAManager(func(bool) {}, func() { actives <- struct{}{} })
	sec := &fwconfig.HA{Node: fwconfig.HASecondary}
	h.setConfig(sec)
	h.peerSeen = time.Now()
	h.decide()
	// The secondary hearing the primary leaves the updates to it.
	if !h.isStandby() {
		t.Fatal("secondary with its primary alive is not standby")
	}
	// The primary gone, the secondary with the witness's vote takes over.
	h.peerSeen = time.Now().Add(-haDeadAfter)
	h.vote(time.Minute)
	if h.isStandby() {
		t.Fatal("secondary on its own is standby")
	}
	<-actives
	// Fenced, it is standby again.
	h.voteUntil = time.Now().Add(-time.Second)
	h.decide()
	if !h.isStandby() {
		t.Error("fenced host is not standby")
	}
	// A primary is never standby while it has a quorum.
	h.setConfig(&fwconfig.HA{Node: fwconfig.HAPrimary})
	h.peerSeen = time.Now()
	h.decide()
	if h.isStandby() {
		t.Error("primary with its peer is standby")
	}
}

func TestHAStale(t *testing.T) {
	changes := make(chan bool, 10)
	h := newHAManager(func(f bool) { changes <- f }, func() {})
	prim := &fwconfig.HA{Node: fwconfig.HAPrimary, Secret: strings.Repeat("s", 43)}
	h.setConfig(prim)
	h.mu.Lock()
	h.heard(&agentapi.HAHeartbeat{Node: fwconfig.HASecondary})
	h.mu.Unlock()
	h.decide()
	if h.isFenced() || h.status().Stale {
		t.Fatal("a primary hearing its secondary is fenced or stale")
	}
	// The peer promoted while this host was away: it answers as the
	// primary at a later epoch. Its peer alive, this host is fenced.
	h.mu.Lock()
	h.heard(&agentapi.HAHeartbeat{Node: fwconfig.HAPrimary, Epoch: 1})
	h.mu.Unlock()
	h.vote(time.Minute)
	if st := h.status(); !st.Fenced || !st.Stale || !st.Standby {
		t.Fatalf("taken over: %+v", st)
	}
	// Caught up as the secondary of the next epoch, it takes part again.
	h.setConfig(&fwconfig.HA{Node: fwconfig.HASecondary, Secret: prim.Secret, Epoch: 1})
	if st := h.status(); st.Fenced || st.Stale || st.Epoch != 1 {
		t.Errorf("caught up: %+v", st)
	}
	// A primary of the same epoch as its peer is not stale (both promoted
	// by force: the commit catches one up).
	h.setConfig(&fwconfig.HA{Node: fwconfig.HAPrimary, Secret: prim.Secret, Epoch: 1})
	if h.status().Stale {
		t.Error("stale at the peer's epoch")
	}
}

func TestHAWitnessAuth(t *testing.T) {
	a, h := testAgent(t)
	secret, witness := strings.Repeat("k", 43), strings.Repeat("w", 43)
	if rec := call(t, h, "GET", "/v1/ha", witness, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("witness outside a pair: %d", rec.Code)
	}
	a.ha.setConfig(&fwconfig.HA{Node: fwconfig.HAPrimary, Secret: secret, WitnessSecret: witness})
	if rec := call(t, h, "GET", "/v1/ha", witness, nil); rec.Code != http.StatusOK {
		t.Errorf("quorum with the witness secret: %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, h, "POST", "/v1/ha/vote", witness, agentapi.HAVoteRequest{Seconds: 10}); rec.Code != http.StatusOK || a.ha.status().VoteUntil == nil {
		t.Errorf("vote with the witness secret: %d %s", rec.Code, rec.Body)
	}
	// It opens nothing else, and the pair's secret not the vote.
	for _, p := range []string{"/v1/status", "/v1/ha/peer-config"} {
		if rec := call(t, h, "GET", p, witness, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with the witness secret: %d", p, rec.Code)
		}
	}
	if rec := call(t, h, "POST", "/v1/ha/vote", secret, agentapi.HAVoteRequest{Seconds: 10}); rec.Code != http.StatusUnauthorized {
		t.Errorf("vote with the pair's secret: %d", rec.Code)
	}
	// The token reads where portitor-config copies from.
	rec := call(t, h, "GET", "/v1/ha/peer-config", testToken, nil)
	var pc agentapi.HAPeerConfig
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &pc) != nil || pc.Secret != secret || pc.Node != fwconfig.HAPrimary {
		t.Errorf("peer config: %d %s", rec.Code, rec.Body)
	}
}

func TestHAApplyEpoch(t *testing.T) {
	a, h := testAgent(t)
	secret := strings.Repeat("k", 43)
	a.ha.setConfig(&fwconfig.HA{Node: fwconfig.HASecondary, Secret: secret, Epoch: 2})
	doc := fwconfig.Document{Version: fwconfig.Version, Generation: 1, HA: &fwconfig.HA{Node: fwconfig.HAPrimary, Secret: secret, Epoch: 1}}
	rec := call(t, h, "POST", "/v1/apply", testToken, agentapi.ApplyRequest{Document: doc})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "promoted") {
		t.Errorf("a document of an earlier epoch: %d %s", rec.Code, rec.Body)
	}
}
