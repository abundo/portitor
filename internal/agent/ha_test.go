// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
