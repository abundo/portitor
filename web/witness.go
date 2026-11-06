// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// The witness is the third vote of an HA pair's quorum (fwconfig.HA).
// Every witnessBeat it asks both hosts at once and keeps its vote on one of
// them, the holder. A vote names the active host: the host reporting
// active is the one that gets it, ahead of everything else, so a witness
// that restarts doesn't hand it to the primary while the secondary is
// active. The vote moves only when the old holder's has run out, plus
// witnessGrace for a request still in flight after a timeout. So two hosts
// that can't hear each other never both hold one. After a restart the
// holder is the host that reports a vote.
//
// A pair has one witness, never two (each could vote for another host):
// portitor-config on the primary (Firewall.HAWitness local, the default),
// or an external one on a third host, which survives the primary's loss:
// portitor-web, or portitor-web witness alone (portalwitness.go), given
// the pair's witness string.
//
// portitor-config's round also catches up a host a commit skipped while it
// was unreachable (deployment status "skipped"): it applies the commit's
// document there once the host answers.
const (
	witnessBeat = time.Second
	// witnessAsk bounds a call to a host, so a dead one costs a round
	// little.
	witnessAsk = 500 * time.Millisecond
	// witnessVote is how long a vote lasts, in seconds. A failover waits
	// for it: it and the agent's watchdog and margin must fit
	// (agent.haWatchdogTimeout).
	witnessVote = 4
	// witnessGrace is added to a vote that has run out before it moves.
	witnessGrace = time.Second
)

// haHost is what the witness asks of an HA host's agent.
type haHost interface {
	HA(ctx context.Context) (*agentapi.HAStatus, error)
	HAVote(ctx context.Context, seconds int) (*agentapi.HAStatus, error)
}

// witness is the votes of the pairs, by a key per pair.
type witness struct {
	mu      sync.Mutex
	started time.Time
	pairs   map[string]*pairVote
}

// pairVote is one pair's vote: held by host 0 (the primary), 1 or none
// (-1), and until when.
type pairVote struct {
	holder int
	until  time.Time
}

func newWitnessState() *witness {
	return &witness{started: time.Now(), pairs: map[string]*pairVote{}}
}

// haOf asks a host for its state; nil when it can't be asked.
func haOf(ctx context.Context, h haHost) *agentapi.HAStatus {
	if h == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, witnessAsk)
	defer cancel()
	st, err := h.HA(ctx)
	if err != nil {
		return nil
	}
	return st
}

// bothOf asks the two hosts at once.
func bothOf(ctx context.Context, hosts [2]haHost) [2]*agentapi.HAStatus {
	var sts [2]*agentapi.HAStatus
	var wg sync.WaitGroup
	for i := range hosts {
		wg.Go(func() { sts[i] = haOf(ctx, hosts[i]) })
	}
	wg.Wait()
	return sts
}

// activeOf is the host that reports active, -1 for none. Of two, the one
// at the higher term: the other is about to close.
func activeOf(sts [2]*agentapi.HAStatus) int {
	active := -1
	for i, st := range sts {
		if st == nil || st.State != agentapi.HAActive {
			continue
		}
		if active < 0 || st.Term > sts[active].Term {
			active = i
		}
	}
	return active
}

// vote keeps the vote of the pair key of hosts (the primary first; nil:
// can't be asked).
func (w *witness) vote(ctx context.Context, key string, hosts [2]haHost) {
	sts := bothOf(ctx, hosts)
	w.mu.Lock()
	pv := w.pairs[key]
	if pv == nil {
		pv = &pairVote{holder: -1}
		w.pairs[key] = pv
	}
	w.mu.Unlock()
	now := time.Now()
	if pv.holder < 0 {
		for i, st := range sts {
			if st != nil && st.VoteUntil != nil {
				pv.holder, pv.until = i, *st.VoteUntil
				break
			}
		}
	}
	active := activeOf(sts)
	to := -1
	switch {
	case active >= 0:
		to = active
	case pv.holder >= 0 && sts[pv.holder] != nil:
		to = pv.holder
	case pv.holder < 0 && sts[0] != nil && sts[1] != nil:
		to = 0
	case sts[0] != nil:
		to = 0
	case sts[1] != nil:
		to = 1
	default:
		return
	}
	// A host that can't be asked may hold a vote from before the witness
	// started.
	if pv.holder < 0 && (sts[0] == nil || sts[1] == nil) && now.Sub(w.started) < witnessVote*time.Second+witnessGrace {
		return
	}
	// The old holder's vote may still count.
	if pv.holder >= 0 && to != pv.holder && now.Before(pv.until.Add(witnessGrace)) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, witnessAsk)
	defer cancel()
	_, err := hosts[to].HAVote(ctx, witnessVote)
	if err != nil {
		slog.Warn("witness: vote", "pair", key, "host", to, "err", err)
	} else if pv.holder != to {
		slog.Info("witness: vote moved", "pair", key, "to", to)
	}
	// Counted from after the call, as the host counts from when it got
	// the vote, and also when it failed: a lost answer may be of a vote
	// the host took. So the host's vote never outlasts this record.
	pv.holder, pv.until = to, time.Now().Add(witnessVote*time.Second)
}

// runWitness is portitor-config's round until ctx is cancelled: it votes
// in its pairs whose witness it is, and catches up their hosts.
func (s *Server) runWitness(ctx context.Context) {
	s.witness = newWitnessState()
	t := time.NewTicker(witnessBeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if s.isReplica() {
			// The primary's portitor-config does both.
			continue
		}
		fws, err := s.firewalls()
		if err != nil {
			slog.Warn("witness", "err", err)
			continue
		}
		byID := map[uint]models.Firewall{}
		for _, fw := range fws {
			byID[fw.ID] = fw
		}
		for _, fw := range fws {
			if fw.HAPrimaryID == nil {
				continue
			}
			p, ok := byID[*fw.HAPrimaryID]
			if !ok {
				continue
			}
			if p.HAWitness != models.HAWitnessExternal {
				s.witnessPair(ctx, p, fw)
			}
			s.catchUp(ctx, p)
			s.catchUp(ctx, fw)
		}
	}
}

// witnessPair keeps the vote of the pair of primary p and secondary q.
func (s *Server) witnessPair(ctx context.Context, p, q models.Firewall) {
	var hosts [2]haHost
	for i, fw := range []*models.Firewall{&p, &q} {
		if a, err := s.newAgent(fw); err == nil {
			hosts[i] = a
		}
	}
	s.witness.vote(ctx, fmt.Sprintf("firewall %d", p.ID), hosts)
}

// catchUp applies the document a commit skipped on the firewall, once it
// answers.
func (s *Server) catchUp(ctx context.Context, fw models.Firewall) {
	dep, err := s.latestDeployment(fw.ID)
	if err != nil || dep == nil || dep.Status != "skipped" {
		return
	}
	if !s.deployMu.TryLock() {
		return
	}
	defer s.deployMu.Unlock()
	a, err := s.newAgent(&fw)
	if err != nil || haOf(ctx, a) == nil {
		return
	}
	dir, err := s.snapshotDir()
	if err != nil {
		return
	}
	b, err := os.ReadFile(docPath(dir, dep.CommitID, fw.ID))
	if err != nil {
		slog.Warn("catch up: the commit's document", "firewall", fw.Name, "err", err)
		return
	}
	var doc fwconfig.Document
	if err := json.Unmarshal(b, &doc); err != nil {
		return
	}
	res, err := a.Apply(ctx, doc, 0)
	if err != nil {
		dep.Message = "catching up: " + err.Error()
		s.db.Save(dep)
		return
	}
	dep.Status = "applied"
	dep.Message = fmt.Sprintf("caught up %s", time.Now().Format(time.TimeOnly))
	dep.Log = joinLog(res.Log)
	s.db.Save(dep)
	slog.Info("caught up", "firewall", fw.Name, "commit", dep.CommitID, "generation", dep.Generation)
}
