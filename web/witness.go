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
// Every witnessBeat it asks both hosts and keeps its vote on one of them,
// the holder, renewing it while it sees that host. A host that has lost
// its peer stays active with the vote, and the other is fenced, so two
// hosts that can't see each other never both are. The vote moves only
// when the holder can't be asked and its vote has run out. After a restart
// the holder is the host that reports a vote.
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
	witnessBeat = 2 * time.Second
	// witnessVote is how long a vote lasts, in seconds.
	witnessVote = 10
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

// haOf asks a host for its quorum; nil when it can't be asked.
func haOf(ctx context.Context, h haHost) *agentapi.HAStatus {
	if h == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, witnessBeat)
	defer cancel()
	st, err := h.HA(ctx)
	if err != nil {
		return nil
	}
	return st
}

// vote keeps the vote of the pair key of hosts (the primary first; nil:
// can't be asked).
func (w *witness) vote(ctx context.Context, key string, hosts [2]haHost) {
	sts := [2]*agentapi.HAStatus{haOf(ctx, hosts[0]), haOf(ctx, hosts[1])}
	w.mu.Lock()
	defer w.mu.Unlock()
	pv := w.pairs[key]
	if pv == nil {
		pv = &pairVote{holder: -1}
		w.pairs[key] = pv
	}
	now := time.Now()
	if pv.holder < 0 {
		for i, st := range sts {
			if st != nil && st.VoteUntil != nil {
				pv.holder = i
				break
			}
		}
	}
	to := -1
	switch {
	case pv.holder >= 0 && sts[pv.holder] != nil:
		to = pv.holder
	case pv.holder >= 0 && now.Before(pv.until):
		// The holder can't be asked, and its vote may still count.
		return
	case pv.holder < 0 && sts[0] != nil && sts[1] != nil:
		to = 0
	case now.Sub(w.started) < witnessVote*time.Second:
		// A host that can't be asked may hold a vote from before the
		// witness started.
		return
	case sts[0] != nil:
		to = 0
	case sts[1] != nil:
		to = 1
	default:
		return
	}
	ctx, cancel := context.WithTimeout(ctx, witnessBeat)
	defer cancel()
	if _, err := hosts[to].HAVote(ctx, witnessVote); err != nil {
		slog.Warn("witness: vote", "pair", key, "host", to, "err", err)
		return
	}
	if pv.holder != to {
		slog.Info("witness: vote moved", "pair", key, "to", to)
	}
	pv.holder, pv.until = to, now.Add(witnessVote*time.Second)
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
