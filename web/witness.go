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

// portitor-web is the witness of each HA pair: the third vote of the
// quorum (fwconfig.HA). Every witnessBeat it asks both hosts and keeps its
// vote on one of them, the holder, renewing it while it sees that host. A
// host that has lost its peer stays active with the vote, and the other is
// fenced, so two hosts that can't see each other never both are. The
// vote moves only when the holder can't be asked and its vote has run
// out. After a restart the holder is the host that reports a vote.
//
// Each round also catches up a host a commit skipped while it was
// unreachable (deployment status "skipped"): it applies the commit's
// document there once the host answers.
const (
	witnessBeat = 2 * time.Second
	// witnessVote is how long a vote lasts, in seconds.
	witnessVote = 10
)

type witness struct {
	mu      sync.Mutex
	started time.Time
	// holder and until are per pair, by the primary's id.
	holder map[uint]uint
	until  map[uint]time.Time
}

// runWitness runs the witness until ctx is cancelled.
func (s *Server) runWitness(ctx context.Context) {
	s.witness = &witness{started: time.Now(), holder: map[uint]uint{}, until: map[uint]time.Time{}}
	t := time.NewTicker(witnessBeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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
			if s.votes() {
				s.witnessPair(ctx, p, fw)
			}
			// A pair behind portitor-config is caught up by it.
			if !viaConfig(fws, p) {
				s.catchUp(ctx, p)
				s.catchUp(ctx, fw)
			}
		}
	}
}

// votes tells whether this portitor-web is its pairs' witness: not
// portitor-config with a manager, which is the witness then (two
// witnesses could each vote for another host).
func (s *Server) votes() bool {
	return !(s.cfg.Local && s.cfg.ManagerTokenFile != "")
}

// haOf asks a host for its quorum; nil when it can't be asked.
func (s *Server) haOf(ctx context.Context, fw *models.Firewall) (agentAPI, *agentapi.HAStatus) {
	a, err := s.newAgent(fw)
	if err != nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, witnessBeat)
	defer cancel()
	st, err := a.HA(ctx)
	if err != nil {
		return nil, nil
	}
	return a, st
}

// witnessPair keeps the vote of the pair of primary p and secondary q.
func (s *Server) witnessPair(ctx context.Context, p, q models.Firewall) {
	ap, sp := s.haOf(ctx, &p)
	aq, sq := s.haOf(ctx, &q)
	w := s.witness
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	holder := w.holder[p.ID]
	if holder == 0 {
		switch {
		case sp != nil && sp.VoteUntil != nil:
			holder = p.ID
		case sq != nil && sq.VoteUntil != nil:
			holder = q.ID
		}
	}
	var to agentAPI
	var toID uint
	switch {
	case holder == p.ID && sp != nil:
		to, toID = ap, p.ID
	case holder == q.ID && sq != nil:
		to, toID = aq, q.ID
	case holder != 0 && now.Before(w.until[p.ID]):
		// The holder can't be asked, and its vote may still count.
		return
	case holder == 0 && sp != nil && sq != nil:
		to, toID = ap, p.ID
	case now.Sub(w.started) < witnessVote*time.Second:
		// A host that can't be asked may hold a vote from before
		// portitor-web started.
		return
	case sp != nil:
		to, toID = ap, p.ID
	case sq != nil:
		to, toID = aq, q.ID
	default:
		return
	}
	ctx, cancel := context.WithTimeout(ctx, witnessBeat)
	defer cancel()
	if _, err := to.HAVote(ctx, witnessVote); err != nil {
		slog.Warn("witness: vote", "firewall", toID, "err", err)
		return
	}
	if holder != toID {
		slog.Info("witness: vote moved", "pair", p.Name, "to", toID)
	}
	w.holder[p.ID], w.until[p.ID] = toID, now.Add(witnessVote*time.Second)
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
	a, st := s.haOf(ctx, &fw)
	if st == nil {
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
