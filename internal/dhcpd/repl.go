// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcpd

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"time"
)

// Replication to an HA pair's standby. The server numbers its changes;
// the agent long-polls them (Changes), sends them to the peer's agent,
// which applies them to its server (Apply), and reports the peer's
// acknowledgement (Acked). A reply to a new binding waits for it, for at
// most ackWait, while a peer has acknowledged anything lately: the
// standby has the lease before the client does. Renewals are batched for
// up to batchWait. Merging is by Lease.Updated, the newer one winning, so
// the order of batches and snapshots doesn't matter.

const (
	// ackWait bounds the wait for the standby's acknowledgement.
	ackWait = 100 * time.Millisecond
	// peerFresh: an acknowledgement this recent means a standby takes the
	// stream, so new bindings wait for it.
	peerFresh = 3 * time.Second
	// batchWait is the longest a renewal waits to go out.
	batchWait = time.Second
	// maxJournal bounds the changes kept for Changes; a poller further
	// behind gets a snapshot.
	maxJournal = 1 << 16
)

type journalEntry struct {
	seq  uint64
	addr netip.Addr
}

// repl is the server's replication state; Server.mu guards it.
type repl struct {
	epoch   uint64
	seq     uint64
	journal []journalEntry
	// first is the oldest seq the journal still has.
	first uint64
	// urgent: an unsent new binding.
	urgent bool
	// changed is closed and replaced on each change.
	changed chan struct{}
	acked   uint64
	ackedAt time.Time
	// ack is closed and replaced on each acknowledgement.
	ack chan struct{}
}

func newRepl() repl {
	return repl{epoch: rand.Uint64() | 1, first: 1, changed: make(chan struct{}), ack: make(chan struct{})}
}

// put records a lease (Store.Put) as a change, stamped now; s.mu held.
// It returns the change's number when the reply must wait for the
// standby: a new binding while a standby takes the stream.
func (s *Server) put(l Lease, sync, fresh bool) (uint64, error) {
	l.Updated = s.now().UnixMilli()
	if err := s.store.Put(l, sync); err != nil {
		return 0, err
	}
	n := s.note(l.Addr, fresh)
	if fresh && s.r.ackedAt.After(s.now().Add(-peerFresh)) {
		return n, nil
	}
	return 0, nil
}

// note adds a change of a's lease to the journal; s.mu held.
func (s *Server) note(a netip.Addr, urgent bool) uint64 {
	s.r.seq++
	s.r.journal = append(s.r.journal, journalEntry{s.r.seq, a})
	if len(s.r.journal) > maxJournal {
		drop := len(s.r.journal) / 2
		s.r.first = s.r.journal[drop].seq
		s.r.journal = append([]journalEntry(nil), s.r.journal[drop:]...)
	}
	s.r.urgent = s.r.urgent || urgent
	close(s.r.changed)
	s.r.changed = make(chan struct{})
	return s.r.seq
}

// Changes are the leases changed since a poller's last batch.
type Changes struct {
	Epoch uint64 `json:"epoch"`
	Seq   uint64 `json:"seq"`
	// Snapshot: Leases is every lease, as the poller's epoch is another
	// process's or it fell behind the journal.
	Snapshot bool    `json:"snapshot,omitempty"`
	Leases   []Lease `json:"leases,omitempty"`
}

// Changes waits up to wait for changes after seq (of epoch) and returns
// them: at once for a new binding or a snapshot, else after up to
// batchWait, so renewals go out together.
func (s *Server) Changes(ctx context.Context, epoch, after uint64, wait time.Duration) Changes {
	deadline := time.Now().Add(wait)
	var batchUntil time.Time
	for {
		s.mu.Lock()
		if epoch != s.r.epoch || after+1 < s.r.first || after > s.r.seq {
			out := Changes{Epoch: s.r.epoch, Seq: s.r.seq, Snapshot: true, Leases: s.store.All()}
			s.r.urgent = false
			s.mu.Unlock()
			return out
		}
		pending := s.r.seq > after
		if pending && (s.r.urgent || (!batchUntil.IsZero() && !time.Now().Before(batchUntil)) || !time.Now().Before(deadline)) {
			out := Changes{Epoch: s.r.epoch, Seq: s.r.seq}
			seen := map[netip.Addr]bool{}
			for i := len(s.r.journal) - 1; i >= 0 && s.r.journal[i].seq > after; i-- {
				a := s.r.journal[i].addr
				if seen[a] {
					continue
				}
				seen[a] = true
				if l := s.store.Get(a); l != nil {
					out.Leases = append(out.Leases, *l)
				}
			}
			s.r.urgent = false
			s.mu.Unlock()
			return out
		}
		if pending && batchUntil.IsZero() {
			batchUntil = time.Now().Add(batchWait)
		}
		changed := s.r.changed
		s.mu.Unlock()
		until := deadline
		if !batchUntil.IsZero() && batchUntil.Before(until) {
			until = batchUntil
		}
		left := time.Until(until)
		if left <= 0 {
			if !pending {
				s.mu.Lock()
				out := Changes{Epoch: s.r.epoch, Seq: s.r.seq}
				s.mu.Unlock()
				return out
			}
			continue
		}
		t := time.NewTimer(left)
		select {
		case <-ctx.Done():
			t.Stop()
			return Changes{Epoch: epoch, Seq: after}
		case <-changed:
		case <-t.C:
		}
		t.Stop()
	}
}

// Acked records that the standby has every change up to seq.
func (s *Server) Acked(seq uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.r.ackedAt = s.now()
	if seq > s.r.acked {
		s.r.acked = seq
	}
	close(s.r.ack)
	s.r.ack = make(chan struct{})
}

// waitAck waits, without s.mu, until the standby has change seq, for at
// most ackWait; 0 waits for nothing.
func (s *Server) waitAck(seq uint64) {
	if seq == 0 {
		return
	}
	deadline := time.Now().Add(ackWait)
	for {
		s.mu.Lock()
		done := s.r.acked >= seq
		ack := s.r.ack
		s.mu.Unlock()
		left := time.Until(deadline)
		if done || left <= 0 {
			return
		}
		t := time.NewTimer(left)
		select {
		case <-ack:
		case <-t.C:
		}
		t.Stop()
	}
}

// Apply takes the active host's leases: each one replaces the stored
// lease of its address unless that one is newer. It returns how many it
// took.
func (s *Server) Apply(leases []Lease) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, l := range leases {
		if !l.Addr.IsValid() {
			continue
		}
		if old := s.store.Get(l.Addr); old != nil && old.Updated >= l.Updated {
			continue
		}
		if err := s.store.Put(l, false); err != nil {
			return n, err
		}
		s.note(l.Addr, false)
		n++
	}
	return n, s.store.Flush()
}
