// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"math/rand/v2"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func TestHADecide(t *testing.T) {
	sec := func(n float64) time.Time { return t0.Add(time.Duration(n * float64(time.Second))) }
	cases := []struct {
		name string
		f    haFacts
		want haMove
	}{
		{"active with a vote stays", haFacts{active: true, vote: sec(3)}, haStay},
		{"active with a promise stays", haFacts{active: true, held: sec(2)}, haStay},
		{"active closes before its leases end", haFacts{active: true, vote: sec(0.9), held: sec(0.9)}, haClose},
		{"active with neither closes", haFacts{active: true}, haClose},
		{"active and stale closes", haFacts{active: true, stale: true, vote: sec(4)}, haClose},
		{"active hears a higher term", haFacts{active: true, term: 3, vote: sec(4), peerSeen: t0, peerActive: true, peerTerm: 4}, haClose},
		{"active hears a lower term", haFacts{active: true, term: 4, vote: sec(4), peerSeen: t0, peerActive: true, peerTerm: 3}, haStay},
		{"equal terms: the secondary closes", haFacts{active: true, term: 4, vote: sec(4), peerSeen: t0, peerActive: true, peerTerm: 4}, haClose},
		{"equal terms: the primary stays", haFacts{primary: true, active: true, term: 4, vote: sec(4), peerSeen: t0, peerActive: true, peerTerm: 4}, haStay},
		{"a higher term long ago doesn't count", haFacts{active: true, term: 3, vote: sec(4), peerSeen: sec(-3), peerActive: true, peerTerm: 4}, haStay},

		{"standby with a vote opens", haFacts{vote: sec(4)}, haOpen},
		{"standby with a short vote stays", haFacts{vote: sec(0.5)}, haStay},
		{"standby with no vote stays", haFacts{}, haStay},
		{"rule 2: a promise given holds it closed", haFacts{vote: sec(4), given: sec(1)}, haStay},
		{"rule 2: it opens when the promise has run out", haFacts{vote: sec(4), given: t0}, haOpen},
		{"it never opens while it hears an active peer", haFacts{vote: sec(4), peerSeen: t0, peerActive: true}, haStay},
		{"an active peer gone long ago doesn't hold it", haFacts{vote: sec(4), peerSeen: sec(-3), peerActive: true}, haOpen},
		{"rule 3: the primary opens with a promise", haFacts{primary: true, held: sec(2)}, haOpen},
		{"rule 3: the secondary doesn't", haFacts{held: sec(2)}, haStay},
		{"rule 3: not while the peer is active", haFacts{primary: true, held: sec(2), peerSeen: t0, peerActive: true}, haStay},
		{"stale never opens", haFacts{stale: true, vote: sec(4)}, haStay},
		{"no watchdog: no failover on a vote", haFacts{noWatchdog: true, vote: sec(4)}, haStay},
		{"no watchdog: the console can", haFacts{noWatchdog: true, forced: true, vote: sec(4)}, haOpen},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.f.now = t0
			if c.f.peerSeen.IsZero() {
				c.f.peerSeen = t0.Add(-time.Hour)
			}
			if got, _ := haDecide(c.f); got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestHAGives(t *testing.T) {
	cases := []struct {
		active, primary, peerActive, peerPrimary, want bool
	}{
		{false, false, true, true, true},   // a standby secondary, its primary active
		{false, true, true, false, true},   // a standby primary, its secondary active
		{false, false, false, true, true},  // at start, to the primary
		{false, true, false, false, false}, // the primary never holds itself back
		{true, false, true, true, false},   // an active host promises nothing
	}
	for _, c := range cases {
		if got := haGives(c.active, c.primary, c.peerActive, c.peerPrimary); got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
}

// simHost is a host in the simulation below.
type simHost struct {
	primary, active, dead bool
	term                  int64
	vote, held, given     time.Time
	peerSeen              time.Time
	peerActive            bool
	peerTerm              int64
	// A closing host has a slow nft: it is open on the wire until closedAt.
	closedAt time.Time
	openWire bool
}

// TestHANeverBothOpen runs a pair and its witness through random link cuts
// and host deaths, with delayed messages, and checks the two hosts are
// never open on the wire at once. The witness does what web/witness.go does.
func TestHANeverBothOpen(t *testing.T) {
	const (
		step = 50 * time.Millisecond
		vote = 4 * time.Second
		beat = 500 * time.Millisecond
		// grace is the witness's G.
		grace = time.Second
		// closeLag is how long nft may take; haMargin must cover it.
		closeLag = 300 * time.Millisecond
	)
	seeds := 200
	if testing.Short() {
		seeds = 20
	}
	takeovers := 0
	for seed := range seeds {
		r := rand.New(rand.NewPCG(uint64(seed), 1))
		now := t0
		hosts := [2]*simHost{{primary: true, peerSeen: t0.Add(-time.Hour)}, {peerSeen: t0.Add(-time.Hour)}}
		// A host's own calls to its peer can fail while the peer's reach
		// it: a hung server, or a rule in one direction.
		calls := [2]bool{true, true}
		witLink := [2]bool{true, true}
		holder, until := -1, time.Time{}
		var nextBeat, nextRound time.Time

		for tick := 0; tick < 3000; tick++ {
			now = now.Add(step)
			if r.IntN(60) == 0 {
				switch r.IntN(6) {
				case 0:
					calls[0], calls[1] = !calls[0], !calls[0]
				case 1:
					calls[0] = !calls[0]
				case 2:
					calls[1] = !calls[1]
				case 3:
					witLink[0] = !witLink[0]
				case 4:
					witLink[1] = !witLink[1]
				case 5:
					h := hosts[r.IntN(2)]
					h.dead = !h.dead
					if h.dead {
						h.active, h.openWire = false, false
					} else {
						// A restart forgets its leases, and waits out any
						// promise it may have given (haManager.boot).
						h.vote, h.held, h.given = time.Time{}, time.Time{}, now.Add(haPromise)
					}
				}
			}
			delay := time.Duration(r.IntN(200)) * time.Millisecond

			if !now.Before(nextBeat) {
				nextBeat = now.Add(beat)
				for i, h := range hosts {
					p := hosts[1-i]
					if h.dead || p.dead || !calls[i] {
						continue
					}
					// The holder counts from before the send; the grantor
					// from when it answers, later.
					sent := now
					answered := now.Add(delay)
					// A closing host still says it is active (openWire):
					// the manager clears active after the gate has closed.
					p.peerSeen, p.peerActive, p.peerTerm = answered, h.openWire, h.term
					if haGives(p.openWire, p.primary, h.openWire, h.primary) {
						p.given = answered.Add(haPromise)
						h.held = sent.Add(haPromise)
					}
					h.peerSeen, h.peerActive, h.peerTerm = answered, p.openWire, p.term
				}
			}
			if !now.Before(nextRound) {
				nextRound = now.Add(time.Second)
				to := -1
				for i, h := range hosts {
					if !h.dead && witLink[i] && h.openWire {
						to = i
					}
				}
				if to < 0 && holder >= 0 && !hosts[holder].dead && witLink[holder] {
					to = holder
				}
				if to < 0 && holder < 0 {
					for i, h := range hosts {
						if !h.dead && witLink[i] {
							to = i
							break
						}
					}
				}
				if to < 0 && !now.Before(until.Add(grace)) {
					for i, h := range hosts {
						if !h.dead && witLink[i] {
							to = i
							break
						}
					}
				}
				if to >= 0 && (to == holder || holder < 0 || !now.Before(until.Add(grace))) {
					hosts[to].vote = now.Add(vote)
					holder, until = to, now.Add(delay).Add(vote)
				}
			}
			for _, h := range hosts {
				if h.dead {
					continue
				}
				f := haFacts{now: now, primary: h.primary, active: h.active, term: h.term, vote: h.vote, held: h.held,
					given: h.given, peerSeen: h.peerSeen, peerActive: h.peerActive, peerTerm: h.peerTerm}
				switch mv, _ := haDecide(f); mv {
				case haOpen:
					h.term = max(h.term, h.peerTerm) + 1
					h.active, h.openWire = true, true
					takeovers++
				case haClose:
					h.active = false
					h.closedAt = now.Add(closeLag)
				}
				if !h.active && h.openWire && !now.Before(h.closedAt) {
					h.openWire = false
				}
			}
			if hosts[0].openWire && hosts[1].openWire {
				t.Fatalf("seed %d, %v: both open: %+v %+v", seed, now.Sub(t0), hosts[0], hosts[1])
			}
		}
	}
	if takeovers < seeds {
		t.Errorf("only %d openings in %d runs: the simulation tests little", takeovers, seeds)
	}
}
