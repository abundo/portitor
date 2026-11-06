// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import "time"

// Who is active is decided by two kinds of lease, a promise with an end
// time. A lease is counted from before the request that got it was sent
// by the holder, and from after the call returned or failed by the
// grantor, so a holder always thinks it ends first.
//
//   - The vote, from the witness, to one host at a time.
//   - The promise: the standby's answer to a heartbeat, "I stay closed for
//     haPromise".
//
// haDecide is the rules, with no clock or I/O of its own.
const (
	// haBeat is how often each path carries a heartbeat.
	haBeat = 500 * time.Millisecond
	// haPromise is how long a standby's promise lasts.
	haPromise = 2 * time.Second
	// haMargin: the active host closes this long before its leases end,
	// so it is closed in time even if nft is slow.
	haMargin = time.Second
	// haDeadAfter without a word the peer counts as gone.
	haDeadAfter = 2 * time.Second
	// haTick is how often the leases are looked at.
	haTick = 100 * time.Millisecond
	// haWatchdogTimeout resets a host whose HA loop stops while open. With
	// haMargin it must be less than the witness's vote, 4 s: a hung host
	// is gone before its vote can move.
	haWatchdogTimeout = 2 * time.Second
)

// haFacts is what a host knows when it decides.
type haFacts struct {
	now     time.Time
	primary bool
	active  bool
	// stale: taken over by a promotion (fwconfig.HA.Epoch).
	stale bool
	term  int64
	// vote and held are the ends of the leases this host holds, given the
	// end of the promise it gave.
	vote, held, given time.Time
	// forced: the vote is the console's, which needs no watchdog.
	forced bool
	// The peer's last word.
	peerSeen   time.Time
	peerActive bool
	peerTerm   int64
	// noWatchdog refuses to open on a vote: a host that hangs while open
	// would keep the addresses from the one that takes over.
	noWatchdog bool
}

type haMove int

const (
	haStay haMove = iota
	haOpen
	haClose
)

func (f haFacts) peerAlive() bool { return f.now.Sub(f.peerSeen) < haDeadAfter }

// valid tells whether a lease still counts for this host: it has to last
// past the margin.
func (f haFacts) valid(until time.Time) bool { return f.now.Before(until.Add(-haMargin)) }

// outranked: the peer is active and wins over this host, by a higher term,
// or the primary at equal terms.
func (f haFacts) outranked() bool {
	return f.peerAlive() && f.peerActive && (f.peerTerm > f.term || (f.peerTerm == f.term && !f.primary))
}

// haDecide applies the rules.
//
//  1. Stay open while the host holds a vote or a promise. A host holding
//     neither closes at once.
//  2. Open only with a vote, when every promise this host gave has run
//     out, and it doesn't hear an active peer.
//  3. At start, with neither active, the primary opens when it holds a
//     promise. So a healthy pair runs without its witness.
//  4. Stale: a host that hears a higher term closes.
func haDecide(f haFacts) (haMove, string) {
	if f.active {
		switch {
		case f.stale:
			return haClose, "taken over by a promotion"
		case f.outranked():
			return haClose, "the peer is active at a higher term"
		case f.valid(f.vote) || f.valid(f.held):
			return haStay, ""
		}
		return haClose, "neither a vote nor a promise"
	}
	switch {
	case f.stale:
		return haStay, ""
	case f.now.Before(f.given):
		return haStay, "" // rule 2: this host promised
	case f.peerAlive() && f.peerActive:
		return haStay, ""
	case f.valid(f.vote) && (f.forced || !f.noWatchdog):
		return haOpen, "the witness's vote"
	case f.primary && f.valid(f.held):
		return haOpen, "the primary, with the standby's promise"
	}
	return haStay, ""
}

// haGives tells whether a closed host promises a peer that asks: an active
// peer, or the primary at start. A primary never promises a secondary that
// isn't active, or neither would ever open.
func haGives(active, primary, peerActive, peerPrimary bool) bool {
	return !active && (peerActive || (peerPrimary && !primary))
}
