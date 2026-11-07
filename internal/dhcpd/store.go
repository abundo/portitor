// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dhcpd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Lease is one address's binding, DHCPv4 or DHCPv6. A lease that has run
// out or was released stays, so its client gets the same address back
// while no one else took it; a declined one holds the address from
// everyone until it runs out.
type Lease struct {
	Addr netip.Addr `json:"addr"`
	// MAC is the client's hardware address (DHCPv4's chaddr; for DHCPv6
	// what was learned of it, possibly nothing).
	MAC string `json:"mac,omitempty"`
	// ClientID is DHCPv4's option 61 or DHCPv6's DUID, in hex.
	ClientID string `json:"cid,omitempty"`
	IAID     uint32 `json:"iaid,omitempty"`
	Hostname string `json:"host,omitempty"`
	// Expires is in Unix seconds.
	Expires  int64 `json:"exp"`
	Declined bool  `json:"declined,omitempty"`
	// Updated is when the lease last changed, in Unix milliseconds: of
	// two copies (an HA pair's), the newer wins.
	Updated int64 `json:"upd,omitempty"`
}

// Valid says whether the lease binds its address at t.
func (l *Lease) Valid(t time.Time) bool { return l.Expires > t.Unix() }

// keepExpired is how long a lease that ran out stays in the store.
const keepExpired = 30 * 24 * time.Hour

// Store is the leases, kept in memory and in an append-only log of JSON
// lines, one per change, the last line of an address winning. It is
// rewritten without the dead lines when they outnumber the live ones.
// Not safe for concurrent use.
type Store struct {
	path   string
	f      *os.File
	leases map[netip.Addr]*Lease
	lines  int
	dirty  bool
}

// OpenStore reads the log at path, writes it again compacted and opens it
// for appending.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, leases: map[netip.Addr]*Lease{}}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var l Lease
			// A line cut short by a crash is the last; skip it.
			if json.Unmarshal(sc.Bytes(), &l) != nil || !l.Addr.IsValid() {
				continue
			}
			s.leases[l.Addr] = &l
		}
		f.Close()
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := s.compact(time.Now()); err != nil {
		return nil, err
	}
	return s, nil
}

// Get is the lease of an address, nil without one.
func (s *Store) Get(a netip.Addr) *Lease { return s.leases[a] }

// All is every lease, by address.
func (s *Store) All() []Lease {
	out := make([]Lease, 0, len(s.leases))
	for _, l := range s.leases {
		out = append(out, *l)
	}
	slices.SortFunc(out, func(a, b Lease) int { return a.Addr.Compare(b.Addr) })
	return out
}

// Each calls fn for every lease, in no order, until it returns false.
func (s *Store) Each(fn func(*Lease) bool) {
	for _, l := range s.leases {
		if !fn(l) {
			return
		}
	}
}

// Put records a lease. With sync it is on disk when Put returns, as a new
// binding must be before the client hears of it; else by the next Flush.
func (s *Store) Put(l Lease, sync bool) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if _, err := s.f.Write(append(b, '\n')); err != nil {
		return err
	}
	cp := l
	s.leases[l.Addr] = &cp
	s.lines++
	s.dirty = true
	if sync {
		return s.Flush()
	}
	if s.lines > 2*len(s.leases)+1000 {
		return s.compact(time.Now())
	}
	return nil
}

// Flush writes what Put left in the page cache to disk.
func (s *Store) Flush() error {
	if !s.dirty {
		return nil
	}
	s.dirty = false
	return s.f.Sync()
}

// Close flushes and closes the log.
func (s *Store) Close() error {
	if s.f == nil {
		return nil
	}
	err := s.Flush()
	if cerr := s.f.Close(); err == nil {
		err = cerr
	}
	s.f = nil
	return err
}

// compact writes the live leases to a new file and renames it over the
// log, dropping leases that ran out more than keepExpired ago.
func (s *Store) compact(now time.Time) error {
	old := now.Add(-keepExpired).Unix()
	for a, l := range s.leases {
		if l.Expires < old {
			delete(s.leases, a)
		}
	}
	tmp := s.path + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, l := range s.All() {
		b, _ := json.Marshal(l)
		w.Write(append(b, '\n'))
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(s.path)); err == nil {
		d.Sync()
		d.Close()
	}
	if s.f != nil {
		s.f.Close()
	}
	s.f, err = os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("lease log: %w", err)
	}
	s.lines = len(s.leases)
	s.dirty = false
	return nil
}
