// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/abundo/portitor/internal/schema"
)

// Backend is where the configuration lives and runs.
type Backend interface {
	// Current is the shared configuration as it stands: what was committed
	// and the edits made since, in the GUI too.
	Current(ctx context.Context) (*Tree, error)
	// Running is what the firewalls run: the live commit's.
	Running(ctx context.Context) (*Tree, error)
	// Commit makes t the configuration and deploys it; it leaves the
	// configuration as it was when that fails. It says how it went.
	Commit(ctx context.Context, t *Tree, o CommitOptions) (string, error)
}

// CommitOptions are a commit's.
type CommitOptions struct {
	User string
	// Owner is the committing session, for the locks.
	Owner string
	// Confirm is the confirm window in seconds; nil is the settings', 0 none.
	Confirm *int
	// Validate checks the commit as far as it goes without applying it.
	Validate bool
	// Only are the virtual firewalls an instance admin's commit deploys
	// (nil: all).
	Only map[string]bool
}

// Store is the candidate the CLI's (and NETCONF's) sessions share: the
// backend's current configuration with their edits. When the current
// configuration changes under it (an edit in the GUI, a commit), the
// candidate's edits are made again on the new one: a rebase, in which the
// candidate wins where both changed a leaf.
type Store struct {
	mu      sync.Mutex
	schema  *schema.Node
	backend Backend
	dir     string // candidate.json and candidate-base.json; "" keeps them in memory

	cand, base *Tree // nil: no edits

	locks map[string]string // datastore (candidate, running) → the session holding its lock
}

// LockedError is an edit or commit refused for another session's lock.
type LockedError struct {
	Datastore, Owner string
}

func (e *LockedError) Error() string {
	return fmt.Sprintf("the %s configuration is locked by session %s", e.Datastore, e.Owner)
}

// Lock locks the candidate or running configuration for the session
// owner: others can't edit (candidate) or commit (either) until it
// unlocks or ends. A candidate with changes can't be locked (RFC 6241).
func (s *Store) Lock(ctx context.Context, owner, datastore string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if datastore != "candidate" && datastore != "running" {
		return fmt.Errorf("no %s configuration to lock", datastore)
	}
	if o := s.locks[datastore]; o != "" {
		return &LockedError{datastore, o}
	}
	if datastore == "candidate" && s.cand != nil {
		c, err := s.candidate(ctx)
		if err != nil {
			return err
		}
		if !Equal(c, s.base) {
			return errors.New("the candidate has changes not committed or discarded")
		}
	}
	if s.locks == nil {
		s.locks = map[string]string{}
	}
	s.locks[datastore] = owner
	return nil
}

// Unlock releases owner's lock.
func (s *Store) Unlock(owner, datastore string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locks[datastore] != owner {
		return fmt.Errorf("the %s configuration is not locked by this session", datastore)
	}
	delete(s.locks, datastore)
	return nil
}

// Release releases every lock of owner, a session that ends.
func (s *Store) Release(owner string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ds, o := range s.locks {
		if o == owner {
			delete(s.locks, ds)
		}
	}
}

// locked is the lock on the datastores that keeps owner out; s.mu is held.
func (s *Store) locked(owner string, datastores ...string) error {
	for _, ds := range datastores {
		if o := s.locks[ds]; o != "" && o != owner {
			return &LockedError{ds, o}
		}
	}
	return nil
}

// NewStore is a store whose candidate is kept in dir.
func NewStore(root *schema.Node, b Backend, dir string) *Store {
	s := &Store{schema: root, backend: b, dir: dir}
	s.load()
	return s
}

func (s *Store) files() (cand, base string) {
	return filepath.Join(s.dir, "candidate.json"), filepath.Join(s.dir, "candidate-base.json")
}

func (s *Store) load() {
	if s.dir == "" {
		return
	}
	cf, bf := s.files()
	cand, err1 := s.read(cf)
	base, err2 := s.read(bf)
	if err1 == nil && err2 == nil {
		s.cand, s.base = cand, base
	}
}

func (s *Store) read(path string) (*Tree, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	t := New(s.schema)
	if err := t.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Store) save() error {
	if s.dir == "" {
		return nil
	}
	cf, bf := s.files()
	if s.cand == nil {
		os.Remove(cf)
		os.Remove(bf)
		return nil
	}
	for path, t := range map[string]*Tree{cf: s.cand, bf: s.base} {
		data, err := t.JSON(JSONOptions{Secrets: true})
		if err != nil {
			return err
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	return nil
}

// candidate is the rebased candidate; s.mu is held.
func (s *Store) candidate(ctx context.Context) (*Tree, error) {
	cur, err := s.backend.Current(ctx)
	if err != nil {
		return nil, err
	}
	if s.cand == nil {
		return cur, nil
	}
	if Equal(s.base, cur) {
		return s.cand, nil
	}
	rebased := cur.Clone()
	if err := rebased.Apply(Diff(s.base, s.cand)); err != nil {
		return nil, fmt.Errorf("rebasing the candidate on the changed configuration: %w", err)
	}
	s.cand, s.base = rebased, cur
	if err := s.save(); err != nil {
		return nil, err
	}
	return s.cand, nil
}

// Candidate is a copy of the candidate, to read.
func (s *Store) Candidate(ctx context.Context) (*Tree, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.candidate(ctx)
	if err != nil {
		return nil, err
	}
	return c.Clone(), nil
}

// Running is the running configuration.
func (s *Store) Running(ctx context.Context) (*Tree, error) {
	return s.backend.Running(ctx)
}

// Edit changes the candidate with fn, all or nothing, for the session
// owner.
func (s *Store) Edit(ctx context.Context, owner string, fn func(*Tree) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.locked(owner, "candidate"); err != nil {
		return err
	}
	c, err := s.candidate(ctx)
	if err != nil {
		return err
	}
	work := c.Clone()
	if err := fn(work); err != nil {
		return err
	}
	if s.cand == nil {
		s.base = c
	}
	s.cand = work
	return s.save()
}

// Changed reports whether the candidate holds edits not in the current
// configuration.
func (s *Store) Changed(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cand == nil {
		return false, nil
	}
	c, err := s.candidate(ctx)
	if err != nil {
		return false, err
	}
	return !Equal(c, s.base), nil
}

// Discard drops the candidate's edits.
func (s *Store) Discard(owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.locked(owner, "candidate"); err != nil {
		return err
	}
	s.cand, s.base = nil, nil
	return s.save()
}

// ValidationError is a commit's problems with the schema.
type ValidationError struct{ Problems []error }

func (e *ValidationError) Error() string {
	msg := "the candidate is not valid:"
	for _, p := range e.Problems {
		msg += "\n  " + p.Error()
	}
	return msg
}

// Commit checks the candidate against the schema and commits it through
// the backend. Its edits are then in the current configuration, so the
// candidate starts over from that.
func (s *Store) Commit(ctx context.Context, o CommitOptions) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.locked(o.Owner, "candidate", "running"); err != nil {
		return "", err
	}
	c, err := s.candidate(ctx)
	if err != nil {
		return "", err
	}
	if errs := c.Validate(); len(errs) > 0 {
		return "", &ValidationError{errs}
	}
	msg, err := s.backend.Commit(ctx, c, o)
	if err != nil || o.Validate {
		return msg, err
	}
	s.cand, s.base = nil, nil
	if err := s.save(); err != nil {
		return msg, errors.Join(errors.New("committed, but removing the candidate's files failed"), err)
	}
	return msg, nil
}
