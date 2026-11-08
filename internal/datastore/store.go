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

// Backend is where the configuration is committed and runs.
type Backend interface {
	// Initial is the candidate when there is none kept yet: running, or an
	// old database's configuration at the first start.
	Initial(ctx context.Context) (*Tree, error)
	// Running is what the firewalls run: the live commit's.
	Running(ctx context.Context) (*Tree, error)
	// Commit keeps t as a commit and deploys it; when that fails, nothing
	// changes. It says how it went.
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

// Store is the candidate: the working configuration that every frontend
// (the GUI and API, the CLI, NETCONF) edits and commits, shared as the
// database was before it. A commit leaves it as it is; discarding its
// changes makes it running again.
type Store struct {
	mu      sync.Mutex
	schema  *schema.Node
	backend Backend
	dir     string // candidate.json; "" keeps it in memory

	cand *Tree // nil until first used

	locks map[string]string // datastore (candidate, running) → the session holding its lock

	// OnChange, when set, is told each new candidate (s.mu is held).
	OnChange func(*Tree) error
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
	if datastore == "candidate" {
		c, err := s.candidate(ctx)
		if err != nil {
			return err
		}
		run, err := s.backend.Running(ctx)
		if err != nil {
			return err
		}
		if !Equal(c, run) {
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
	if dir != "" {
		if t, err := s.read(filepath.Join(dir, "candidate.json")); err == nil {
			s.cand = t
		}
	}
	return s
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
	if s.dir == "" || s.cand == nil {
		return nil
	}
	data, err := s.cand.JSON(JSONOptions{Secrets: true})
	if err != nil {
		return err
	}
	return WriteFile(filepath.Join(s.dir, "candidate.json"), data)
}

// WriteFile writes a tree's file (0600: it holds secrets) whole or not
// at all.
func WriteFile(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// candidate is the candidate; s.mu is held.
func (s *Store) candidate(ctx context.Context) (*Tree, error) {
	if s.cand == nil {
		t, err := s.backend.Initial(ctx)
		if err != nil {
			return nil, err
		}
		s.cand = t
		if err := s.save(); err != nil {
			return nil, err
		}
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
	return s.set(work)
}

// set makes t the candidate; s.mu is held.
func (s *Store) set(t *Tree) error {
	if s.OnChange != nil {
		if err := s.OnChange(t); err != nil {
			return err
		}
	}
	t.Renamed = nil
	s.cand = t
	return s.save()
}

// Replace makes t the candidate without OnChange: for what OnChange's
// source changed.
func (s *Store) Replace(ctx context.Context, t *Tree) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cand = t
	return s.save()
}

// Changed reports whether the candidate differs from running.
func (s *Store) Changed(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.candidate(ctx)
	if err != nil {
		return false, err
	}
	run, err := s.backend.Running(ctx)
	if err != nil {
		return false, err
	}
	return !Equal(run, c), nil
}

// Discard makes the candidate running again.
func (s *Store) Discard(ctx context.Context, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.locked(owner, "candidate"); err != nil {
		return err
	}
	run, err := s.backend.Running(ctx)
	if err != nil {
		return err
	}
	return s.set(run.Clone())
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

// Prepare is the candidate to commit, for a commit made outside Commit
// (the GUI's): the locks let owner commit and it is valid by the schema.
func (s *Store) Prepare(ctx context.Context, owner string) (*Tree, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.locked(owner, "candidate", "running"); err != nil {
		return nil, err
	}
	c, err := s.candidate(ctx)
	if err != nil {
		return nil, err
	}
	if errs := c.Validate(); len(errs) > 0 {
		return nil, &ValidationError{errs}
	}
	return c.Clone(), nil
}

// Commit checks the candidate against the schema and commits it through
// the backend. The candidate stays as it is.
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
	return s.backend.Commit(ctx, c.Clone(), o)
}
