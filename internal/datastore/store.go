// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/abundo/portitor/internal/schema"
)

// Backend is where the configuration is committed and runs.
type Backend interface {
	// Initial is the candidate when there is none kept yet: running.
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
	// Scope are the top-level lists a commit takes from the candidate, the
	// rest of the configuration staying what runs (nil: all).
	Scope []string
	// NoDeploy: a scoped commit that only makes the lists run; the
	// documents follow at the next commit.
	NoDeploy bool
}

// Store is the candidate: the working configuration that every frontend
// (the GUI and API, the CLI, NETCONF) edits and commits, shared by all. A commit leaves it as it is; discarding its
// changes makes it running again.
type Store struct {
	mu      sync.Mutex
	schema  *schema.Node
	backend Backend
	dir     string // candidate.json; "" keeps it in memory

	cand *Tree     // nil until first used
	gen  uint64    // counts the candidates set
	seen FileStamp // of candidate.json when it was last read or written here
	// bad is why candidate.json, there, could not be read: no candidate is
	// made in its place until it reads, or Discard or Replace sets one (the
	// file kept beside it, BadSuffix).
	bad error

	locks map[string]string // datastore (candidate, running) → the session holding its lock

	// OnChange, when set, is told each new candidate (s.mu is held).
	// Normalize's before is the candidate before the edit.
	OnChange func(*Tree) error
	// Normalize, when set, fixes up the entries an edit changed (in the
	// edited tree) or refuses the edit; Check reports what is wrong with a
	// candidate beyond the schema, at a commit and its validate.
	Normalize func(before, t *Tree, changed []*Node) error
	Check     func(t *Tree) []error
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
		t, err := s.read(s.path())
		switch {
		case err == nil:
			s.cand = t
		case !errors.Is(err, fs.ErrNotExist):
			s.bad = err
		}
		s.seen = StampOf(s.path())
	}
	return s
}

// BadSuffix names the copy of an unreadable candidate.json kept when a new
// candidate replaces it.
const BadSuffix = ".corrupt"

// CorruptError is a candidate.json that is there and can't be read.
type CorruptError struct {
	Path string
	Err  error
}

func (e *CorruptError) Error() string {
	return fmt.Sprintf("the candidate %s can't be read (%v): fix or remove it, or discard the candidate (it is kept as %s%s)",
		e.Path, e.Err, e.Path, BadSuffix)
}

func (e *CorruptError) Unwrap() error { return e.Err }

func (s *Store) path() string { return filepath.Join(s.dir, "candidate.json") }

// lockFile takes the lock the processes that share the candidate (the daemon
// and the console commands beside it) hold from reading it to writing it.
// A lock that can't be taken is an error: nothing goes on without it.
func (s *Store) lockFile() (unlock func(), err error) {
	if s.dir == "" {
		return func() {}, nil
	}
	u, err := LockDir(s.dir, ".candidate.lock")
	if err != nil {
		return nil, fmt.Errorf("locking the candidate: %w", err)
	}
	return u, nil
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
	if s.bad != nil {
		// The unreadable file is kept for a look at what went wrong.
		if err := os.Rename(s.path(), s.path()+BadSuffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("keeping the unreadable candidate: %w", err)
		}
	}
	if err := WriteFile(s.path(), data); err != nil {
		return err
	}
	s.bad = nil
	s.seen = StampOf(s.path())
	return nil
}

// WriteFile writes a tree's file (0600: it holds secrets) whole or not
// at all, on disk before it returns: the file and then its directory are
// synced, so a power loss leaves the old file or the new one.
func WriteFile(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// candidate is the candidate; s.mu is held.
func (s *Store) candidate(ctx context.Context) (*Tree, error) {
	// Another process may have changed the file (a console command that
	// resets a password): it is read again.
	if s.dir != "" && (s.cand != nil || s.bad != nil) {
		if now := StampOf(s.path()); now != s.seen && now != (FileStamp{}) {
			if t, err := s.read(s.path()); err == nil {
				s.cand, s.seen, s.bad = t, now, nil
				s.gen++
			}
		}
	}
	if s.cand == nil && s.bad != nil && StampOf(s.path()) == (FileStamp{}) {
		s.bad = nil // removed: a new candidate is made
	}
	if s.cand == nil && s.bad != nil {
		return nil, &CorruptError{Path: s.path(), Err: s.bad}
	}
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
	t, _, err := s.CandidateGen(ctx)
	return t, err
}

// CandidateGen is Candidate and its generation, which every new candidate
// raises: what a cache of something made from it is keyed by.
func (s *Store) CandidateGen(ctx context.Context) (*Tree, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.candidate(ctx)
	if err != nil {
		return nil, 0, err
	}
	return c.Clone(), s.gen, nil
}

// Gen is the candidate's generation (CandidateGen).
func (s *Store) Gen() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen
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
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
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
	if s.Normalize != nil {
		if err := s.Normalize(c, work, ChangedEntries(c, work)); err != nil {
			return err
		}
	}
	return s.set(work)
}

// EditRaw is Edit without Normalize: for a change the system makes that
// no user may (an HA promotion moves the hosts to the other firewall).
func (s *Store) EditRaw(ctx context.Context, fn func(*Tree) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
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
	s.gen++
	return s.save()
}

// Replace makes t the candidate without OnChange: for what OnChange's
// source changed.
func (s *Store) Replace(ctx context.Context, t *Tree) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	s.cand = t
	s.gen++
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
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
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
	if errs := s.validate(c); len(errs) > 0 {
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
	// A commit of some lists is checked as far as it goes by the backend:
	// what else the candidate holds doesn't stop it.
	if len(o.Scope) == 0 {
		if errs := s.validate(c); len(errs) > 0 {
			return "", &ValidationError{errs}
		}
	}
	// The backend runs without the store's lock, as the GUI's commit does
	// (Prepare): what it does afterwards edits the candidate too.
	clone := c.Clone()
	s.mu.Unlock()
	defer s.mu.Lock()
	return s.backend.Commit(ctx, clone, o)
}

// validate is the schema's problems with t, then Check's.
func (s *Store) validate(t *Tree) []error {
	if errs := t.Validate(); len(errs) > 0 || s.Check == nil {
		return errs
	}
	return s.Check(t)
}
