// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package datastore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/abundo/portitor/internal/schema"
)

type memBackend struct{ running *Tree }

func (m *memBackend) Initial(context.Context) (*Tree, error) { return m.running.Clone(), nil }
func (m *memBackend) Running(context.Context) (*Tree, error) { return m.running.Clone(), nil }
func (m *memBackend) Commit(context.Context, *Tree, CommitOptions) (string, error) {
	return "", nil
}

// A candidate.json that is there but unreadable is never replaced by
// running behind the user's back: it is an error, kept as it is, until it
// is fixed, removed or discarded (and then kept beside the new one).
func TestCorruptCandidate(t *testing.T) {
	ctx := context.Background()
	root := schema.MustLoad()
	dir := t.TempDir()
	path := filepath.Join(dir, "candidate.json")
	bad := []byte(`{"portitor:host-name": `)
	must(t, os.WriteFile(path, bad, 0o600))

	s := NewStore(root, &memBackend{running: New(root)}, dir)
	var ce *CorruptError
	if _, err := s.Candidate(ctx); !errors.As(err, &ce) {
		t.Fatalf("Candidate: %v, want a CorruptError", err)
	}
	if err := s.Edit(ctx, "a", func(*Tree) error { return nil }); !errors.As(err, &ce) {
		t.Fatalf("Edit: %v, want a CorruptError", err)
	}
	if got, _ := os.ReadFile(path); string(got) != string(bad) {
		t.Fatalf("the corrupt file was changed: %q", got)
	}

	// Discarding sets running as the candidate and keeps the old file.
	must(t, s.Discard(ctx, "a"))
	if got, _ := os.ReadFile(path + BadSuffix); string(got) != string(bad) {
		t.Fatalf("kept copy %q, want %q", got, bad)
	}
	if _, err := s.Candidate(ctx); err != nil {
		t.Fatal(err)
	}

	// A missing file is a new candidate, from running.
	must(t, os.Remove(path))
	s = NewStore(root, &memBackend{running: New(root)}, dir)
	if _, err := s.Candidate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}

	// A corrupt file removed by hand lets a new candidate be made.
	must(t, os.WriteFile(path, bad, 0o600))
	s = NewStore(root, &memBackend{running: New(root)}, dir)
	must(t, os.Remove(path))
	if _, err := s.Candidate(ctx); err != nil {
		t.Fatal(err)
	}
}
