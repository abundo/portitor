// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/fwconfig"
)

// failRunner fails loading a ruleset (nft -f <file>) while fail is set.
type failRunner struct {
	Runner
	fail atomic.Bool
}

func (r *failRunner) RunInput(ctx context.Context, netns string, stdin []byte, name string, args ...string) ([]byte, error) {
	if r.fail.Load() && name == "nft" && len(args) == 2 && args[0] == "-f" && args[1] != "-" {
		return nil, errors.New("nft: injected failure")
	}
	return r.Runner.RunInput(ctx, netns, stdin, name, args...)
}

func (r *failRunner) Run(ctx context.Context, netns, name string, args ...string) ([]byte, error) {
	return r.RunInput(ctx, netns, nil, name, args...)
}

func withFailRunner(a *Agent) *failRunner {
	r := &failRunner{Runner: a.run}
	a.run = r
	return r
}

func sampleGen(gen int64) fwconfig.Document {
	doc := fwconfig.SampleDocument()
	doc.Generation = gen
	return doc
}

func pendingOnDisk(t *testing.T, a *Agent) *pendingConfirm {
	t.Helper()
	var p pendingConfirm
	if err := readJSON(a.rollbackFile(), &p); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		t.Fatal(err)
	}
	return &p
}

// A crash while a change is pending rolls back at the next start, and a
// start whose rollback fails leaves the rollback for the one after.
func TestRollbackSurvivesRestarts(t *testing.T) {
	a, _ := testAgent(t)
	ctx := context.Background()
	if _, err := a.Apply(ctx, sampleGen(1), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(ctx, sampleGen(2), time.Hour); err != nil {
		t.Fatal(err)
	}
	if p := pendingOnDisk(t, a); p == nil || p.Generation != 2 || p.Previous.Generation != 1 {
		t.Fatalf("rollback file: %+v", p)
	}
	a.Stop() // the "crash": nothing is confirmed

	a2 := New(a.cfg)
	t.Cleanup(a2.Stop)
	withFailRunner(a2).fail.Store(true)
	if err := a2.Start(ctx); err == nil {
		t.Fatal("startup rollback did not fail")
	}
	if p := pendingOnDisk(t, a2); p == nil || p.Previous.Generation != 1 {
		t.Fatalf("a failed startup rollback lost the rollback file: %+v", p)
	}
	a2.Stop()

	a3 := New(a.cfg)
	t.Cleanup(a3.Stop)
	if err := a3.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if st := a3.Status(ctx); st.Generation != 1 {
		t.Errorf("restored generation %d, want 1", st.Generation)
	}
	if p := pendingOnDisk(t, a3); p != nil {
		t.Errorf("rollback file left after a restore: %+v", p)
	}
}

// A rollback that fails keeps the change pending, and says so.
func TestFailedRollbackStaysPending(t *testing.T) {
	a, _ := testAgent(t)
	fr := withFailRunner(a)
	ctx := context.Background()
	if _, err := a.Apply(ctx, sampleGen(1), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(ctx, sampleGen(2), time.Hour); err != nil {
		t.Fatal(err)
	}

	fr.fail.Store(true)
	res, err := a.Rollback(ctx)
	if err == nil || res.RolledBack || res.RollbackErrors == "" {
		t.Fatalf("failed rollback: %+v %v", res, err)
	}
	if st := a.Status(ctx); st.Pending == nil || st.Pending.Generation != 2 {
		t.Errorf("not pending after a failed rollback: %+v", st.Pending)
	}
	if p := pendingOnDisk(t, a); p == nil {
		t.Error("rollback file removed after a failed rollback")
	}

	fr.fail.Store(false)
	if res, err := a.Rollback(ctx); err != nil || !res.RolledBack {
		t.Fatalf("rollback: %+v %v", res, err)
	}
	if st := a.Status(ctx); st.Pending != nil || st.Generation != 1 {
		t.Errorf("after rollback: pending %+v, generation %d", st.Pending, st.Generation)
	}
	if p := pendingOnDisk(t, a); p != nil {
		t.Errorf("rollback file left: %+v", p)
	}
}

// A failed apply whose restore fails too doesn't claim a rollback, and
// keeps the rollback file of a pending change.
func TestFailedApplyFailedRestore(t *testing.T) {
	a, _ := testAgent(t)
	fr := withFailRunner(a)
	ctx := context.Background()
	if _, err := a.Apply(ctx, sampleGen(1), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(ctx, sampleGen(2), time.Hour); err != nil {
		t.Fatal(err)
	}
	fr.fail.Store(true)
	res, err := a.Apply(ctx, sampleGen(3), time.Hour)
	if err == nil || res.RolledBack || res.RollbackErrors == "" {
		t.Fatalf("apply 3: %+v %v", res, err)
	}
	if p := pendingOnDisk(t, a); p == nil || p.Previous.Generation != 1 {
		t.Errorf("rollback file: %+v", p)
	}

	// With the restore working, the failed apply goes back to the last
	// confirmed generation and the rollback file goes.
	fr.fail.Store(false)
	if _, err := a.Apply(ctx, sampleGen(4), time.Hour); err != nil {
		t.Fatal(err)
	}
	// Fail only the new apply; the restore after it works.
	a.run = &failOnce{Runner: fr.Runner}
	res, err = a.Apply(ctx, sampleGen(5), time.Hour)
	if err == nil || !res.RolledBack || res.RollbackErrors != "" {
		t.Fatalf("apply 5: %+v %v", res, err)
	}
	if p := pendingOnDisk(t, a); p != nil {
		t.Errorf("rollback file after a restore: %+v", p)
	}
}

// failOnce fails the first ruleset load only.
type failOnce struct {
	Runner
	done bool
}

func (r *failOnce) RunInput(ctx context.Context, netns string, stdin []byte, name string, args ...string) ([]byte, error) {
	if !r.done && name == "nft" && len(args) == 2 && args[0] == "-f" && args[1] != "-" {
		r.done = true
		return nil, errors.New("nft: injected failure")
	}
	return r.Runner.RunInput(ctx, netns, stdin, name, args...)
}

func (r *failOnce) Run(ctx context.Context, netns, name string, args ...string) ([]byte, error) {
	return r.RunInput(ctx, netns, nil, name, args...)
}

// An apply with confirmation that can't write its rollback file changes
// nothing.
func TestApplyNeedsRollbackFile(t *testing.T) {
	a, _ := testAgent(t)
	ctx := context.Background()
	if _, err := a.Apply(ctx, sampleGen(1), 0); err != nil {
		t.Fatal(err)
	}
	// A directory in the way makes the write fail.
	if err := os.MkdirAll(filepath.Join(a.rollbackFile(), "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(ctx, sampleGen(2), time.Hour); err == nil {
		t.Fatal("apply without a rollback file succeeded")
	}
	if st := a.Status(ctx); st.Generation != 1 || st.Pending != nil {
		t.Errorf("generation %d pending %+v, want 1 and none", st.Generation, st.Pending)
	}
}

// Each ruleset is loaded before an interface comes up or moves, and
// before forwarding is turned on.
func TestRulesetBeforeForwarding(t *testing.T) {
	a, _ := testAgent(t)
	res, err := a.Apply(context.Background(), sampleGen(1), 0)
	if err != nil {
		t.Fatal(err)
	}
	loaded := map[string]int{}
	for i, l := range res.Log {
		if strings.Contains(l, "nft -f ") && strings.HasSuffix(l, "nftables.nft") {
			loaded[filepath.Base(filepath.Dir(strings.Fields(l)[len(strings.Fields(l))-1]))] = i
		}
	}
	if len(loaded) != 2 {
		t.Fatalf("rulesets loaded: %v\n%s", loaded, strings.Join(res.Log, "\n"))
	}
	for i, l := range res.Log {
		if (strings.Contains(l, " up") && !strings.Contains(l, "dev lo up")) || strings.Contains(l, "forwarding=1") || strings.Contains(l, " netns fw-") {
			for in, at := range loaded {
				if at > i {
					t.Errorf("ruleset of %s loaded after %q", in, l)
				}
			}
		}
	}
}
