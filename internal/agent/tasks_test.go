// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"os/user"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/fwconfig"
)

// testScheduler is a scheduler without its loop, on a clock the test sets.
type testScheduler struct {
	*scheduler
	mu    sync.Mutex
	clock time.Time
	runs  chan string
	// release ends a run; its value is the run's error.
	release chan error
}

func newTestScheduler(start time.Time) *testScheduler {
	ts := &testScheduler{clock: start, runs: make(chan string, 10), release: make(chan error)}
	ctx, stop := context.WithCancel(context.Background())
	ts.scheduler = &scheduler{
		run: func(ctx context.Context, t fwconfig.Task) (string, error) {
			ts.runs <- t.Name
			return "out " + t.Name, <-ts.release
		},
		now:   func() time.Time { ts.mu.Lock(); defer ts.mu.Unlock(); return ts.clock },
		tasks: map[string]*taskState{}, wake: make(chan struct{}, 1), ctx: ctx, stop: stop,
	}
	return ts
}

func (ts *testScheduler) set(t time.Time) {
	ts.mu.Lock()
	ts.clock = t
	ts.mu.Unlock()
}

func (ts *testScheduler) status(name string) TaskStatus {
	for _, s := range ts.Status() {
		if s.Name == name {
			return s
		}
	}
	return TaskStatus{}
}

func (ts *testScheduler) wait(t *testing.T, name string, running bool) TaskStatus {
	t.Helper()
	for range 200 {
		if s := ts.status(name); s.Running == running {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("task %s never got running=%v", name, running)
	return TaskStatus{}
}

func TestScheduler(t *testing.T) {
	t0 := time.Date(2026, 9, 28, 10, 7, 30, 0, time.Local)
	ts := newTestScheduler(t0)
	ts.Reconcile([]fwconfig.Task{
		{Name: "often", Schedule: "*/15 * * * *", Kind: fwconfig.TaskIPList, IPList: "x"},
		{Name: "never", Schedule: "0 0 30 2 *", Kind: fwconfig.TaskIPList, IPList: "x"},
	})
	st := ts.status("often")
	if st.Next == nil || !st.Next.Equal(t0.Add(7*time.Minute+30*time.Second)) || st.Kind != "iplist" || st.Schedule != "*/15 * * * *" {
		t.Fatalf("status %+v", st)
	}
	if ts.status("never").Next != nil {
		t.Error("a schedule that never fires has a next run")
	}

	ts.startDue()
	select {
	case name := <-ts.runs:
		t.Fatalf("%s ran early", name)
	default:
	}

	// Due: it runs, and its next run moves on.
	ts.set(t0.Add(8 * time.Minute))
	ts.startDue()
	if name := <-ts.runs; name != "often" {
		t.Fatalf("ran %s", name)
	}
	st = ts.wait(t, "often", true)
	if !st.Next.Equal(t0.Add(22*time.Minute + 30*time.Second)) {
		t.Errorf("next %s", st.Next)
	}
	// Due again while running: skipped.
	ts.set(t0.Add(23 * time.Minute))
	ts.startDue()
	if err := ts.RunNow("often"); !errors.As(err, new(errBusy)) {
		t.Errorf("run now while running: %v", err)
	}
	ts.release <- errors.New("boom")
	st = ts.wait(t, "often", false)
	if st.LastResult != "error" || st.LastError != "boom" || st.Output != "out often" || st.LastEnd == nil {
		t.Errorf("after failure: %+v", st)
	}
	select {
	case <-ts.runs:
		t.Fatal("a run while running was not skipped")
	default:
	}

	// Run now, outside the schedule.
	if err := ts.RunNow("often"); err != nil {
		t.Fatal(err)
	}
	<-ts.runs
	ts.release <- nil
	if st = ts.wait(t, "often", false); st.LastResult != "ok" || st.LastError != "" {
		t.Errorf("after success: %+v", st)
	}
	if err := ts.RunNow("nope"); !errors.As(err, new(errNotFound)) {
		t.Errorf("unknown task: %v", err)
	}

	// An unchanged task keeps its state; a changed one is rescheduled; a
	// removed one goes.
	next := *ts.status("often").Next
	ts.Reconcile([]fwconfig.Task{{Name: "often", Schedule: "*/15 * * * *", Kind: fwconfig.TaskIPList, IPList: "x"}})
	if st = ts.status("often"); !st.Next.Equal(next) || st.LastResult != "ok" {
		t.Errorf("unchanged task: %+v", st)
	}
	ts.Reconcile([]fwconfig.Task{{Name: "often", Schedule: "@daily", Kind: fwconfig.TaskIPList, IPList: "x"}})
	if st = ts.status("often"); st.Next.Hour() != 0 || st.Schedule != "@daily" || st.LastResult != "ok" {
		t.Errorf("changed task: %+v", st)
	}
	if len(ts.Status()) != 1 {
		t.Errorf("removed task still there: %+v", ts.Status())
	}
}

func TestRunCommand(t *testing.T) {
	a, _ := testAgent(t)
	task := fwconfig.Task{Name: "t", Kind: fwconfig.TaskCommand, Command: "echo hello; echo oops >&2"}

	a.cfg.ConsoleUser = ConsoleDisabled
	if _, err := a.runCommand(context.Background(), task); err == nil || !strings.Contains(err.Error(), "console_user: none") {
		t.Errorf("console off: %v", err)
	}
	a.cfg.ConsoleUser = "portitor"
	if out, err := a.runCommand(context.Background(), task); err != nil || !strings.Contains(out, "dry-run") {
		t.Errorf("dry-run: %q %v", out, err)
	}

	// A real run needs a user with a login shell; the agent runs the
	// command as itself when it is that user.
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	if _, err := loginShell("/etc/passwd", u.Username); err != nil {
		t.Skip(err)
	}
	a.cfg.DryRun, a.cfg.ConsoleUser = false, u.Username
	out, err := a.runCommand(context.Background(), task)
	if err != nil || out != "hello\noops\n" {
		t.Errorf("run: %q %v", out, err)
	}
	task.Command = "echo before; exit 3"
	if out, err := a.runCommand(context.Background(), task); err == nil || out != "before\n" {
		t.Errorf("exit 3: %q %v", out, err)
	}
	// The timeout kills the whole process group, background jobs too.
	task.Command, task.Timeout = "sleep 30 & sleep 30", 1
	start := time.Now()
	if _, err := a.runCommand(context.Background(), task); err == nil || !strings.Contains(err.Error(), "timed out after 1s") {
		t.Errorf("timeout: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("timeout took %s", d)
	}
}

func TestTailBuffer(t *testing.T) {
	b := &tailBuffer{max: 8}
	b.Write([]byte("0123"))
	if b.String() != "0123" {
		t.Errorf("%q", b.String())
	}
	b.Write([]byte("456789ab"))
	if b.String() != "...\n456789ab" {
		t.Errorf("%q", b.String())
	}
}
