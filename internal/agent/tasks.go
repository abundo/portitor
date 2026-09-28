// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/abundo/portitor/internal/cron"
	"github.com/abundo/portitor/internal/fwconfig"
)

// taskOutputMax is how much of a command's output (its end) is kept.
const taskOutputMax = 4 << 10

// maxTaskSleep bounds how long the scheduler sleeps, so a change of the
// system clock delays a task by at most this.
const maxTaskSleep = time.Minute

// scheduler runs the applied document's tasks on their schedules, in the
// firewall's local time. A task that is still running when it is due
// again is not started twice.
type scheduler struct {
	// run runs one task; set by the agent (runTask), replaced in tests.
	run func(ctx context.Context, t fwconfig.Task) (output string, err error)
	now func() time.Time

	mu    sync.Mutex
	tasks map[string]*taskState
	wake  chan struct{}
	wg    sync.WaitGroup
	ctx   context.Context
	stop  context.CancelFunc
}

type taskState struct {
	cfg    fwconfig.Task
	sched  *cron.Schedule
	next   time.Time
	status TaskStatus
}

func newScheduler(run func(context.Context, fwconfig.Task) (string, error)) *scheduler {
	ctx, stop := context.WithCancel(context.Background())
	s := &scheduler{run: run, now: time.Now, tasks: map[string]*taskState{}, wake: make(chan struct{}, 1), ctx: ctx, stop: stop}
	s.wg.Add(1)
	go s.loop()
	return s
}

// Stop ends the scheduler and cancels running tasks, waiting for them.
func (s *scheduler) Stop() {
	s.stop()
	s.wg.Wait()
}

// Reconcile takes the tasks of a just applied document. A task whose
// configuration is unchanged keeps its next run and its last result.
func (s *scheduler) Reconcile(tasks []fwconfig.Task) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	keep := map[string]bool{}
	for _, t := range tasks {
		keep[t.Name] = true
		st, ok := s.tasks[t.Name]
		if ok && st.cfg == t {
			continue
		}
		sched, err := cron.Parse(t.Schedule)
		if err != nil {
			slog.Error("task schedule", "task", t.Name, "err", err) // validated; not reached
			continue
		}
		if !ok {
			st = &taskState{status: TaskStatus{Name: t.Name}}
			s.tasks[t.Name] = st
		}
		st.cfg, st.sched, st.next = t, sched, sched.Next(now)
		st.status.Kind, st.status.Schedule = t.Kind, t.Schedule
	}
	for name := range s.tasks {
		if !keep[name] {
			delete(s.tasks, name)
		}
	}
	notify(s.wake)
}

func (s *scheduler) loop() {
	defer s.wg.Done()
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
		case <-timer.C:
		}
		s.startDue()
		timer.Reset(s.sleep())
	}
}

// sleep is the time until the next task is due, at most maxTaskSleep.
func (s *scheduler) sleep() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := maxTaskSleep
	now := s.now()
	for _, st := range s.tasks {
		if !st.next.IsZero() {
			d = min(d, max(st.next.Sub(now), 0))
		}
	}
	return d
}

// startDue starts every task whose time has come and schedules its next
// run.
func (s *scheduler) startDue() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, st := range s.tasks {
		if st.next.IsZero() || st.next.After(now) {
			continue
		}
		st.next = st.sched.Next(now)
		if st.status.Running {
			slog.Warn("task still running; skipping this run", "task", st.cfg.Name)
			continue
		}
		s.start(st)
	}
}

// RunNow starts a task outside its schedule.
func (s *scheduler) RunNow(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.tasks[name]
	if !ok {
		return errNotFound{"no task " + name + " in the applied configuration"}
	}
	if st.status.Running {
		return errBusy{"task " + name + " is running"}
	}
	s.start(st)
	return nil
}

// start runs st in the background. Caller holds s.mu.
func (s *scheduler) start(st *taskState) {
	cfg := st.cfg
	started := s.now()
	st.status.Running = true
	st.status.LastStart = &started
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		log := slog.With("task", cfg.Name, "kind", cfg.Kind)
		log.Info("task started")
		out, err := s.run(s.ctx, cfg)
		ended := s.now()

		s.mu.Lock()
		defer s.mu.Unlock()
		if s.tasks[cfg.Name] != st {
			return // removed meanwhile
		}
		st.status.Running = false
		st.status.LastEnd = &ended
		st.status.Output = out
		if err != nil {
			st.status.LastResult, st.status.LastError = "error", err.Error()
			log.Warn("task failed", "err", err, "duration", ended.Sub(started).Round(time.Millisecond))
		} else {
			st.status.LastResult, st.status.LastError = "ok", ""
			log.Info("task done", "duration", ended.Sub(started).Round(time.Millisecond))
		}
	}()
}

// Status returns every task's state, by name.
func (s *scheduler) Status() []TaskStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TaskStatus, 0, len(s.tasks))
	for _, st := range s.tasks {
		ts := st.status
		if !st.next.IsZero() {
			next := st.next
			ts.Next = &next
		}
		out = append(out, ts)
	}
	slices.SortFunc(out, func(a, b TaskStatus) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// runTask runs one task for the scheduler.
func (a *Agent) runTask(ctx context.Context, t fwconfig.Task) (string, error) {
	switch t.Kind {
	case fwconfig.TaskIPList:
		return "", a.refreshIPList(ctx, t.IPList)
	case fwconfig.TaskCommand:
		return a.runCommand(ctx, t)
	}
	return "", fmt.Errorf("unknown task kind %q", t.Kind)
}

// runCommand runs a command task with /bin/sh -c as the console user, in
// its home directory. All of its processes are killed at the timeout.
func (a *Agent) runCommand(ctx context.Context, t fwconfig.Task) (string, error) {
	if a.cfg.ConsoleUser == ConsoleDisabled {
		return "", errors.New("command tasks are disabled on this firewall (console_user: none in agent.yaml)")
	}
	if a.cfg.DryRun {
		slog.Info("dry-run: not running command", "task", t.Name, "command", t.Command)
		return "(dry-run: not run)", nil
	}
	timeout := time.Duration(t.Timeout) * time.Second
	if timeout == 0 {
		timeout = fwconfig.DefaultTaskTimeout * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	login, err := consoleCommand(a.cfg.ConsoleUser, a.cfg.DryRun)
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", t.Command)
	cmd.Dir, cmd.Env = login.Dir, login.Env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if login.SysProcAttr != nil {
		cmd.SysProcAttr.Credential = login.SysProcAttr.Credential
	}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	// Background processes that keep the output open do not hold up
	// the task past this.
	cmd.WaitDelay = 5 * time.Second
	out := &tailBuffer{max: taskOutputMax}
	cmd.Stdout, cmd.Stderr = out, out
	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out after %s", timeout)
	}
	return out.String(), err
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu        sync.Mutex
	max       int
	buf       []byte
	truncated bool
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if over := len(b.buf) - b.max; over > 0 {
		b.buf = append(b.buf[:0], b.buf[over:]...)
		b.truncated = true
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := strings.ToValidUTF8(string(b.buf), "?")
	if b.truncated {
		s = "...\n" + s
	}
	return s
}
