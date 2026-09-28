// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
)

func TestParseAptSimulation(t *testing.T) {
	out := `NOTE: This is only a simulation!
Reading package lists...
Inst libssl3t64 [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [amd64])
Inst bind9 [1:9.20.11-4] (1:9.20.11-4+deb13u1 Debian:13.1/stable [amd64]) []
Inst linux-image-6.12.48+deb13-amd64 (6.12.48-1 Debian:13.1/stable [amd64])
Conf libssl3t64 (3.5.1-1+deb13u1 Debian-Security:13/stable-security [amd64])
`
	got := parseAptSimulation([]byte(out))
	want := []agentapi.PackageUpgrade{
		{Name: "libssl3t64", From: "3.5.1-1", To: "3.5.1-1+deb13u1", Security: true},
		{Name: "bind9", From: "1:9.20.11-4", To: "1:9.20.11-4+deb13u1"},
		{Name: "linux-image-6.12.48+deb13-amd64", To: "6.12.48-1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestParseUnitShow(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		state     string
		finished  bool
		ok        bool
	}{
		{"not loaded", "LoadState=not-found\nActiveState=inactive\n", "", false, false},
		{"running", "LoadState=loaded\nActiveState=active\nSubState=running\nExecMainStartTimestamp=@1700000000\nExecMainExitTimestamp=\n", agentapi.JobRunning, false, true},
		{"done", "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nExecMainStartTimestamp=@1700000000\nExecMainExitTimestamp=@1700000100\n", agentapi.JobSucceeded, true, true},
		{"failed", "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainStartTimestamp=@1700000000\nExecMainExitTimestamp=@1700000100\n", agentapi.JobFailed, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job, _, ok := parseUnitShow([]byte(tc.out + "InvocationID=abc\n"))
			if ok != tc.ok || job.State != tc.state || (job.Finished != nil) != tc.finished {
				t.Errorf("got ok=%v state=%q finished=%v", ok, job.State, job.Finished)
			}
		})
	}
}

func TestParseBootTime(t *testing.T) {
	bt, ok := parseBootTime([]byte("cpu  1 2 3\nbtime 1700000000\nprocesses 5\n"))
	if !ok || !bt.Equal(time.Unix(1700000000, 0)) {
		t.Errorf("got %v %v", bt, ok)
	}
}

// sysRunner records commands and answers systemctl show with a unit state.
type sysRunner struct {
	mu    sync.Mutex
	cmds  []string
	units map[string]string // unit -> ActiveState/SubState, e.g. "active/running"
}

func (r *sysRunner) RunInput(ctx context.Context, netns string, _ []byte, name string, args ...string) ([]byte, error) {
	return r.Run(ctx, netns, name, args...)
}

func (r *sysRunner) Run(_ context.Context, _, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cmd := name + " " + strings.Join(args, " ")
	if name == "systemctl" && args[0] == "show" {
		state, ok := r.units[args[1]]
		if !ok {
			return []byte("LoadState=not-found\n"), nil
		}
		active, sub, _ := strings.Cut(state, "/")
		return []byte("LoadState=loaded\nActiveState=" + active + "\nSubState=" + sub + "\n"), nil
	}
	if name == "python3" {
		return []byte(`{"installed":{"agent":"v1.0.0"},"latest":"v1.1.0","releases":[{"tag":"v1.1.0","newer":true,"installable":true}]}`), nil
	}
	r.cmds = append(r.cmds, cmd)
	return nil, nil
}

func (r *sysRunner) ran(prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.cmds {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func TestSystemJobs(t *testing.T) {
	ctx := context.Background()
	run := &sysRunner{units: map[string]string{}}
	m := newSystemManager(run)
	m.installer = filepath.Join(t.TempDir(), "install.py")
	if err := os.WriteFile(m.installer, []byte("#"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := m.Start(ctx, agentapi.SystemJobRequest{Job: agentapi.JobUpdate, Release: "v1.2.3; rm -rf /"}); err == nil {
		t.Error("an invalid release tag was accepted")
	}
	if err := m.Start(ctx, agentapi.SystemJobRequest{Job: "shell"}); err == nil {
		t.Error("an unknown job was accepted")
	}

	if err := m.Start(ctx, agentapi.SystemJobRequest{Job: agentapi.JobUpdate, Release: "v1.2.3"}); err != nil {
		t.Fatal(err)
	}
	if !run.ran("systemd-run --unit=portitor-update.service") {
		t.Errorf("update not started as a transient unit: %q", run.cmds)
	}

	// While a job runs, no other starts.
	run.units[upgradeUnit] = "active/running"
	var busy errBusy
	if err := m.Start(ctx, agentapi.SystemJobRequest{Job: agentapi.JobCheck}); !errors.As(err, &busy) {
		t.Errorf("check during an upgrade: %v", err)
	}
	run.units[upgradeUnit] = "active/exited"

	if err := m.Start(ctx, agentapi.SystemJobRequest{Job: agentapi.JobCheck}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := m.Status(ctx)
		var check *agentapi.SystemJob
		for i := range st.Jobs {
			if st.Jobs[i].Name == agentapi.JobCheck {
				check = &st.Jobs[i]
			}
		}
		if check != nil && check.State != agentapi.JobRunning {
			if check.State != agentapi.JobSucceeded || st.Releases == nil || st.Releases.Latest != "v1.1.0" {
				t.Errorf("check: %+v, releases %+v (%s)", check, st.Releases, st.ReleasesError)
			}
			if !st.Installer {
				t.Error("installer not found")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("check did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !run.ran("apt-get update") {
		t.Error("check did not run apt-get update")
	}
}
