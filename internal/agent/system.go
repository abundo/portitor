// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
)

// InstallerPath is where install.py puts a copy of itself on the agent
// host; the agent runs it to list and install Portitor releases.
const InstallerPath = "/usr/lib/portitor/install.py"

// Transient systemd units for the jobs that must outlive the agent: a
// Portitor update restarts it, and an interrupted dpkg run leaves a mess.
const (
	upgradeUnit = "portitor-os-upgrade.service"
	updateUnit  = "portitor-update.service"
)

// jobOutputLines is how much of a job's journal is returned.
const jobOutputLines = 400

// aptUpgrade upgrades without removing packages or asking about changed
// configuration files (the local version is kept).
const aptUpgrade = "apt-get update -q && apt-get -y -q " +
	"-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold " +
	"upgrade --with-new-pkgs"

// releaseTag is what the agent accepts as a release to install.
var releaseTag = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

// systemManager runs the operating system and Portitor updates.
type systemManager struct {
	run       Runner
	installer string

	mu       sync.Mutex
	check    agentapi.SystemJob
	releases *agentapi.Releases
	relErr   string
}

func newSystemManager(run Runner) *systemManager {
	return &systemManager{run: run, installer: InstallerPath}
}

// Status gathers the system status. It asks apt for the upgrades each
// time (a simulation: quick, no lock, no network).
func (m *systemManager) Status(ctx context.Context) agentapi.SystemStatus {
	st := agentapi.SystemStatus{
		OS:       osName(),
		Kernel:   readTrim("/proc/sys/kernel/osrelease"),
		Packages: []agentapi.PackageUpgrade{},
		Jobs:     []agentapi.SystemJob{},
	}
	if bt, ok := bootTime(); ok {
		st.BootTime = &bt
		st.RebootRequired = rebootRequired(bt)
	}
	if out, err := m.run.Run(ctx, "", "apt-get", "-s", "-q", "upgrade", "--with-new-pkgs"); err == nil {
		st.Packages = parseAptSimulation(out)
	}
	_, err := os.Stat(m.installer)
	st.Installer = err == nil

	m.mu.Lock()
	st.Releases, st.ReleasesError = m.releases, m.relErr
	if m.check.State != "" {
		st.Jobs = append(st.Jobs, m.check)
	}
	m.mu.Unlock()
	for _, j := range []struct{ name, unit string }{{agentapi.JobUpgrade, upgradeUnit}, {agentapi.JobUpdate, updateUnit}} {
		if job, ok := m.unitJob(ctx, j.name, j.unit); ok {
			st.Jobs = append(st.Jobs, job)
		}
	}
	return st
}

// Start starts a job, or returns errBusy while one runs. Only one job
// runs at a time: they all use apt or dpkg, or replace the agent.
func (m *systemManager) Start(ctx context.Context, req agentapi.SystemJobRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.check.State == agentapi.JobRunning {
		return errBusy{"an update check is running"}
	}
	for _, unit := range []string{upgradeUnit, updateUnit} {
		if job, ok := m.unitJob(ctx, "", unit); ok && job.State == agentapi.JobRunning {
			return errBusy{strings.TrimSuffix(unit, ".service") + " is running"}
		}
	}
	switch req.Job {
	case agentapi.JobCheck:
		now := time.Now()
		m.check = agentapi.SystemJob{Name: agentapi.JobCheck, State: agentapi.JobRunning, Started: &now}
		go m.runCheck(context.WithoutCancel(ctx))
		return nil
	case agentapi.JobUpgrade:
		return m.startUnit(ctx, upgradeUnit, "Portitor: upgrade Debian packages", "/bin/sh", "-c", aptUpgrade)
	case agentapi.JobUpdate:
		if !releaseTag.MatchString(req.Release) {
			return fmt.Errorf("invalid release %q", req.Release)
		}
		if _, err := os.Stat(m.installer); err != nil {
			return fmt.Errorf("%s is missing; update with install.py once", m.installer)
		}
		return m.startUnit(ctx, updateUnit, "Portitor: install release "+req.Release,
			"python3", m.installer, "--install", req.Release, "--yes", "--skip-self-update")
	}
	return fmt.Errorf("unknown job %q", req.Job)
}

// runCheck refreshes apt's package lists and lists the Portitor releases.
func (m *systemManager) runCheck(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var log strings.Builder
	var failed bool
	out, err := m.run.Run(ctx, "", "apt-get", "update", "-q")
	log.Write(out)
	if err != nil {
		failed = true
		fmt.Fprintf(&log, "apt-get update failed: %v\n", err)
	}

	var rel *agentapi.Releases
	var relErr string
	if _, statErr := os.Stat(m.installer); statErr != nil {
		relErr = m.installer + " is missing; update with install.py once"
	} else {
		out, err := m.run.Run(ctx, "", "python3", m.installer, "--list", "--json", "--skip-self-update")
		var r agentapi.Releases
		switch {
		case err != nil:
			relErr = err.Error()
		case len(bytes.TrimSpace(out)) == 0:
			relErr = "no answer from install.py (dry run?)"
		case json.Unmarshal(out, &r) != nil:
			relErr = "install.py --list --json printed something else than JSON"
		default:
			rel = &r
		}
		if relErr != "" {
			failed = true
			fmt.Fprintf(&log, "listing Portitor releases failed: %s\n", relErr)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	m.check.Finished = &now
	m.check.Output = log.String()
	m.check.State = agentapi.JobSucceeded
	if failed {
		m.check.State = agentapi.JobFailed
	}
	m.releases, m.relErr = rel, relErr
	slog.Info("update check done", "state", m.check.State)
}

// startUnit runs argv as a transient unit that stays loaded after it
// exits (RemainAfterExit), so its result can be read until the next run.
func (m *systemManager) startUnit(ctx context.Context, unit, desc string, argv ...string) error {
	// Unload the previous run. Errors mean there was none.
	_, _ = m.run.Run(ctx, "", "systemctl", "stop", unit)
	_, _ = m.run.Run(ctx, "", "systemctl", "reset-failed", unit)
	args := []string{
		"--unit=" + unit, "--description=" + desc,
		"--property=RemainAfterExit=yes",
		"--setenv=DEBIAN_FRONTEND=noninteractive",
		"--setenv=XDG_CACHE_HOME=/var/cache/portitor",
		"--setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"--",
	}
	_, err := m.run.Run(ctx, "", "systemd-run", append(args, argv...)...)
	return err
}

// unitJob reads a transient unit's state and the journal of its latest
// run. ok is false when the unit is not loaded (never run since boot).
func (m *systemManager) unitJob(ctx context.Context, name, unit string) (agentapi.SystemJob, bool) {
	out, err := m.run.Run(ctx, "", "systemctl", "show", unit, "--timestamp=unix",
		"--property=LoadState,ActiveState,SubState,Result,InvocationID,ExecMainStartTimestamp,ExecMainExitTimestamp")
	if err != nil {
		return agentapi.SystemJob{}, false
	}
	job, id, ok := parseUnitShow(out)
	if !ok {
		return job, false
	}
	job.Name = name
	if id != "" && name != "" {
		logOut, _ := m.run.Run(ctx, "", "journalctl", "--no-pager", "-q", "-o", "cat",
			"-n", strconv.Itoa(jobOutputLines), "_SYSTEMD_INVOCATION_ID="+id)
		job.Output = strings.ToValidUTF8(string(logOut), "?")
	}
	return job, true
}

// Reboot restarts the firewall shortly, so the answer gets out first.
func (m *systemManager) Reboot() {
	time.AfterFunc(2*time.Second, func() {
		slog.Warn("rebooting (requested through the API)")
		if _, err := m.run.Run(context.Background(), "", "systemctl", "reboot"); err != nil {
			slog.Error("reboot failed", "err", err)
		}
	})
}

// parseUnitShow reads `systemctl show --timestamp=unix` output: the job's
// state and times, and the invocation id of its latest run.
func parseUnitShow(out []byte) (job agentapi.SystemJob, invocation string, ok bool) {
	p := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if k, v, found := strings.Cut(sc.Text(), "="); found {
			p[k] = v
		}
	}
	if p["LoadState"] != "loaded" {
		return job, "", false
	}
	switch p["ActiveState"] {
	case "activating", "reloading", "deactivating":
		job.State = agentapi.JobRunning
	case "active":
		job.State = agentapi.JobRunning
		if p["SubState"] == "exited" {
			job.State = agentapi.JobSucceeded
		}
	case "failed":
		job.State = agentapi.JobFailed
	default: // inactive: stopped
		job.State = agentapi.JobSucceeded
		if p["Result"] != "success" {
			job.State = agentapi.JobFailed
		}
	}
	job.Started = unixStamp(p["ExecMainStartTimestamp"])
	if job.State != agentapi.JobRunning {
		job.Finished = unixStamp(p["ExecMainExitTimestamp"])
	}
	return job, p["InvocationID"], true
}

// unixStamp parses systemd's "@1700000000" (empty when not set).
func unixStamp(s string) *time.Time {
	n, err := strconv.ParseInt(strings.TrimPrefix(s, "@"), 10, 64)
	if err != nil || n <= 0 {
		return nil
	}
	t := time.Unix(n, 0)
	return &t
}

// aptInst matches a simulated install: "Inst name [old] (new origins [arch])".
// A new package has no [old].
var aptInst = regexp.MustCompile(`^Inst (\S+) (?:\[([^\]]*)\] )?\((\S+) ([^)]*)\)`)

// parseAptSimulation lists the packages `apt-get -s upgrade` would install.
func parseAptSimulation(out []byte) []agentapi.PackageUpgrade {
	pkgs := []agentapi.PackageUpgrade{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		m := aptInst.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		pkgs = append(pkgs, agentapi.PackageUpgrade{
			Name: m[1], From: m[2], To: m[3],
			Security: strings.Contains(m[4], "-security"),
		})
	}
	return pkgs
}

// rebootRequired: a package asked for it (/run/reboot-required, written
// by some Debian packages), or a kernel image was installed since boot.
func rebootRequired(boot time.Time) bool {
	if _, err := os.Stat("/run/reboot-required"); err == nil {
		return true
	}
	images, _ := filepath.Glob("/boot/vmlinuz-*")
	for _, f := range images {
		if fi, err := os.Stat(f); err == nil && fi.ModTime().After(boot) {
			return true
		}
	}
	return false
}

func bootTime() (time.Time, bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, false
	}
	return parseBootTime(data)
}

func parseBootTime(procStat []byte) (time.Time, bool) {
	sc := bufio.NewScanner(bytes.NewReader(procStat))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return time.Time{}, false
			}
			return time.Unix(n, 0), true
		}
	}
	return time.Time{}, false
}

// osName is PRETTY_NAME from os-release.
func osName() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			if u, err := strconv.Unquote(v); err == nil {
				return u
			}
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

func readTrim(path string) string {
	data, _ := os.ReadFile(path)
	return strings.TrimSpace(string(data))
}
