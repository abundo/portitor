// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package agent is portitor-agent: it runs on the firewall as root,
// receives fwconfig documents from portitor-web over an authenticated TLS
// API, and makes the system match them.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

type Agent struct {
	cfg *Config
	run Runner
	log *OpLog
	// bg runs the background commands (endpoint re-resolving), which are
	// not part of an apply's log.
	bg    Runner
	dhcp  *dhcpManager
	dhcp6 *dhcp6Manager
	ddns  *dyndnsManager
	certs *certManager
	pkts  *packetLog
	dnsq  *queryLog
	lldp  *lldpManager
	lists *ipLists
	tasks *scheduler
	sys   *systemManager

	stopBg context.CancelFunc
	bgDone sync.WaitGroup

	mu        sync.Mutex // serialises apply / confirm / rollback
	applied   *fwconfig.Document
	pending   *pendingConfirm
	lastApply time.Time
	lastError string
}

// pendingConfirm is an applied document that rolls back to Previous
// unless confirmed before Deadline.
type pendingConfirm struct {
	Generation int64              `json:"generation"`
	Deadline   time.Time          `json:"deadline"`
	Previous   *fwconfig.Document `json:"previous"`
	timer      *time.Timer
}

func New(cfg *Config) *Agent {
	a := &Agent{cfg: cfg, log: &OpLog{}}
	if cfg.DryRun {
		a.run = &DryRunner{Log: a.log}
	} else {
		a.run = &ExecRunner{Log: a.log}
	}
	a.dhcp = newDHCPManager(a.run, cfg.DryRun, a.onDHCPChange)
	a.dhcp6 = newDHCP6Manager(a.run, cfg.DryRun, a.onPDChange)
	a.ddns = newDyndnsManager(cfg.DryRun)
	a.pkts = newPacketLog(cfg.DryRun)
	a.dnsq = newQueryLog(cfg.DryRun)
	a.lldp = newLLDPManager(cfg.DryRun)
	a.lists = newIPLists()
	a.tasks = newScheduler(a.runTask)
	// Updates and background work have runners of their own: their
	// commands are not part of an apply's log.
	if cfg.DryRun {
		a.sys = newSystemManager(&DryRunner{})
		a.bg = &DryRunner{}
	} else {
		a.sys = newSystemManager(&ExecRunner{})
		a.bg = &ExecRunner{}
	}
	a.certs = newCertManager(cfg.DryRun, cfg.Paths, a.bg)
	return a
}

func (a *Agent) appliedFile() string  { return filepath.Join(a.cfg.Paths.StateDir, "applied.json") }
func (a *Agent) rollbackFile() string { return filepath.Join(a.cfg.Paths.StateDir, "rollback.json") }

// Start restores state after a (re)boot: if a change was awaiting
// confirmation when the agent stopped, the previous config is restored;
// otherwise the last applied config is re-applied.
func (a *Agent) Start(ctx context.Context) error {
	// 0711: BIND (running as its own user) must traverse into its zone
	// directories below; the agent's own state files are 0600.
	if err := os.MkdirAll(a.cfg.Paths.StateDir, 0o711); err != nil {
		return err
	}
	for _, p := range programStatus(nil) {
		if p.Path == "" {
			slog.Warn("program not installed", "program", p.Name, "purpose", p.Purpose)
		}
	}
	bgCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	a.stopBg = cancel
	a.bgDone.Add(1)
	go func() {
		defer a.bgDone.Done()
		a.resolveLoop(bgCtx)
	}()

	a.mu.Lock()
	defer a.mu.Unlock()

	var pending pendingConfirm
	if err := readJSON(a.rollbackFile(), &pending); err == nil {
		slog.Warn("unconfirmed change found at startup; rolling back", "generation", pending.Generation)
		if pending.Previous != nil {
			// The file stays until the previous config is back, so a
			// failed restore is tried again at the next start.
			if err := a.applyLocked(ctx, *pending.Previous); err != nil {
				a.lastError = "startup rollback: " + err.Error()
				return fmt.Errorf("startup rollback: %w", err)
			}
			a.log.Take()
			return a.removeRollback()
		}
		// No previous config: stay with the applied one below.
		if err := a.removeRollback(); err != nil {
			return err
		}
	}

	var doc fwconfig.Document
	if err := readJSON(a.appliedFile(), &doc); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Info("no applied configuration yet; waiting for portitor-web")
			return nil
		}
		return err
	}
	slog.Info("re-applying last configuration", "generation", doc.Generation)
	if err := a.applyLocked(ctx, doc); err != nil {
		a.lastError = err.Error()
		return err
	}
	a.log.Take()
	return nil
}

func (a *Agent) Stop() {
	if a.stopBg != nil {
		a.stopBg()
		a.bgDone.Wait()
	}
	a.tasks.Stop()
	a.lists.Stop()
	a.ddns.Stop()
	a.certs.Stop()
	a.pkts.Stop()
	a.dnsq.Stop()
	a.lldp.Stop()
	a.dhcp.Stop()
	a.dhcp6.Stop()
}

func (a *Agent) renderOptions() render.Options {
	return render.Options{
		Paths:       a.cfg.Paths,
		Units:       a.cfg.Units,
		AntiLockout: a.cfg.antiLockout(),
		DHCPDNS:     a.dhcp.DNSServers(),
		Delegated:   a.dhcp6.Prefixes(),
	}
}

func (a *Agent) Render(doc fwconfig.Document) (*RenderResult, error) {
	b, err := render.Render(doc, a.renderOptions())
	if err != nil {
		return nil, err
	}
	res := &RenderResult{Files: b.Redacted(), Current: []render.File{}}
	a.mu.Lock()
	applied := a.applied
	a.mu.Unlock()
	if applied != nil {
		if cur, err := render.Render(*applied, a.renderOptions()); err == nil {
			res.Current = cur.Redacted()
		}
	}
	return res, nil
}

// Apply makes the system match doc. With confirmTimeout > 0 the change
// is rolled back automatically unless Confirm is called in time - the
// safety net for rules that cut off the management connection.
func (a *Agent) Apply(ctx context.Context, doc fwconfig.Document, confirmTimeout time.Duration) (*ApplyResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.log.Take()

	// The rollback target is the last confirmed config: a second apply
	// while one is pending does not move it.
	previous := a.applied
	if a.pending != nil {
		previous = a.pending.Previous
	}
	confirm := confirmTimeout > 0 && previous != nil
	var p *pendingConfirm
	if confirm {
		// Journal the rollback target before anything changes: a crash
		// during or after the apply then rolls back at the next start.
		// Without it there is no safety net, so don't apply.
		p = &pendingConfirm{Generation: doc.Generation, Deadline: time.Now().Add(confirmTimeout), Previous: previous}
		if err := writeJSON(a.rollbackFile(), p, 0o600); err != nil {
			return nil, fmt.Errorf("persist rollback state: %w", err)
		}
	}
	if a.pending != nil {
		a.pending.timer.Stop()
		a.pending = nil
	}

	res := &ApplyResult{Generation: doc.Generation}
	err := a.applyLocked(ctx, doc)
	if err != nil {
		a.lastError = err.Error()
		if previous == nil {
			// Nothing to go back to; no rollback file was written.
			res.Log = a.log.Take()
			return res, err
		}
		a.log.Infof("apply failed, restoring generation %d: %v", previous.Generation, err)
		if rerr := a.applyLocked(ctx, *previous); rerr != nil {
			// The rollback file, if any, stays: the next start tries
			// again. Without one, applied.json still holds previous.
			res.RollbackErrors = rerr.Error()
			a.lastError = fmt.Sprintf("%v; restoring generation %d failed: %v", err, previous.Generation, rerr)
		} else {
			res.RolledBack = true
			if rerr := a.removeRollback(); rerr != nil {
				res.RollbackErrors = rerr.Error()
			}
		}
		res.Log = a.log.Take()
		return res, err
	}
	a.lastError = ""

	if confirm {
		gen := doc.Generation
		p.timer = time.AfterFunc(confirmTimeout, func() { a.confirmTimeout(gen) })
		a.pending = p
		res.ConfirmBy = &p.Deadline
		a.log.Infof("generation %d applied; confirm before %s or it is rolled back", gen, p.Deadline.Format(time.RFC3339))
	} else {
		if err := a.removeRollback(); err != nil {
			// A leftover file would roll this config back at the next
			// start.
			res.Log = a.log.Take()
			return res, err
		}
		a.log.Infof("generation %d applied", doc.Generation)
	}
	res.Log = a.log.Take()
	return res, nil
}

// removeRollback removes the rollback file, which marks a change as not
// confirmed yet, and makes the removal durable.
func (a *Agent) removeRollback() error {
	if err := os.Remove(a.rollbackFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove rollback state: %w", err)
	}
	return syncDir(filepath.Dir(a.rollbackFile()))
}

func (a *Agent) Confirm(generation int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending == nil {
		return errors.New("nothing to confirm")
	}
	if a.pending.Generation != generation {
		return fmt.Errorf("pending generation is %d, not %d", a.pending.Generation, generation)
	}
	// Until the file is gone a restart would roll back, so the change
	// stays pending if it can't be removed.
	if err := a.removeRollback(); err != nil {
		return err
	}
	a.pending.timer.Stop()
	a.pending = nil
	slog.Info("configuration confirmed", "generation", generation)
	return nil
}

// Rollback restores the pre-change config of a pending apply now.
func (a *Agent) Rollback(ctx context.Context) (*ApplyResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending == nil {
		return nil, errors.New("nothing to roll back")
	}
	return a.rollbackLocked(ctx)
}

func (a *Agent) confirmTimeout(generation int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pending == nil || a.pending.Generation != generation {
		return
	}
	slog.Warn("change not confirmed in time; rolling back", "generation", generation)
	if _, err := a.rollbackLocked(context.Background()); err != nil {
		slog.Error("rollback failed", "err", err)
	}
}

// rollbackRetry is how long a failed rollback waits before it is tried
// again.
const rollbackRetry = time.Minute

// rollbackLocked restores the previous config of the pending change. If
// that fails, the change stays pending (and its rollback file stays), and
// the rollback is tried again after rollbackRetry.
func (a *Agent) rollbackLocked(ctx context.Context) (*ApplyResult, error) {
	p := a.pending
	p.timer.Stop()
	a.log.Take()
	err := a.applyLocked(ctx, *p.Previous)
	if err == nil {
		err = a.removeRollback()
	}
	res := &ApplyResult{Generation: p.Previous.Generation, Log: a.log.Take()}
	if err != nil {
		res.RollbackErrors = err.Error()
		a.lastError = "rollback: " + err.Error()
		gen := p.Generation
		p.timer = time.AfterFunc(rollbackRetry, func() { a.confirmTimeout(gen) })
		return res, err
	}
	a.pending = nil
	res.RolledBack = true
	a.lastError = fmt.Sprintf("generation %d was rolled back to %d", p.Generation, p.Previous.Generation)
	return res, nil
}

// onDHCPChange re-renders an instance's BIND config when the upstream DNS
// servers learned by DHCP change.
func (a *Agent) onDHCPChange(instance string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.applied == nil {
		return
	}
	in := a.applied.Instance(instance)
	if in == nil || !in.DNS.Enabled || in.DNS.ForwardMode == fwconfig.ForwardOff ||
		in.DNS.Upstream != fwconfig.UpstreamDHCP && !in.DNS.ForwardFromDHCP {
		return
	}
	b, err := render.Render(*a.applied, a.renderOptions())
	if err != nil {
		return
	}
	path := filepath.Join(a.cfg.Paths.InstanceEtc(instance), "named.conf")
	f := b.File(path)
	if f == nil {
		return
	}
	changed, err := a.writeFile(*f)
	if err != nil {
		slog.Error("update named.conf", "err", err)
		return
	}
	if changed {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = a.run.Run(ctx, "", "systemctl", "reload-or-restart", a.cfg.Units.Named(instance))
	}
	a.log.Take()
}

// onPDChange applies the current document again when a prefix delegated
// to an instance changes: the delegated addresses, and the router
// advertisements and DNS built on them, move to the new prefix.
func (a *Agent) onPDChange(instance string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.applied == nil {
		return
	}
	if in := a.applied.Instance(instance); in == nil || !in.UsesDelegated() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	a.log.Infof("delegated prefix of instance %s changed, applying generation %d again", instance, a.applied.Generation)
	if err := a.applyLocked(ctx, *a.applied); err != nil {
		slog.Error("apply after delegated prefix change", "instance", instance, "err", err)
		a.lastError = err.Error()
	}
	a.log.Take()
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func writeJSON(path string, v any, mode os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, data, mode)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// syncDir makes a rename or removal in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
