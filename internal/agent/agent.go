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
	cfg  *Config
	run  Runner
	log  *OpLog
	dhcp *dhcpManager

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
	a.mu.Lock()
	defer a.mu.Unlock()

	var pending pendingConfirm
	if err := readJSON(a.rollbackFile(), &pending); err == nil {
		slog.Warn("unconfirmed change found at startup; rolling back", "generation", pending.Generation)
		os.Remove(a.rollbackFile())
		if pending.Previous != nil {
			if err := a.applyLocked(ctx, *pending.Previous); err != nil {
				a.lastError = err.Error()
				return fmt.Errorf("startup rollback: %w", err)
			}
			a.log.Take()
			return nil
		}
		// No previous config: stay with the applied one below.
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
	a.dhcp.Stop()
}

func (a *Agent) renderOptions() render.Options {
	return render.Options{
		Paths:       a.cfg.Paths,
		Units:       a.cfg.Units,
		AntiLockout: a.cfg.antiLockout(),
		DHCPDNS:     a.dhcp.DNSServers(),
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
		a.pending.timer.Stop()
		a.pending = nil
	}

	res := &ApplyResult{Generation: doc.Generation}
	err := a.applyLocked(ctx, doc)
	if err != nil {
		a.lastError = err.Error()
		if previous != nil {
			a.log.Infof("apply failed, restoring generation %d: %v", previous.Generation, err)
			if rerr := a.applyLocked(ctx, *previous); rerr != nil {
				res.RollbackErrors = rerr.Error()
			}
			res.RolledBack = true
		}
		res.Log = a.log.Take()
		os.Remove(a.rollbackFile())
		return res, err
	}
	a.lastError = ""

	if confirmTimeout > 0 && previous != nil {
		p := &pendingConfirm{Generation: doc.Generation, Deadline: time.Now().Add(confirmTimeout), Previous: previous}
		if err := writeJSON(a.rollbackFile(), p, 0o600); err != nil {
			slog.Error("cannot persist rollback state", "err", err)
		}
		gen := doc.Generation
		p.timer = time.AfterFunc(confirmTimeout, func() { a.confirmTimeout(gen) })
		a.pending = p
		res.ConfirmBy = &p.Deadline
		a.log.Infof("generation %d applied; confirm before %s or it is rolled back", gen, p.Deadline.Format(time.RFC3339))
	} else {
		os.Remove(a.rollbackFile())
		a.log.Infof("generation %d applied", doc.Generation)
	}
	res.Log = a.log.Take()
	return res, nil
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
	a.pending.timer.Stop()
	a.pending = nil
	os.Remove(a.rollbackFile())
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

func (a *Agent) rollbackLocked(ctx context.Context) (*ApplyResult, error) {
	p := a.pending
	p.timer.Stop()
	a.pending = nil
	a.log.Take()
	err := a.applyLocked(ctx, *p.Previous)
	os.Remove(a.rollbackFile())
	res := &ApplyResult{Generation: p.Previous.Generation, RolledBack: true, Log: a.log.Take()}
	if err != nil {
		a.lastError = "rollback: " + err.Error()
		return res, err
	}
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
	if in == nil || !in.DNS.Enabled || !in.DNS.ForwardFromDHCP {
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
	return os.Rename(tmp.Name(), path)
}
