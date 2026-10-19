// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// A firewall with portitor-config (Firewall.ConfigURL) gets its virtual
// firewalls from this portitor-web, its manager, through the manager API:
// a commit pushes those whose configuration differs there (InstanceHash),
// deletes those it no longer has, and commits there, as one of the
// commit's firewalls (confirmed and rolled back with the others). Its host
// (default instance) is portitor-config's own. The agent is asked for live
// data only; an HA pair with portitor-config on its primary is deployed
// by it to both hosts.

// viaConfig tells whether the firewall is deployed through portitor-config:
// its own, or its HA primary's.
func viaConfig(fws []models.Firewall, fw models.Firewall) bool {
	if fw.ConfigURL != "" {
		return true
	}
	if fw.HAPrimaryID != nil {
		for _, p := range fws {
			if p.ID == *fw.HAPrimaryID {
				return p.ConfigURL != ""
			}
		}
	}
	return false
}

// configTargets compares each portitor-config firewall's virtual firewalls
// with db (the commit's snapshot), and returns those that changed, and
// those that did not. A virtual firewall changed there (break-glass) or
// of the same name but portitor-config's own is a problem: the drift view
// settles it.
func (s *Server) configTargets(ctx context.Context, db *gorm.DB, fws []models.Firewall, only map[string]bool) (changed, same []*commitTarget, err error) {
	me := s.managerName()
	var problems []string
	for _, fw := range fws {
		if fw.ConfigURL == "" {
			continue
		}
		cfg, err := s.newConfig(&fw)
		if err != nil {
			return nil, nil, bad(fmt.Sprintf("firewall %s: %v", fw.Name, err))
		}
		st, err := cfg.State(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("firewall %s: %w", fw.Name, err)
		}
		if st.Pending {
			return nil, nil, errPending
		}
		if err := s.pushUsers(ctx, &fw, cfg); err != nil {
			return nil, nil, err
		}
		there := map[string]ManagedInstance{}
		for _, in := range st.Instances {
			there[in.Name] = in
		}
		var mine []models.Instance
		if err := db.Where("firewall_id = ? AND NOT is_default", fw.ID).Order("name").Find(&mine).Error; err != nil {
			return nil, nil, err
		}
		t := &commitTarget{fw: fw, cfg: cfg}
		for _, in := range mine {
			if only != nil && !only[in.Name] {
				continue
			}
			h, err := InstanceHash(db, in.Name)
			if err != nil {
				return nil, nil, err
			}
			got, ok := there[in.Name]
			switch {
			case ok && got.ManagedBy != me:
				problems = append(problems, fmt.Sprintf("%s: virtual firewall %s is the firewall's own there; rename one of them", fw.Name, in.Name))
			case ok && got.Diverged && got.Hash != h:
				problems = append(problems, fmt.Sprintf("%s: virtual firewall %s was changed on the firewall (break-glass); take that version or overwrite it (Firewalls)", fw.Name, in.Name))
			case !ok || got.Hash != h || got.Diverged:
				t.push = append(t.push, in.Name)
			}
		}
		if only == nil {
			for _, got := range st.Instances {
				if got.ManagedBy == me && !slices.ContainsFunc(mine, func(m models.Instance) bool { return m.Name == got.Name }) {
					t.del = append(t.del, got.Name)
				}
			}
		}
		if st.Schema != s.schemaVersion(db) {
			problems = append(problems, fmt.Sprintf("%s: portitor-config is at schema %d, this portitor-web at %d; update both to the same version", fw.Name, st.Schema, s.schemaVersion(db)))
		}
		if len(t.push) > 0 || len(t.del) > 0 {
			changed = append(changed, t)
		} else {
			same = append(same, t)
		}
	}
	if len(problems) > 0 {
		return nil, nil, &fwconfig.ValidationError{Problems: problems}
	}
	return changed, same, nil
}

func (s *Server) schemaVersion(db *gorm.DB) int64 {
	var v int64
	db.Raw("SELECT max(version_id) FROM goose_db_version WHERE is_applied").Scan(&v)
	return v
}

// pushTargets pushes and deletes the targets' virtual firewalls there.
// Pushed and uncommitted, they wait there for the next commit.
func (s *Server) pushTargets(ctx context.Context, db *gorm.DB, targets []*commitTarget) error {
	me := s.managerName()
	for _, t := range targets {
		for _, name := range t.push {
			var in models.Instance
			if err := db.Where("name = ?", name).First(&in).Error; err != nil {
				return err
			}
			b, err := ExportBundle(ctx, db, in.ID)
			if err != nil {
				return err
			}
			// A version taken from the firewall is overwritten by the
			// same: diverged no more.
			if _, err := t.cfg.Push(ctx, name, me, true, b); err != nil {
				return fmt.Errorf("firewall %s: pushing %s: %w", t.fw.Name, name, err)
			}
			slog.Info("pushed", "firewall", t.fw.Name, "instance", name)
		}
		for _, name := range t.del {
			if err := t.cfg.Delete(ctx, name, me); err != nil {
				return fmt.Errorf("firewall %s: deleting %s: %w", t.fw.Name, name, err)
			}
			slog.Info("deleted there", "firewall", t.fw.Name, "instance", name)
		}
		// Again, now with the memberships of the virtual firewalls just
		// pushed.
		if len(t.push) > 0 {
			if err := s.pushUsers(ctx, &t.fw, t.cfg); err != nil {
				return err
			}
		}
	}
	return nil
}

// commitVia commits the target's firewall through its portitor-config and
// records the outcome in t.dep.
func (s *Server) commitVia(ctx context.Context, t *commitTarget, confirm int) error {
	res, err := t.cfg.Commit(ctx, s.managerName(), confirm)
	if err != nil {
		t.dep.Status, t.dep.Message = "failed", err.Error()
		return err
	}
	t.dep.Status = res.Status
	t.dep.Message = fmt.Sprintf("portitor-config commit %d", res.Commit)
	var logs []string
	for _, d := range res.Deployments {
		if t.dep.Generation == 0 {
			// Its own firewall's generation, which its agent reports.
			t.dep.Generation = d.Generation
		}
		logs = append(logs, d.Log)
	}
	t.dep.Log = strings.Join(logs, "\n")
	if res.Status == "failed" {
		return errors.New("the commit failed there")
	}
	return nil
}

// finishTarget confirms (or rolls back) a target of this commit.
func (s *Server) finishTarget(ctx context.Context, t *commitTarget, confirm bool) error {
	switch {
	case t.cfg != nil && confirm:
		return t.cfg.Confirm(ctx)
	case t.cfg != nil:
		return t.cfg.Rollback(ctx)
	case confirm:
		return t.a.Confirm(ctx, t.dep.Generation)
	}
	_, err := t.a.Rollback(ctx)
	return err
}

// finishDeployment confirms (or rolls back) a pending deployment, through
// portitor-config where the firewall has one.
func (s *Server) finishDeployment(ctx context.Context, dep *models.Deployment, confirm bool) (*models.Firewall, error) {
	var fw models.Firewall
	if err := s.db.First(&fw, dep.FirewallID).Error; err != nil {
		return nil, err
	}
	t := &commitTarget{fw: fw, dep: *dep}
	var err error
	if fw.ConfigURL != "" {
		t.cfg, err = s.newConfig(&fw)
	} else {
		t.a, err = s.newAgent(&fw)
	}
	if err != nil {
		return &fw, bad(err.Error())
	}
	return &fw, s.finishTarget(ctx, t, confirm)
}
