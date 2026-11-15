// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// planOf makes a plan over the given agents, one target each.
func planOf(srv *Server, confirm int, agents ...*fleetAgent) *commitPlan {
	p := &commitPlan{commit: 1, st: &models.Settings{}, confirm: confirm}
	for i, a := range agents {
		fw := models.Firewall{Name: string(rune('a' + i))}
		fw.ID = uint(i + 1)
		p.fws = append(p.fws, fw)
		p.targets = append(p.targets, &commitTarget{fw: fw, a: a, doc: &fwconfig.Document{Generation: 1}})
	}
	srv.newAgent = func(f *models.Firewall) (agentAPI, error) { return agents[f.ID-1], nil }
	return p
}

// A change pending on any firewall refuses the commit before any is applied.
func TestCheckAgentsPendingRefusesBeforeApply(t *testing.T) {
	env := newEnv(t)
	a, b := &fleetAgent{}, &fleetAgent{pending: &agentapi.PendingStatus{Generation: 1}}
	p := planOf(env.srv, 0, a, b)
	if err := env.srv.checkAgents(context.Background(), p); !errors.Is(err, errPending) {
		t.Fatalf("checkAgents: %v", err)
	}
	if len(a.applied)+len(b.applied) != 0 {
		t.Errorf("applied before the check was done")
	}
}

// Several firewalls apply together with a window; with no timeout they are
// confirmed together, and when one fails the others are rolled back and the
// later ones are not tried.
func TestApplyAndSettleTogether(t *testing.T) {
	ctx := context.Background()
	env := newEnv(t)

	a, b := &fleetAgent{}, &fleetAgent{}
	p := planOf(env.srv, 0, a, b)
	if err := env.srv.checkAgents(ctx, p); err != nil {
		t.Fatal(err)
	}
	if !p.together || p.applyConfirm != jointConfirm {
		t.Errorf("together %v, window %d", p.together, p.applyConfirm)
	}
	res, err := env.srv.applyTargets(ctx, p, "u")
	if err != nil || len(a.applied) != 1 || len(b.applied) != 1 {
		t.Fatalf("apply: %v %d %d", err, len(a.applied), len(b.applied))
	}
	env.srv.settleTargets(ctx, p, err)
	if len(a.confirmed) != 1 || len(b.confirmed) != 1 || p.targets[0].dep.Status != "applied" {
		t.Errorf("confirmed %v %v, %q", a.confirmed, b.confirmed, p.targets[0].dep.Status)
	}
	if res.Commit != 1 || res.Status != "applied" {
		t.Errorf("result %+v", res)
	}

	a, b = &fleetAgent{}, &fleetAgent{fail: true}
	c := &fleetAgent{}
	p = planOf(env.srv, 0, a, b, c)
	if err := env.srv.checkAgents(ctx, p); err != nil {
		t.Fatal(err)
	}
	_, err = env.srv.applyTargets(ctx, p, "u")
	if err == nil {
		t.Fatal("a failed apply gave no error")
	}
	env.srv.settleTargets(ctx, p, err)
	if a.rolledBack != 1 || len(a.confirmed) != 0 || len(c.applied) != 0 {
		t.Errorf("rolled back %d, confirmed %v, c applied %d", a.rolledBack, a.confirmed, len(c.applied))
	}
	got := []string{p.targets[0].dep.Status, p.targets[1].dep.Status, p.targets[2].dep.Status}
	if got[0] != "rolled_back" || got[1] != "failed" || got[2] != "failed" {
		t.Errorf("statuses %v", got)
	}
}

// A document that does not validate is refused before any agent is asked,
// and the error names the firewall.
func TestValidateTargetsRefusesInvalid(t *testing.T) {
	fw := models.Firewall{Name: "edge"}
	good := &fwconfig.Document{Version: fwconfig.Version, Instances: []fwconfig.Instance{{Name: "main", Default: true}}}
	bad := &fwconfig.Document{Version: fwconfig.Version, Instances: []fwconfig.Instance{{Name: "bad name!"}}}
	if err := validateTargets([]*commitTarget{{fw: fw, doc: good}}); err != nil {
		t.Fatalf("a valid document refused: %v", err)
	}
	err := validateTargets([]*commitTarget{{fw: fw, doc: good}, {fw: fw, doc: bad}})
	if err == nil || !strings.Contains(err.Error(), "firewall edge") {
		t.Fatalf("validateTargets: %v", err)
	}
}
