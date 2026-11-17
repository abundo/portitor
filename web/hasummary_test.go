// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

func TestPairSummary(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	healthy := func() [2]*agentapi.HAStatus {
		return [2]*agentapi.HAStatus{
			{Node: "primary", State: agentapi.HAActive, Term: 3, PeerAlive: true, Watchdog: agentapi.HAWatchdogHardware,
				Health: 2, Monitored: 2, LinkSeen: ago(time.Second), MgmtSeen: ago(time.Second), WitnessSeen: ago(time.Second), Version: "1.2.0"},
			{Node: "secondary", State: agentapi.HAStandby, Term: 3, PeerAlive: true, Watchdog: agentapi.HAWatchdogHardware,
				Health: 2, Monitored: 2, LinkSeen: ago(time.Second), MgmtSeen: ago(time.Second), Version: "1.2.0"},
		}
	}
	good := configCopy{Known: true, Replicated: true, At: ago(5 * time.Second)}
	names := [2]string{"fw1", "fw2"}
	status := func(p haPairSummary, name string) string {
		for _, c := range p.Checks {
			if c.Name == name {
				return c.Status
			}
		}
		return ""
	}

	p := pairSummary(names, healthy(), models.HAWitnessExternal, good, now)
	if !p.FailoverReady || p.Active != "fw1" {
		t.Fatalf("healthy pair: %+v", p)
	}
	for _, c := range p.Checks {
		if c.Status != checkOK {
			t.Errorf("healthy pair: %+v", c)
		}
	}

	cases := []struct {
		name  string
		edit  func(*[2]*agentapi.HAStatus, *configCopy, *string)
		check string
		want  string
		ready bool
	}{
		{"standby gone", func(s *[2]*agentapi.HAStatus, _ *configCopy, _ *string) { s[1] = nil }, "standby", checkFail, false},
		{"standby fenced", func(s *[2]*agentapi.HAStatus, _ *configCopy, _ *string) { s[1].State = agentapi.HAFenced }, "standby", checkFail, false},
		{"standby less healthy", func(s *[2]*agentapi.HAStatus, _ *configCopy, _ *string) { s[1].Health = 1 }, "standby", checkWarn, true},
		{"none active", func(s *[2]*agentapi.HAStatus, _ *configCopy, _ *string) { s[0].State = agentapi.HAStandby }, "active", checkFail, false},
		{"link silent", func(s *[2]*agentapi.HAStatus, _ *configCopy, _ *string) { s[0].LinkSeen = ago(time.Minute) }, "paths", checkWarn, true},
		{"no paths", func(s *[2]*agentapi.HAStatus, _ *configCopy, _ *string) {
			s[0].LinkSeen, s[0].MgmtSeen, s[0].PeerAlive = ago(time.Minute), ago(time.Minute), false
		}, "paths", checkFail, false},
		{"old agent", func(s *[2]*agentapi.HAStatus, _ *configCopy, _ *string) { s[0].LinkSeen, s[0].MgmtSeen = nil, nil }, "paths", checkOK, true},
		{"local witness", func(_ *[2]*agentapi.HAStatus, _ *configCopy, w *string) { *w = models.HAWitnessLocal }, "witness", checkWarn, true},
		{"witness silent", func(s *[2]*agentapi.HAStatus, _ *configCopy, _ *string) { s[0].WitnessSeen = ago(time.Minute) }, "witness", checkWarn, true},
		{"softdog", func(s *[2]*agentapi.HAStatus, _ *configCopy, _ *string) { s[1].Watchdog = agentapi.HAWatchdogSoft }, "watchdog", checkWarn, true},
		{"no watchdog", func(s *[2]*agentapi.HAStatus, _ *configCopy, _ *string) { s[1].Watchdog = agentapi.HAWatchdogNone }, "watchdog", checkFail, false},
		{"not copied", func(_ *[2]*agentapi.HAStatus, c *configCopy, _ *string) { c.Replicated = false }, "configuration", checkFail, false},
		{"copy failed", func(_ *[2]*agentapi.HAStatus, c *configCopy, _ *string) { c.Error = "disk full" }, "configuration", checkFail, false},
		{"copy old", func(_ *[2]*agentapi.HAStatus, c *configCopy, _ *string) { c.At = ago(time.Hour) }, "configuration", checkWarn, true},
		{"releases differ", func(s *[2]*agentapi.HAStatus, _ *configCopy, _ *string) { s[1].Version = "1.1.0" }, "release", checkWarn, true},
		{"dhcp error", func(s *[2]*agentapi.HAStatus, _ *configCopy, _ *string) {
			s[0].DHCP = []agentapi.HADHCPSync{{Instance: "guest", Error: "refused"}}
		}, "dhcp", checkWarn, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sts, cp, w := healthy(), good, models.HAWitnessExternal
			tc.edit(&sts, &cp, &w)
			p := pairSummary(names, sts, w, cp, now)
			if got := status(p, tc.check); got != tc.want {
				t.Errorf("%s: %q, want %q (%+v)", tc.check, got, tc.want, p.Checks)
			}
			if p.FailoverReady != tc.ready {
				t.Errorf("failover ready %v, want %v (%+v)", p.FailoverReady, tc.ready, p.Checks)
			}
		})
	}

	// The secondary active after a failover: it is the one checked.
	sts := healthy()
	sts[0].State, sts[1].State, sts[1].Term, sts[1].WitnessSeen = agentapi.HAStandby, agentapi.HAActive, 4, ago(time.Second)
	if p := pairSummary(names, sts, models.HAWitnessExternal, good, now); p.Active != "fw2" || !p.FailoverReady {
		t.Errorf("secondary active: %+v", p)
	}
}

// TestCheckPairAction: the firewall's check action, on either host of a
// pair, sums the pair up and adds the interfaces the hosts lack.
func TestCheckPairAction(t *testing.T) {
	env, _, _ := haPair(t)
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	for _, fw := range []string{"firewall", "fw1b"} {
		rec := env.do("GET", "/api/config/candidate/firewall="+fw+"?action=check", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", fw, rec.Code, rec.Body)
		}
		var out struct {
			Primary, Secondary string
			Ready              bool `json:"failover-ready"`
			Checks             []haCheck
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		// The fake agents have no active host, and the same NICs (none).
		if out.Primary != "firewall" || out.Secondary != "fw1b" || out.Ready {
			t.Errorf("%s: %s", fw, rec.Body)
		}
		if !slices.ContainsFunc(out.Checks, func(c haCheck) bool { return c.Name == "interfaces" && c.Status == checkOK }) {
			t.Errorf("%s: no interfaces check: %s", fw, rec.Body)
		}
	}
	// A firewall in no pair.
	alone, _, _ := twoFirewalls(t)
	if rec := alone.do("GET", "/api/config/candidate/firewall=firewall?action=check", nil); rec.Code != http.StatusConflict {
		t.Errorf("no pair: %d %s", rec.Code, rec.Body)
	}
}

// pairAgent is one host of a fake pair that hands the active role over.
type pairAgent struct {
	*fleetAgent
	pair *fakePair
	me   int
	nics []agentapi.NICStatus
}

type fakePair struct {
	mu       sync.Mutex
	active   int
	switches []int
}

func (p *pairAgent) ha() *agentapi.HAStatus {
	p.pair.mu.Lock()
	defer p.pair.mu.Unlock()
	now := time.Now()
	st := &agentapi.HAStatus{Node: []string{"primary", "secondary"}[p.me], State: agentapi.HAStandby, PeerAlive: true,
		Watchdog: agentapi.HAWatchdogHardware, LinkSeen: &now, MgmtSeen: &now, WitnessSeen: &now, Version: "1.2.0"}
	if p.pair.active == p.me {
		st.State = agentapi.HAActive
	}
	return st
}

func (p *pairAgent) HA(context.Context) (*agentapi.HAStatus, error) { return p.ha(), nil }

func (p *pairAgent) Status(context.Context) (*agentapi.Status, error) {
	return &agentapi.Status{HA: p.ha(), NICs: append([]agentapi.NICStatus{}, p.nics...)}, nil
}

func (p *pairAgent) HASwitchover(context.Context) error {
	p.pair.mu.Lock()
	defer p.pair.mu.Unlock()
	if p.pair.active != p.me {
		return errors.New("not active")
	}
	p.pair.active = 1 - p.me
	p.pair.switches = append(p.pair.switches, p.me)
	return nil
}

// TestSwitchoverTest: the action refuses a pair that can't fail over, and
// switches a ready one over and back.
func TestSwitchoverTest(t *testing.T) {
	env, agents, pair := haPair(t)
	env.do("PUT", "/api/firewalls/1", map[string]any{"name": "firewall", "agent_url": "https://192.0.2.1:8443", "agent_fingerprint": strings.Repeat("ab", 32), "ha_witness": "external"})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	old := switchSettle
	switchSettle = 0
	t.Cleanup(func() { switchSettle = old })
	fp := &fakePair{}
	hosts := map[uint]*pairAgent{1: {fleetAgent: agents[1], pair: fp, me: 0}, pair: {fleetAgent: agents[pair], pair: fp, me: 1}}
	env.srv.newAgent = func(f *models.Firewall) (agentAPI, error) { return hosts[f.ID], nil }

	doc, err := env.srv.liveDocument(1)
	if err != nil {
		t.Fatal(err)
	}
	var nics []agentapi.NICStatus
	for _, in := range doc.Instances {
		for _, ifc := range in.Interfaces {
			if ifc.Kind == fwconfig.KindPhysical {
				nics = append(nics, agentapi.NICStatus{Name: ifc.Name})
			}
		}
	}
	// The secondary lacks the primary's interfaces: refused.
	hosts[1].nics = nics
	rec := env.do("POST", "/api/config/candidate/firewall=fw1b?action=test-switchover", map[string]any{})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "interface") {
		t.Fatalf("not ready: %d %s", rec.Code, rec.Body)
	}
	if len(fp.switches) != 0 {
		t.Fatalf("switched anyway: %v", fp.switches)
	}

	// With the same interfaces: over to the secondary and back.
	hosts[pair].nics = nics
	rec = env.do("POST", "/api/config/candidate/firewall=fw1b?action=test-switchover", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("ready: %d %s", rec.Code, rec.Body)
	}
	var out struct{ From, To string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.From != "firewall" || out.To != "fw1b" || !slices.Equal(fp.switches, []int{0, 1}) || fp.active != 0 {
		t.Errorf("%s, switches %v, active %d", rec.Body, fp.switches, fp.active)
	}

	// Only a global admin switches; only who reads everything checks.
	fp.switches = nil
	var tina uint
	for _, u := range []struct{ name, role string }{{"vera", "viewer"}, {"nora", "none"}, {"tina", "none"}} {
		tina = env.create("/api/users", map[string]string{"username": u.name, "password": "a long password", "role": u.role})
	}
	guest := env.roles()["vf-guest"].ID
	if rec := env.do("PUT", fmt.Sprintf("/api/roles/%d", guest), map[string]any{
		"members": []map[string]any{{"user_id": tina, "level": "admin"}},
	}); rec.Code != http.StatusOK {
		t.Fatalf("role: %d %s", rec.Code, rec.Body)
	}
	for _, u := range []string{"vera", "nora", "tina"} {
		env.login(u, "a long password")
		if rec := env.do("POST", "/api/config/candidate/firewall=fw1b?action=test-switchover", map[string]any{}); rec.Code < 400 {
			t.Errorf("%s switched: %d %s", u, rec.Code, rec.Body)
		}
		rec := env.do("GET", "/api/config/candidate/firewall=fw1b?action=check", nil)
		if ok := rec.Code == http.StatusOK; ok != (u == "vera") {
			t.Errorf("%s checked: %d %s", u, rec.Code, rec.Body)
		}
	}
	if len(fp.switches) != 0 {
		t.Errorf("switched for a non-admin: %v", fp.switches)
	}
}
