// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// fleetAgent is one firewall's agent: it records what it applies, holds a
// change pending while it has a confirm timeout, and fails when told to.
type fleetAgent struct {
	agentAPI
	fail       bool
	applied    []fwconfig.Document
	pending    *agentapi.PendingStatus
	generation int64
	confirmed  []int64
	rolledBack int
	vrrp, log  string
	// down: the agent can't be reached; votes counts the witness's.
	down  bool
	votes int
}

var errDown = errors.New("agent unreachable")

func (f *fleetAgent) HA(context.Context) (*agentapi.HAStatus, error) {
	if f.down {
		return nil, errDown
	}
	return &agentapi.HAStatus{Node: "primary"}, nil
}

func (f *fleetAgent) HAVote(context.Context, int) (*agentapi.HAStatus, error) {
	if f.down {
		return nil, errDown
	}
	f.votes++
	return &agentapi.HAStatus{}, nil
}

func (f *fleetAgent) Status(context.Context) (*agentapi.Status, error) {
	if f.down {
		return nil, errDown
	}
	return &agentapi.Status{Generation: f.generation, Pending: f.pending, NICs: []agentapi.NICStatus{}}, nil
}

func (f *fleetAgent) Apply(_ context.Context, doc fwconfig.Document, confirm int) (*agentapi.ApplyResult, error) {
	if f.fail {
		return nil, errors.New("apply failed")
	}
	f.applied = append(f.applied, doc)
	f.generation = doc.Generation
	res := &agentapi.ApplyResult{Generation: doc.Generation}
	if confirm > 0 {
		by := time.Now().Add(time.Duration(confirm) * time.Second)
		f.pending = &agentapi.PendingStatus{Generation: doc.Generation, Deadline: by}
		res.ConfirmBy = &by
	}
	return res, nil
}

func (f *fleetAgent) Confirm(_ context.Context, gen int64) error {
	f.confirmed = append(f.confirmed, gen)
	f.pending = nil
	return nil
}

func (f *fleetAgent) Rollback(context.Context) (*agentapi.ApplyResult, error) {
	f.rolledBack++
	f.pending = nil
	return &agentapi.ApplyResult{RolledBack: true}, nil
}

// VRRP and Logs answer with the instance and the log line the test set.
func (f *fleetAgent) VRRP(context.Context) (*agentapi.VRRPResponse, error) {
	return &agentapi.VRRPResponse{Instances: []agentapi.VRRPInstance{{Instance: f.vrrp}}}, nil
}

func (f *fleetAgent) Logs(context.Context, int64) (*agentapi.LogsResponse, error) {
	return &agentapi.LogsResponse{Entries: []agentapi.LogEntry{{Message: f.log}}}, nil
}

func (f *fleetAgent) last() *fwconfig.Document {
	if len(f.applied) == 0 {
		return nil
	}
	return &f.applied[len(f.applied)-1]
}

func instanceNames(doc *fwconfig.Document) []string {
	var out []string
	for _, in := range doc.Instances {
		out = append(out, in.Name)
	}
	slices.Sort(out)
	return out
}

// twoFirewalls sets up the first firewall with a virtual firewall "guest"
// and a second one, "branch", with "shop"; each has its own agent.
func twoFirewalls(t *testing.T) (*testEnv, map[uint]*fleetAgent, uint) {
	t.Helper()
	env := newEnv(t)
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	env.do("PUT", "/api/settings", map[string]any{"virtual_firewalls": true, "confirm_timeout": 0})
	branch := env.create("/api/firewalls", map[string]any{"name": "branch", "agent_url": "https://192.0.2.2:8443", "agent_token": "secret"})
	agents := map[uint]*fleetAgent{1: {}, branch: {}}
	env.srv.newAgent = func(f *models.Firewall) (agentAPI, error) { return agents[f.ID], nil }
	env.create("/api/instances", map[string]any{"name": "guest"})
	env.create("/api/instances", map[string]any{"name": "shop", "firewall_id": branch})
	return env, agents, branch
}

func TestFirewallsDeploy(t *testing.T) {
	env, agents, branch := twoFirewalls(t)

	// The second firewall's host is its default instance, named after it,
	// and the token never comes back.
	var host models.Instance
	if err := env.srv.db.Where("firewall_id = ? AND is_default", branch).First(&host).Error; err != nil || host.Name != "branch" {
		t.Fatalf("branch host: %+v %v", host, err)
	}
	if rec := env.do("GET", "/api/firewalls", nil); strings.Contains(rec.Body.String(), "secret") || !strings.Contains(rec.Body.String(), `"has_agent_token":true`) {
		t.Errorf("firewalls: %s", rec.Body)
	}

	// The first commit deploys each firewall its own instances.
	rec := env.do("POST", "/api/deploy/apply", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	if got := instanceNames(agents[1].last()); !slices.Equal(got, []string{"guest", "main"}) {
		t.Errorf("first firewall got %v", got)
	}
	if got := instanceNames(agents[branch].last()); !slices.Equal(got, []string{"branch", "shop"}) {
		t.Errorf("branch got %v", got)
	}
	// Together they waited for confirmation, and were confirmed at once
	// since the confirm timeout is 0.
	if len(agents[1].confirmed) != 1 || len(agents[branch].confirmed) != 1 {
		t.Errorf("confirmed: %v %v", agents[1].confirmed, agents[branch].confirmed)
	}
	if rec := env.do("GET", "/api/deploy/changes", nil); !strings.Contains(rec.Body.String(), `"changed":false`) {
		t.Errorf("changes after commit: %s", rec.Body)
	}

	// A change on the branch deploys there only.
	var shop models.Instance
	env.srv.db.Where("name = ?", "shop").First(&shop)
	env.create("/api/rules", map[string]any{"instance_id": shop.ID, "chain": "input", "action": "drop", "enabled": true})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	if len(agents[1].applied) != 1 || len(agents[branch].applied) != 2 {
		t.Errorf("applies: first %d, branch %d", len(agents[1].applied), len(agents[branch].applied))
	}
	var fws []models.Firewall
	env.srv.db.Order("id").Find(&fws)
	if fws[0].Generation != 1 || fws[1].Generation != 2 {
		t.Errorf("generations: %d %d", fws[0].Generation, fws[1].Generation)
	}
	st, _ := env.srv.settings()
	if st.LastCommit != 2 {
		t.Errorf("last commit %d", st.LastCommit)
	}

	// Revert works from the latest commit's snapshot.
	env.create("/api/rules", map[string]any{"instance_id": shop.ID, "chain": "input", "action": "accept", "enabled": true})
	if rec := env.do("POST", "/api/deploy/revert", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("revert: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("GET", "/api/deploy/changes", nil); !strings.Contains(rec.Body.String(), `"changed":false`) {
		t.Errorf("changes after revert: %s", rec.Body)
	}
}

func TestFirewallsFailedApplyRollsBack(t *testing.T) {
	env, agents, branch := twoFirewalls(t)
	agents[branch].fail = true
	rec := env.do("POST", "/api/deploy/apply", map[string]any{})
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "firewall branch") {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	if agents[1].rolledBack != 1 || len(agents[1].confirmed) != 0 {
		t.Errorf("first firewall: rolled back %d, confirmed %v", agents[1].rolledBack, agents[1].confirmed)
	}
	var deps []models.Deployment
	env.srv.db.Order("firewall_id").Find(&deps)
	if len(deps) != 2 || deps[0].Status != "rolled_back" || deps[1].Status != "failed" {
		t.Errorf("deployments: %+v", deps)
	}
	// Nothing runs from that commit, so there is nothing to revert to.
	if rec := env.do("POST", "/api/deploy/revert", map[string]any{}); rec.Code != http.StatusConflict {
		t.Errorf("revert: %d %s", rec.Code, rec.Body)
	}
}

func TestFirewallsPendingConfirm(t *testing.T) {
	env, agents, branch := twoFirewalls(t)
	env.do("PUT", "/api/settings", map[string]any{"confirm_timeout": 60})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"pending"`) {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	// The status shows the commit as pending; another commit waits.
	if rec := env.do("GET", "/api/agent/status", nil); !strings.Contains(rec.Body.String(), `"pending":{"generation":1`) {
		t.Errorf("status: %s", rec.Body)
	}
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusConflict {
		t.Errorf("second commit: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/deploy/confirm", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body)
	}
	if len(agents[1].confirmed) != 1 || len(agents[branch].confirmed) != 1 {
		t.Errorf("confirmed: %v %v", agents[1].confirmed, agents[branch].confirmed)
	}
}

func TestFirewallsRules(t *testing.T) {
	env, _, branch := twoFirewalls(t)
	var guest, shop models.Instance
	env.srv.db.Where("name = ?", "guest").First(&guest)
	env.srv.db.Where("name = ?", "shop").First(&shop)

	// A link stays on one firewall.
	if rec := env.do("POST", "/api/links", map[string]any{"name": "l1", "instance_a_id": guest.ID, "instance_b_id": shop.ID,
		"interface_a": "to-shop", "interface_b": "to-guest"}); rec.Code != http.StatusBadRequest {
		t.Errorf("link across firewalls: %d %s", rec.Code, rec.Body)
	}
	// A firewall's name can't be a virtual firewall's, and one with
	// virtual firewalls besides its host stays.
	if rec := env.do("POST", "/api/firewalls", map[string]any{"name": "guest"}); rec.Code != http.StatusBadRequest {
		t.Errorf("firewall named like a virtual firewall: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/firewalls/"+itoa(branch), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete with a virtual firewall: %d %s", rec.Code, rec.Body)
	}
	// The host never moves; another virtual firewall may.
	var host models.Instance
	env.srv.db.Where("name = ?", "branch").First(&host)
	if rec := env.do("PUT", "/api/instances/"+itoa(host.ID), map[string]any{"firewall_id": 1}); rec.Code != http.StatusBadRequest {
		t.Errorf("host moved: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/instances/"+itoa(shop.ID), map[string]any{"firewall_id": 1}); rec.Code != http.StatusOK {
		t.Errorf("move: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/firewalls/"+itoa(branch), nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete: %d %s", rec.Code, rec.Body)
	}
	var n int64
	env.srv.db.Model(&models.Instance{}).Where("name = ?", "branch").Count(&n)
	if n != 0 {
		t.Error("the deleted firewall's host stayed")
	}
	if rec := env.do("DELETE", "/api/firewalls/1", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete the only firewall: %d %s", rec.Code, rec.Body)
	}
}

func TestFirewallsLiveData(t *testing.T) {
	env, agents, branch := twoFirewalls(t)
	agents[1].vrrp, agents[branch].vrrp = "guest", "shop"
	agents[1].log, agents[branch].log = "first log", "branch log"
	rec := env.do("GET", "/api/agent/vrrp", nil)
	if !strings.Contains(rec.Body.String(), `"guest"`) || !strings.Contains(rec.Body.String(), `"shop"`) {
		t.Errorf("vrrp of both firewalls: %s", rec.Body)
	}
	if rec := env.do("GET", "/api/agent/logs", nil); !strings.Contains(rec.Body.String(), "first log") {
		t.Errorf("logs: %s", rec.Body)
	}
	if rec := env.do("GET", "/api/agent/logs?firewall_id="+itoa(branch), nil); !strings.Contains(rec.Body.String(), "branch log") {
		t.Errorf("branch logs: %s", rec.Body)
	}
}

func TestFirewallsHAPair(t *testing.T) {
	env, agents, _ := twoFirewalls(t)
	var main models.Instance
	env.srv.db.Where("name = ?", "main").First(&main)
	env.create("/api/interfaces", map[string]any{"instance_id": main.ID, "name": "lan", "kind": "bridge", "enabled": true,
		"ipv4_mode": "static", "addresses": []string{"10.0.0.1/24"}})
	env.create("/api/vrrp/routers", map[string]any{"instance_id": main.ID, "interface": "lan", "vrid": 10, "enabled": true, "ipv4": []string{"10.0.0.254"}})
	fp := strings.Repeat("ab", 32)
	env.do("PUT", "/api/firewalls/1", map[string]any{"name": "firewall", "agent_url": "https://127.0.0.1:8443", "ha_url": "https://192.0.2.1:8443", "agent_fingerprint": fp})
	pair := env.create("/api/firewalls", map[string]any{"name": "fw1b", "ha_primary_id": 1, "agent_url": "https://192.0.2.3:8443", "agent_fingerprint": fp})
	agents[pair] = &fleetAgent{}
	var n int64
	env.srv.db.Model(&models.Instance{}).Where("firewall_id = ?", pair).Count(&n)
	if n != 0 {
		t.Errorf("the secondary has %d instances of its own", n)
	}
	if rec := env.do("POST", "/api/firewalls", map[string]any{"name": "fw1c", "ha_primary_id": 1}); rec.Code != http.StatusBadRequest {
		t.Errorf("second secondary: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/instances", map[string]any{"name": "onsec", "firewall_id": pair}); rec.Code != http.StatusBadRequest {
		t.Errorf("instance on the secondary: %d %s", rec.Code, rec.Body)
	}

	// Without the secondary's own address there is nothing to commit.
	rec := env.do("POST", "/api/deploy/apply", map[string]any{})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "fw1b: main: interface lan") {
		t.Fatalf("commit without peer addresses: %d %s", rec.Code, rec.Body)
	}
	var lan models.Interface
	env.srv.db.Where("name = ?", "lan").First(&lan)
	if rec := env.do("PUT", "/api/interfaces/"+itoa(lan.ID), map[string]any{"peer_addresses": []string{"10.0.0.2/24"}}); rec.Code != http.StatusOK {
		t.Fatalf("peer addresses: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	prim, sec := agents[1].last(), agents[pair].last()
	if sec == nil || !slices.Equal(instanceNames(sec), instanceNames(prim)) {
		t.Fatalf("the secondary runs %v, the primary %v", instanceNames(sec), instanceNames(prim))
	}
	in := sec.Instance("main")
	if a := in.Interfaces[slices.IndexFunc(in.Interfaces, func(i fwconfig.Interface) bool { return i.Name == "lan" })].Addresses; !slices.Equal(a, []string{"10.0.0.2/24"}) {
		t.Errorf("secondary's lan: %v", a)
	}
	if p := in.VRRP[0].Priority; p != 90 {
		t.Errorf("secondary's VRRP priority %d, want 90", p)
	}
	// Each knows its peer by the URL the peer is reached at, and the pair's
	// secret, which history never shows.
	if prim.HA == nil || sec.HA == nil || prim.HA.Node != "primary" || sec.HA.Node != "secondary" ||
		prim.HA.Peer != "https://192.0.2.3:8443" || sec.HA.Peer != "https://192.0.2.1:8443" || prim.HA.Secret != sec.HA.Secret || len(prim.HA.Secret) < 32 {
		t.Errorf("HA blocks: %+v %+v", prim.HA, sec.HA)
	}
	// Connections sync over lan, each host to the other.
	if c, d := prim.Instance("main").ConntrackSync, in.ConntrackSync; c == nil || d == nil ||
		*c != (fwconfig.ConntrackSync{Interface: "lan", This: "10.0.0.1", Peer: "10.0.0.2"}) ||
		*d != (fwconfig.ConntrackSync{Interface: "lan", This: "10.0.0.2", Peer: "10.0.0.1"}) {
		t.Errorf("conntrack sync: %+v %+v", c, d)
	}
	var dep models.Deployment
	env.srv.db.Where("firewall_id = ?", pair).Order("id desc").First(&dep)
	if strings.Contains(dep.Document, prim.HA.Secret) {
		t.Error("the pair's secret is in the deployment history")
	}
	if rec := env.do("DELETE", "/api/firewalls/1", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete the primary: %d %s", rec.Code, rec.Body)
	}
}

// haPair makes the first firewall the primary of a reachable secondary
// "fw1b" with addresses of its own; the branch stays out of it.
func haPair(t *testing.T) (*testEnv, map[uint]*fleetAgent, uint) {
	t.Helper()
	env, agents, branch := twoFirewalls(t)
	env.do("DELETE", "/api/instances/"+itoa(instanceID(t, env, "shop")), nil)
	env.do("DELETE", "/api/firewalls/"+itoa(branch), nil)
	delete(agents, branch)
	fp := strings.Repeat("ab", 32)
	env.do("PUT", "/api/firewalls/1", map[string]any{"name": "firewall", "agent_url": "https://192.0.2.1:8443", "agent_fingerprint": fp})
	pair := env.create("/api/firewalls", map[string]any{"name": "fw1b", "ha_primary_id": 1, "agent_url": "https://192.0.2.3:8443", "agent_fingerprint": fp})
	agents[pair] = &fleetAgent{}
	return env, agents, pair
}

func instanceID(t *testing.T, env *testEnv, name string) uint {
	t.Helper()
	var in models.Instance
	if err := env.srv.db.Where("name = ?", name).First(&in).Error; err != nil {
		t.Fatal(err)
	}
	return in.ID
}

func TestFirewallsHADegradedCommit(t *testing.T) {
	env, agents, pair := haPair(t)
	agents[pair].down = true
	rec := env.do("POST", "/api/deploy/apply", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("commit with the secondary down: %d %s", rec.Code, rec.Body)
	}
	var dep models.Deployment
	env.srv.db.Where("firewall_id = ?", pair).Order("id desc").First(&dep)
	if dep.Status != "skipped" || len(agents[1].applied) != 1 {
		t.Fatalf("secondary %s, primary applied %d", dep.Status, len(agents[1].applied))
	}
	// Back, it catches up with that commit.
	agents[pair].down = false
	var fw models.Firewall
	env.srv.db.First(&fw, pair)
	env.srv.catchUp(context.Background(), fw)
	env.srv.db.First(&dep, dep.ID)
	if dep.Status != "applied" || len(agents[pair].applied) != 1 || agents[pair].last().Generation != dep.Generation {
		t.Errorf("after catching up: %s, applied %d", dep.Status, len(agents[pair].applied))
	}
	// Both down: no commit.
	agents[1].down, agents[pair].down = true, true
	env.create("/api/rules", map[string]any{"instance_id": instanceID(t, env, "main"), "chain": "input", "action": "drop", "enabled": true})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code == http.StatusOK {
		t.Errorf("commit with both down: %d %s", rec.Code, rec.Body)
	}
}

func TestWitness(t *testing.T) {
	env, agents, pair := haPair(t)
	s := env.srv
	s.witness = &witness{started: time.Now().Add(-time.Minute), holder: map[uint]uint{}, until: map[uint]time.Time{}}
	var p, q models.Firewall
	s.db.First(&p, 1)
	s.db.First(&q, pair)
	ctx := context.Background()

	// Both answer: the primary gets the vote, and keeps it.
	s.witnessPair(ctx, p, q)
	s.witnessPair(ctx, p, q)
	if agents[1].votes != 2 || agents[pair].votes != 0 {
		t.Fatalf("votes %d %d", agents[1].votes, agents[pair].votes)
	}
	// The primary gone: its vote may still count, so the secondary waits.
	agents[1].down = true
	s.witnessPair(ctx, p, q)
	if agents[pair].votes != 0 {
		t.Fatal("the vote moved while the holder's still counted")
	}
	// Once it has run out, the vote moves.
	s.witness.until[p.ID] = time.Now().Add(-time.Second)
	s.witnessPair(ctx, p, q)
	if agents[pair].votes != 1 || s.witness.holder[p.ID] != pair {
		t.Fatalf("vote did not move: %d, holder %d", agents[pair].votes, s.witness.holder[p.ID])
	}
	// The primary back: the secondary keeps the vote, no flapping.
	agents[1].down = false
	s.witnessPair(ctx, p, q)
	if agents[pair].votes != 2 || agents[1].votes != 2 {
		t.Errorf("after the primary came back: %d %d", agents[1].votes, agents[pair].votes)
	}
}
