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
	"github.com/abundo/portitor/internal/confview"
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

func (f *fleetAgent) Neighbours(context.Context) (*agentapi.NeighboursResponse, error) {
	if f.down {
		return nil, errDown
	}
	return &agentapi.NeighboursResponse{}, nil
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

// twoFirewalls sets up the firewall with virtual firewalls "guest" and
// "shop", and its agent. Since 1.1.0 a configuration is one firewall's (and
// its HA secondary's), so the second firewall of before is gone: the id it
// returns is 0.
func twoFirewalls(t *testing.T) (*testEnv, map[uint]*fleetAgent, uint) {
	t.Helper()
	return twoFirewallsIn(t, "")
}

// twoFirewallsIn is twoFirewalls with the configuration's files in dir.
func twoFirewallsIn(t *testing.T, dir string) (*testEnv, map[uint]*fleetAgent, uint) {
	t.Helper()
	env := newEnvIn(t, dir)
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	env.do("PUT", "/api/settings", map[string]any{"virtual_firewalls": true, "confirm_timeout": 0})
	agents := map[uint]*fleetAgent{1: {}}
	env.srv.newAgent = func(f *models.Firewall) (agentAPI, error) { return agents[f.ID], nil }
	env.vf("guest")
	env.vf("shop")
	return env, agents, 0
}

// A commit deploys both hosts of an HA pair, the configuration's two
// firewalls, and confirms them together.
func TestFirewallsDeploy(t *testing.T) {
	env, agents, pair := haPair(t)

	// The host is the default instance, on the primary; the token never
	// comes back.
	if host := rows(env, func(v *confview.View) []models.Instance { return v.Instances }, func(in *models.Instance) bool { return in.IsDefault }); len(host) != 1 || host[0].Name != "main" || host[0].FirewallID != 1 {
		t.Fatalf("host: %+v", host)
	}
	if rec := env.do("GET", "/api/firewalls", nil); strings.Contains(rec.Body.String(), "secret") {
		t.Errorf("firewalls: %s", rec.Body)
	}

	rec := env.do("POST", "/api/deploy/apply", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	for _, id := range []uint{1, pair} {
		if got := instanceNames(agents[id].last()); !slices.Equal(got, []string{"guest", "main"}) {
			t.Errorf("firewall %d got %v", id, got)
		}
		if len(agents[id].confirmed) != 1 {
			t.Errorf("firewall %d confirmed %v", id, agents[id].confirmed)
		}
	}
	if rec := env.do("GET", "/api/deploy/changes", nil); !strings.Contains(rec.Body.String(), `"changed":false`) {
		t.Errorf("changes after commit: %s", rec.Body)
	}

	// A change deploys both again.
	env.post("instance=guest/rule", map[string]any{"chain": "input", "action": "drop", "enabled": true})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	if len(agents[1].applied) != 2 || len(agents[pair].applied) != 2 {
		t.Errorf("applies: primary %d, secondary %d", len(agents[1].applied), len(agents[pair].applied))
	}
	st, _ := env.srv.settings()
	if st.LastCommit != 2 {
		t.Errorf("last commit %d", st.LastCommit)
	}

	// Revert works from the latest commit's snapshot.
	env.post("instance=guest/rule", map[string]any{"chain": "input", "action": "accept", "enabled": true})
	if rec := env.do("POST", "/api/deploy/revert", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("revert: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("GET", "/api/deploy/changes", nil); !strings.Contains(rec.Body.String(), `"changed":false`) {
		t.Errorf("changes after revert: %s", rec.Body)
	}
}

func TestFirewallsFailedApplyRollsBack(t *testing.T) {
	env, agents, pair := haPair(t)
	agents[pair].fail = true
	rec := env.do("POST", "/api/deploy/apply", map[string]any{})
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "firewall fw1b") {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	if agents[1].rolledBack != 1 || len(agents[1].confirmed) != 0 {
		t.Errorf("primary: rolled back %d, confirmed %v", agents[1].rolledBack, agents[1].confirmed)
	}
	if rec := env.do("POST", "/api/deploy/revert", map[string]any{}); rec.Code != http.StatusConflict {
		t.Errorf("revert: %d %s", rec.Code, rec.Body)
	}
}

func TestFirewallsPendingConfirm(t *testing.T) {
	env, agents, pair := haPair(t)
	env.do("PUT", "/api/settings", map[string]any{"confirm_timeout": 60})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"pending"`) {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusConflict {
		t.Errorf("second commit: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/deploy/confirm", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body)
	}
	if len(agents[1].confirmed) != 1 || len(agents[pair].confirmed) != 1 {
		t.Errorf("confirmed: %v %v", agents[1].confirmed, agents[pair].confirmed)
	}
}

// The configuration is one firewall's (and its HA secondary's): another
// firewall is refused, names stay apart, the only firewall stays.
func TestFirewallsRules(t *testing.T) {
	env, _, _ := twoFirewalls(t)
	if rec := env.do("POST", "/api/firewalls", map[string]any{"name": "branch"}); rec.Code != http.StatusBadRequest {
		t.Errorf("a second firewall: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("POST", "instance", map[string]any{"name": "Shop-2", "firewall": "firewall"}); rec.Code != http.StatusBadRequest {
		t.Errorf("virtual firewall name: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("POST", "instance", map[string]any{"name": "main", "firewall": "firewall"}); rec.Code < 400 {
		t.Errorf("a virtual firewall named like the host: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/firewalls/1", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete the only firewall: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("DELETE", "instance=main", nil); rec.Code < 400 {
		t.Errorf("the host deleted: %d %s", rec.Code, rec.Body)
	}
}

func TestFirewallsLiveData(t *testing.T) {
	env, agents, pair := haPair(t)
	agents[1].log, agents[pair].log = "first log", "second log"
	if rec := env.do("GET", "/api/agent/logs", nil); !strings.Contains(rec.Body.String(), "first log") {
		t.Errorf("logs: %s", rec.Body)
	}
	if rec := env.do("GET", "/api/agent/logs?firewall_id="+itoa(pair), nil); !strings.Contains(rec.Body.String(), "second log") {
		t.Errorf("secondary's logs: %s", rec.Body)
	}
}

func TestFirewallsHAPair(t *testing.T) {
	env, agents, _ := twoFirewalls(t)
	env.put("instance=main/interface=lan", map[string]any{"kind": "bridge", "enabled": true, "ipv4-mode": "static", "addresses": []string{"10.0.0.1/24"}})
	fp := strings.Repeat("ab", 32)
	env.do("PUT", "/api/firewalls/1", map[string]any{"name": "firewall", "agent_url": "https://127.0.0.1:8443", "agent_fingerprint": fp})
	pair := env.create("/api/firewalls", map[string]any{"name": "fw1b", "ha_primary_id": 1, "agent_url": "https://192.0.2.3:8443", "agent_fingerprint": fp})
	agents[pair] = &fleetAgent{}
	if n := len(rows(env, func(v *confview.View) []models.Instance { return v.Instances }, func(in *models.Instance) bool { return in.FirewallID == uint(pair) })); n != 0 {
		t.Errorf("the secondary has %d instances of its own", n)
	}
	// A role is only for the host's own physical interface.
	if rec := env.cfg("PUT", "instance=main/interface=v0", map[string]any{"kind": "bridge", "enabled": true, "ipv4-mode": "static", "cluster-role": models.ClusterLink}); rec.Code != http.StatusBadRequest {
		t.Errorf("role on a bridge: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("PUT", "instance=main/interface=v0", map[string]any{"kind": "physical", "enabled": true, "ipv4-mode": "static", "cluster-role": fwconfig.HARoleManagement}); rec.Code != http.StatusBadRequest {
		t.Errorf("management without a gateway: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/firewalls", map[string]any{"name": "fw1c", "ha_primary_id": 1}); rec.Code != http.StatusBadRequest {
		t.Errorf("second secondary: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("POST", "instance", map[string]any{"name": "onsec", "firewall": "fw1b"}); rec.Code != http.StatusBadRequest {
		t.Errorf("instance on the secondary: %d %s", rec.Code, rec.Body)
	}

	// Without the pair's two links there is nothing to commit.
	rec := env.do("POST", "/api/deploy/apply", map[string]any{})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "with the cluster role cluster link") {
		t.Fatalf("commit without the links: %d %s", rec.Code, rec.Body)
	}
	addHALinks(t, env)
	// VRRP isn't used on a pair.
	if rec := env.cfg("POST", "instance=main/vrrp-router", map[string]any{"interface": "lan", "vrid": 10, "enabled": true, "ipv4": []string{"10.0.0.254"}}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "VRRP is not used") {
		t.Fatalf("VRRP on a pair: %d %s", rec.Code, rec.Body)
	}
	// A link's peer address is the secondary's own.
	if rec := env.cfg("PATCH", "instance=main/interface=mgmt0", map[string]any{"peer-addresses": []string{}}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "interface mgmt0: the secondary needs") {
		t.Fatalf("no peer addresses: %d %s", rec.Code, rec.Body)
	}
	// The secondary can't reach the primary's agent at 127.0.0.1.
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "loopback") {
		t.Fatalf("commit with a loopback agent URL: %d %s", rec.Code, rec.Body)
	}
	env.do("PUT", "/api/firewalls/1", map[string]any{"agent_url": "https://192.0.2.1:8443"})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	prim, sec := agents[1].last(), agents[pair].last()
	if sec == nil || !slices.Equal(instanceNames(sec), instanceNames(prim)) {
		t.Fatalf("the secondary runs %v, the primary %v", instanceNames(sec), instanceNames(prim))
	}
	in := sec.Instance("main")
	// The traffic interfaces are the same on both hosts; the two links
	// are each host's own.
	lan := func(d *fwconfig.Document) fwconfig.Interface {
		ifs := d.Instance("main").Interfaces
		return ifs[slices.IndexFunc(ifs, func(i fwconfig.Interface) bool { return i.Name == "lan" })]
	}
	if a := lan(sec).Addresses; !slices.Equal(a, []string{"10.0.0.1/24"}) {
		t.Errorf("secondary's lan: %v", a)
	}
	if a := in.HAInterface(fwconfig.HARoleManagement).Addresses; !slices.Equal(a, []string{"192.0.2.3/24"}) {
		t.Errorf("secondary's management: %v", a)
	}
	if a := prim.Instance("main").HAInterface(fwconfig.HARoleManagement).Addresses; !slices.Equal(a, []string{"192.0.2.1/24"}) {
		t.Errorf("primary's management: %v", a)
	}
	// Only a physical traffic interface gets the shared MAC address.
	if in.HAInterface(fwconfig.HARoleLink).MAC != "" || lan(sec).MAC != "" {
		t.Errorf("MAC on a link or a bridge: %+v", in.HAInterface(fwconfig.HARoleLink))
	}
	// The heartbeat's two paths.
	if prim.HA.PeerLink != "https://[fe80::2%25ha0]:8443" || sec.HA.PeerLink != "https://[fe80::1%25ha0]:8443" {
		t.Errorf("HA links: %s %s", prim.HA.PeerLink, sec.HA.PeerLink)
	}
	// Each knows its peer by the URL the peer is reached at, and the pair's
	// secret, which history never shows.
	if prim.HA == nil || sec.HA == nil || prim.HA.Node != "primary" || sec.HA.Node != "secondary" ||
		prim.HA.Peer != "https://192.0.2.3:8443" || sec.HA.Peer != "https://192.0.2.1:8443" || prim.HA.Secret != sec.HA.Secret || len(prim.HA.Secret) < 32 {
		t.Errorf("HA blocks: %+v %+v", prim.HA, sec.HA)
	}
	// Connections sync over the HA link, each host to the other.
	if c, d := prim.Instance("main").ConntrackSync, in.ConntrackSync; c == nil || d == nil ||
		*c != (fwconfig.ConntrackSync{Interface: "ha0", This: "fe80::1", Peer: "fe80::2"}) ||
		*d != (fwconfig.ConntrackSync{Interface: "ha0", This: "fe80::2", Peer: "fe80::1"}) {
		t.Errorf("conntrack sync: %+v %+v", c, d)
	}
	dep := env.deploymentOf(uint(pair))
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
	env, agents, _ := twoFirewalls(t)
	env.mustCfg("DELETE", "instance=shop", nil)
	fp := strings.Repeat("ab", 32)
	env.do("PUT", "/api/firewalls/1", map[string]any{"name": "firewall", "agent_url": "https://192.0.2.1:8443", "agent_fingerprint": fp})
	pair := env.create("/api/firewalls", map[string]any{"name": "fw1b", "ha_primary_id": 1, "agent_url": "https://192.0.2.3:8443", "agent_fingerprint": fp})
	agents[pair] = &fleetAgent{}
	addHALinks(t, env)
	return env, agents, pair
}

// addHALinks gives the first firewall the pair's two links.
func addHALinks(t *testing.T, env *testEnv) {
	t.Helper()
	env.put("instance=main/interface=ha0", map[string]any{"kind": "physical", "enabled": true, "ipv4-mode": "static",
		"cluster-role": models.ClusterLink})
	env.put("instance=main/interface=mgmt0", map[string]any{"kind": "physical", "enabled": true, "ipv4-mode": "static",
		"addresses": []string{"192.0.2.1/24"}, "peer-addresses": []string{"192.0.2.3/24"}, "cluster-role": fwconfig.HARoleManagement, "cluster-gateway": "192.0.2.254"})
}

func instanceID(t *testing.T, env *testEnv, name string) uint {
	t.Helper()
	return env.instanceRow(name).ID
}

// TestFirewallsHAPeerGateway: "peer" as the management gateway is each
// host's the other's management address.
func TestFirewallsHAPeerGateway(t *testing.T) {
	env, agents, pair := haPair(t)
	env.mustCfg("PATCH", "instance=main/interface=mgmt0", map[string]any{"cluster-gateway": fwconfig.HAGatewayPeer})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	for _, c := range []struct {
		id uint
		gw string
	}{{1, "192.0.2.3"}, {pair, "192.0.2.1"}} {
		m := agents[c.id].last().Instance("main").HAInterface(fwconfig.HARoleManagement)
		if m.HAGateway != c.gw || !m.HAGatewayPeer {
			t.Errorf("firewall %d: gateway %q peer %v, want %s", c.id, m.HAGateway, m.HAGatewayPeer, c.gw)
		}
	}
}

func TestFirewallsHADegradedCommit(t *testing.T) {
	env, agents, pair := haPair(t)
	agents[pair].down = true
	rec := env.do("POST", "/api/deploy/apply", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("commit with the secondary down: %d %s", rec.Code, rec.Body)
	}
	dep := env.deploymentOf(uint(pair))
	if dep.Status != "skipped" || len(agents[1].applied) != 1 {
		t.Fatalf("secondary %s, primary applied %d", dep.Status, len(agents[1].applied))
	}
	// Back, it catches up with that commit.
	agents[pair].down = false
	fw := env.firewall(pair)
	env.srv.catchUp(context.Background(), fw)
	dep = env.deploymentOf(dep.FirewallID)
	if dep.Status != "applied" || len(agents[pair].applied) != 1 || agents[pair].last().Generation != dep.Generation {
		t.Errorf("after catching up: %s, applied %d", dep.Status, len(agents[pair].applied))
	}
	// Both down: no commit.
	agents[1].down, agents[pair].down = true, true
	env.post("instance=main/rule", map[string]any{"chain": "input", "action": "drop", "enabled": true})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code == http.StatusOK {
		t.Errorf("commit with both down: %d %s", rec.Code, rec.Body)
	}
}

func TestWitness(t *testing.T) {
	env, agents, pair := haPair(t)
	s := env.srv
	s.witness = &witness{started: time.Now().Add(-time.Minute), pairs: map[string]*pairVote{}}
	var p, q models.Firewall
	p, q = firewallOf(t, s, 1), firewallOf(t, s, pair)
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
	// Run out, but not the grace for a request still in flight.
	pv := s.witness.pairs["firewall 1"]
	pv.until = time.Now().Add(-witnessGrace / 2)
	s.witnessPair(ctx, p, q)
	if agents[pair].votes != 0 {
		t.Fatal("the vote moved within the grace")
	}
	// Past that, the vote moves.
	pv.until = time.Now().Add(-2 * witnessGrace)
	s.witnessPair(ctx, p, q)
	if agents[pair].votes != 1 || pv.holder != 1 {
		t.Fatalf("vote did not move: %d, holder %d", agents[pair].votes, pv.holder)
	}
	// The primary back: the secondary keeps the vote, no flapping.
	agents[1].down = false
	s.witnessPair(ctx, p, q)
	if agents[pair].votes != 2 || agents[1].votes != 2 {
		t.Errorf("after the primary came back: %d %d", agents[1].votes, agents[pair].votes)
	}
}

// stateHost reports a state, and counts votes.
type stateHost struct {
	st    agentapi.HAStatus
	down  bool
	votes int
}

func (h *stateHost) HA(context.Context) (*agentapi.HAStatus, error) {
	if h.down {
		return nil, errDown
	}
	st := h.st
	return &st, nil
}

func (h *stateHost) HAVote(context.Context, int) (*agentapi.HAStatus, error) {
	h.votes++
	return &h.st, nil
}

// The vote follows the host that reports active.
func TestWitnessFollowsActive(t *testing.T) {
	ctx := context.Background()
	old := time.Now().Add(-time.Minute)
	// A witness that restarts doesn't give the primary the vote while the
	// secondary is active.
	a, b := &stateHost{st: agentapi.HAStatus{State: agentapi.HAStandby}}, &stateHost{st: agentapi.HAStatus{State: agentapi.HAActive}}
	w := &witness{started: old, pairs: map[string]*pairVote{}}
	w.vote(ctx, "pair", [2]haHost{a, b})
	if a.votes != 0 || b.votes != 1 {
		t.Errorf("after a restart: %d %d", a.votes, b.votes)
	}
	// Nor while it can't see that the primary holds none.
	until := time.Now().Add(time.Second)
	a, b = &stateHost{st: agentapi.HAStatus{State: agentapi.HAStandby, VoteUntil: &until}}, &stateHost{st: agentapi.HAStatus{State: agentapi.HAActive}}
	w = &witness{started: old, pairs: map[string]*pairVote{}}
	w.vote(ctx, "pair", [2]haHost{a, b})
	if a.votes != 0 || b.votes != 0 {
		t.Errorf("a vote that still counts moved: %d %d", a.votes, b.votes)
	}
	// Just restarted, with a host it can't ask, which may hold a vote.
	a, b = &stateHost{down: true}, &stateHost{st: agentapi.HAStatus{State: agentapi.HAStandby}}
	w = newWitnessState()
	w.vote(ctx, "pair", [2]haHost{a, b})
	if b.votes != 0 {
		t.Errorf("voted within a vote's length of starting: %d", b.votes)
	}
	// A vote that has run out moves to the active host.
	a, b = &stateHost{st: agentapi.HAStatus{State: agentapi.HAStandby}}, &stateHost{st: agentapi.HAStatus{State: agentapi.HAActive}}
	w = &witness{started: old, pairs: map[string]*pairVote{"pair": {holder: 0, until: time.Now().Add(-2 * witnessGrace)}}}
	w.vote(ctx, "pair", [2]haHost{a, b})
	if b.votes != 1 || w.pairs["pair"].holder != 1 {
		t.Errorf("didn't follow: %d, holder %d", b.votes, w.pairs["pair"].holder)
	}
	// A handover took the vote along: the host that gave it up may be gone,
	// so the active host's is renewed at once.
	a, b = &stateHost{down: true}, &stateHost{st: agentapi.HAStatus{State: agentapi.HAActive, VoteUntil: &until}}
	w = &witness{started: old, pairs: map[string]*pairVote{"pair": {holder: 0, until: time.Now().Add(3 * time.Second)}}}
	w.vote(ctx, "pair", [2]haHost{a, b})
	if b.votes != 1 || w.pairs["pair"].holder != 1 {
		t.Errorf("after a handover: %d, holder %d", b.votes, w.pairs["pair"].holder)
	}
	// Two active: the higher term, as the other is about to close.
	sts := [2]*agentapi.HAStatus{{State: agentapi.HAActive, Term: 3}, {State: agentapi.HAActive, Term: 4}}
	if got := activeOf(sts); got != 1 {
		t.Errorf("activeOf %d", got)
	}
}

// slowHost's vote reaches it only after a delay; fail loses the answer.
type slowHost struct {
	delay    time.Duration
	fail     bool
	received time.Time
}

func (h *slowHost) HA(context.Context) (*agentapi.HAStatus, error) {
	return &agentapi.HAStatus{}, nil
}

func (h *slowHost) HAVote(context.Context, int) (*agentapi.HAStatus, error) {
	time.Sleep(h.delay)
	h.received = time.Now()
	if h.fail {
		return nil, errDown
	}
	return &agentapi.HAStatus{}, nil
}

// The witness's record of a vote may never end before the host's, which
// counts from when it got the vote, or both hosts could hold one.
func TestWitnessVoteOutlastsHosts(t *testing.T) {
	for _, tt := range []struct {
		name string
		fail bool
	}{{"answered", false}, {"answer lost", true}} {
		t.Run(tt.name, func(t *testing.T) {
			w := newWitnessState()
			host := &slowHost{delay: 20 * time.Millisecond, fail: tt.fail}
			w.vote(context.Background(), "pair", [2]haHost{host, &slowHost{}})
			pv := w.pairs["pair"]
			if pv.holder != 0 {
				t.Fatalf("holder %d", pv.holder)
			}
			hostUntil := host.received.Add(witnessVote * time.Second)
			if pv.until.Before(hostUntil) {
				t.Errorf("the witness's vote ends %s before the host's", hostUntil.Sub(pv.until))
			}
		})
	}
}

// TestFirewallUndo: a firewall's row and its entries in the candidate
// change together: a second firewall of its own is refused with nothing
// changed, and deleting an HA secondary takes its tasks along.
func TestFirewallUndo(t *testing.T) {
	env, _, pair := haPair(t)
	before, _ := env.srv.view(context.Background())
	if rec := env.do("POST", "/api/firewalls", map[string]any{"name": "two"}); rec.Code/100 == 2 {
		t.Fatalf("a second firewall: %d %s", rec.Code, rec.Body)
	}
	if env.node("firewall=two") != nil {
		t.Error("a refused firewall is in the candidate")
	}
	env.mustCfg("POST", "task", map[string]any{"name": "t2", "firewall": "fw1b", "kind": fwconfig.TaskCommand, "schedule": "0 * * * *", "command": "true"})
	if rec := env.do("DELETE", "/api/firewalls/"+itoa(pair), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	after, _ := env.srv.view(context.Background())
	if len(after.Tasks) != len(before.Tasks) || hostName(after.Tree) != "main" {
		t.Errorf("after: %d tasks (was %d), host %q", len(after.Tasks), len(before.Tasks), hostName(after.Tree))
	}
	if _, err := env.srv.rec.Firewall(pair); err == nil {
		t.Error("the deleted firewall still runs")
	}
}

// A firewall is renamed through its CRUD and keeps its id, which the
// deployments name it by: an HA secondary, and the primary, whose host keeps
// its name and whose virtual firewalls follow.
func TestFirewallRename(t *testing.T) {
	env, _, _ := twoFirewalls(t)
	fp := strings.Repeat("ab", 32)
	pair := env.create("/api/firewalls", map[string]any{"name": "fw1x", "ha_primary_id": 1, "agent_url": "https://192.0.2.3:8443", "agent_fingerprint": fp, "agent_token": "tok"})
	before := env.firewall(pair)
	if rec := env.do("PUT", "/api/firewalls/"+itoa(pair), map[string]any{"name": "fw1b", "agent_url": before.AgentURL, "agent_fingerprint": fp}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	after := env.firewall(pair)
	if after.Name != "fw1b" || after.ID != pair || after.AgentToken != "tok" || after.HAPrimaryID == nil || after.HASecret != before.HASecret {
		t.Errorf("after: %+v", after)
	}
	if env.node("firewall=fw1b") == nil || env.node("firewall=fw1x") != nil {
		t.Error("the candidate did not follow the rename")
	}
	if rec := env.do("PUT", "/api/firewalls/1", map[string]any{"name": "fw-a"}); rec.Code != http.StatusOK {
		t.Fatalf("the primary renamed: %d %s", rec.Code, rec.Body)
	}
	if g := env.node("instance=guest"); g == nil || g.Leaf("firewall") != "fw-a" || env.node("").Leaf("host-name") != "main" {
		t.Errorf("after the primary's rename: guest %v, host %v", g, env.node("").Leaves)
	}
}
