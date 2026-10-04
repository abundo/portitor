// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

// The fixtures are FRR 10.3's answers for the sample document's guest
// instance, with no session up.
func TestParseBGPNeighbors(t *testing.T) {
	data, err := os.ReadFile("testdata/frr-bgp-neighbors.json")
	if err != nil {
		t.Fatal(err)
	}
	peers, err := parseBGPNeighbors(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 3 {
		t.Fatalf("got %d peers: %+v", len(peers), peers)
	}
	p := peers[0]
	if p.Address != "10.255.0.1" || p.RemoteAS != 65000 || p.LocalAS != 65010 || p.State != "Active" || p.Description != "changed" {
		t.Errorf("first peer: %+v", p)
	}
	shut := peers[slices.IndexFunc(peers, func(p agentapi.BGPPeerInfo) bool { return p.Address == "2001:db8::1" })]
	if shut.State != "Idle (Admin)" {
		t.Errorf("shut down peer: %+v", shut)
	}
	if _, err := parseBGPNeighbors([]byte("% BGP instance not found")); err == nil {
		t.Error("vtysh's complaint parsed")
	}
}

func TestParseBGPNeighborEstablished(t *testing.T) {
	peers, err := parseBGPNeighbors([]byte(`{"192.0.2.1":{"remoteAs":65001,"localAs":65000,"bgpState":"Established",
		"bgpTimerUpMsec":3723000,"bgpTimerUpString":"01:02:03","messageStats":{"totalSent":10,"totalRecv":12},
		"addressFamilyInfo":{"ipv4Unicast":{"acceptedPrefixCounter":5,"sentPrefixCounter":2},"l2VpnEvpn":{}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	p := peers[0]
	if p.Uptime != "01:02:03" || p.UptimeSecs != 3723 || p.MsgRcvd != 12 || p.MsgSent != 10 {
		t.Errorf("peer: %+v", p)
	}
	if f := p.Families["ipv4"]; f.PrefixesReceived != 5 || f.PrefixesSent != 2 || len(p.Families) != 1 {
		t.Errorf("families: %+v", p.Families)
	}
}

func TestParseBGPSummaryAndRoutes(t *testing.T) {
	data, err := os.ReadFile("testdata/frr-bgp-summary.json")
	if err != nil {
		t.Fatal(err)
	}
	if s := parseBGPSummary(data); s.RouterID != "10.255.0.2" || s.AS != 65010 || s.RIBCount != 2 {
		t.Errorf("summary: %+v", s)
	}
	// Keyed by address family, as some FRR versions answer.
	if s := parseBGPSummary([]byte(`{"ipv4Unicast":{"routerId":"192.0.2.9","as":64512,"ribCount":3}}`)); s.RouterID != "192.0.2.9" || s.RIBCount != 3 {
		t.Errorf("keyed summary: %+v", s)
	}
	data, err = os.ReadFile("testdata/frr-bgp-routes.json")
	if err != nil {
		t.Fatal(err)
	}
	routes := parseBGPRoutes(data, "ipv4")
	if len(routes) != 1 || routes[0].Prefix != "192.168.50.0/24" || routes[0].NextHop != "0.0.0.0" || routes[0].Weight != 32768 {
		t.Errorf("routes: %+v", routes)
	}
	routes = parseBGPRoutes([]byte(`{"routes":{"2001:db8::/32":[
		{"valid":true,"path":"65001","nexthops":[{"ip":"fe80::1","scope":"link-local"},{"ip":"2001:db8::1","scope":"global"}]},
		{"valid":true,"bestpath":true,"path":"65002 65003","nexthops":[{"ip":"2001:db8::2","scope":"global"}]}]}}`), "ipv6")
	if len(routes) != 2 || !routes[0].Best || routes[0].NextHop != "2001:db8::2" || routes[1].NextHop != "2001:db8::1" {
		t.Errorf("ipv6 routes, best first, global next hops: %+v", routes)
	}
}

func TestBGPInstance(t *testing.T) {
	// A big table is left out.
	bi := bgpInstance("guest", func(cmd string) ([]byte, error) {
		switch {
		case cmd == "show bgp neighbors json":
			return []byte(`{}`), nil
		case strings.HasSuffix(cmd, "summary json"):
			return []byte(`{"routerId":"192.0.2.1","as":65000,"ribCount":900000}`), nil
		}
		t.Errorf("asked %q", cmd)
		return nil, errors.New("no")
	})
	if !bi.RoutesTruncated || bi.ASN != 65000 || bi.Error != "" || bi.Peers == nil || bi.Routes == nil {
		t.Errorf("%+v", bi)
	}
	// FRR not running: vtysh's complaint is the error.
	bi = bgpInstance("guest", func(string) ([]byte, error) {
		return []byte("Exiting: failed to connect to any daemons.\n"), errors.New("exit status 1")
	})
	if bi.Error != "Exiting: failed to connect to any daemons." {
		t.Errorf("error %q", bi.Error)
	}
}

// vtyshRunner answers vtysh and records the commands.
type vtyshRunner struct {
	Runner
	calls  [][]string
	active map[string]bool // units systemctl is-active reports active
	// failReload fails systemctl reload.
	failReload bool
}

func (r *vtyshRunner) RunInput(ctx context.Context, netns string, stdin []byte, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	switch {
	case name == "vtysh":
		return []byte(`{}`), nil
	case name == "systemctl" && len(args) == 2 && args[0] == "reload" && r.failReload:
		return nil, errors.New("exit status 1")
	case name == "systemctl" && len(args) == 2 && args[0] == "is-active":
		if r.active[args[1]] {
			return []byte("active\n"), nil
		}
		return []byte("inactive\n"), errors.New("exit status 3")
	}
	return r.Runner.RunInput(ctx, netns, stdin, name, args...)
}

func (r *vtyshRunner) Run(ctx context.Context, netns, name string, args ...string) ([]byte, error) {
	return r.RunInput(ctx, netns, nil, name, args...)
}

func (r *vtyshRunner) ran(args ...string) bool {
	return slices.ContainsFunc(r.calls, func(c []string) bool { return slices.Equal(c, args) })
}

// A virtual firewall's FRR is asked through its pathspace, the default
// instance's directly.
func TestAgentBGP(t *testing.T) {
	a, _ := testAgent(t)
	r := &vtyshRunner{Runner: a.bg}
	a.bg = r
	doc := fwconfig.SampleDocument()
	doc.Instance("main").BGP = &fwconfig.BGP{Enabled: true, ASN: 65000}
	a.applied = &doc
	resp := a.BGP(context.Background())
	if len(resp.Instances) != 2 || resp.Instances[0].Instance != "main" || resp.Instances[1].Instance != "guest" {
		t.Fatalf("%+v", resp)
	}
	if !r.ran("vtysh", "-c", "show bgp neighbors json") || !r.ran("vtysh", "-N", "guest", "-c", "show bgp neighbors json") {
		t.Errorf("calls %v", r.calls)
	}
}

// FRR starts when BGP is turned on, a changed daemons file restarts it, a
// changed frr.conf reloads it, and it stops when BGP and OSPF are turned
// off.
func TestApplyFRR(t *testing.T) {
	a, _ := testAgent(t)
	r := &vtyshRunner{Runner: a.run, active: map[string]bool{}}
	a.run = r
	ctx := context.Background()
	doc := fwconfig.SampleDocument()
	in := doc.Instance("guest")
	files := a.cfg.Paths.Files(in)
	unit := "portitor-frr@guest.service"

	if err := a.applyFRR(ctx, in, map[string]bool{files.FRRConf: true, files.FRRDaemons: true}); err != nil {
		t.Fatal(err)
	}
	if !r.ran("systemctl", "enable", "--now", unit) || r.ran("systemctl", "restart", unit) {
		t.Errorf("start: %v", r.calls)
	}

	r.calls, r.active[unit] = nil, true
	if err := a.applyFRR(ctx, in, map[string]bool{files.FRRConf: true}); err != nil {
		t.Fatal(err)
	}
	if !r.ran("systemctl", "reload", unit) || r.ran("systemctl", "restart", unit) {
		t.Errorf("reload: %v", r.calls)
	}

	// A reload that fails (no frr-reload.py) restarts it.
	r.calls, r.failReload = nil, true
	if err := a.applyFRR(ctx, in, map[string]bool{files.FRRConf: true}); err != nil {
		t.Fatal(err)
	}
	if !r.ran("systemctl", "restart", unit) {
		t.Errorf("restart after a failed reload: %v", r.calls)
	}
	r.failReload = false

	r.calls = nil
	if err := a.applyFRR(ctx, in, map[string]bool{files.FRRDaemons: true, files.FRRConf: true}); err != nil {
		t.Fatal(err)
	}
	if !r.ran("systemctl", "restart", unit) {
		t.Errorf("restart: %v", r.calls)
	}

	r.calls = nil
	if err := a.applyFRR(ctx, in, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if r.ran("systemctl", "reload", unit) || r.ran("systemctl", "restart", unit) {
		t.Errorf("unchanged: %v", r.calls)
	}

	// OSPF alone keeps it running.
	r.calls = nil
	in.BGP.Enabled = false
	if err := a.applyFRR(ctx, in, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if r.ran("systemctl", "disable", "--now", unit) {
		t.Errorf("stopped with OSPF on: %v", r.calls)
	}

	// VRRP alone keeps it running too.
	r.calls = nil
	in.OSPF.Enabled, in.OSPF6.Enabled = false, false
	if err := a.applyFRR(ctx, in, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if r.ran("systemctl", "disable", "--now", unit) {
		t.Errorf("stopped with VRRP on: %v", r.calls)
	}

	r.calls = nil
	in.VRRP = nil
	if err := a.applyFRR(ctx, in, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if !r.ran("systemctl", "disable", "--now", unit) {
		t.Errorf("stop: %v", r.calls)
	}

	// Its frr.conf, with the passwords, goes; someone else's stays.
	a.cfg.DryRun = false
	writeTestFile(t, files.FRRConf, "! Generated by portitor-agent, instance guest.\n")
	if err := a.applyFRR(ctx, in, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(files.FRRConf); err == nil {
		t.Error("stale frr.conf kept")
	}
	writeTestFile(t, files.FRRConf, "! the admin's own\n")
	if err := a.applyFRR(ctx, in, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(files.FRRConf); err != nil {
		t.Error("someone else's frr.conf removed")
	}
}

// A neighbour's routes: advertised and, with soft reconfiguration, received
// and filtered; without it, the accepted routes. A neighbour FRR does not
// have is refused before any route command.
func TestBGPNeighborRoutes(t *testing.T) {
	neighbors := `{"192.0.2.1":{"remoteAs":65001,"bgpState":"Established",
		"addressFamilyInfo":{"ipv4Unicast":{"acceptedPrefixCounter":1,"sentPrefixCounter":1}}}}`
	adv := `{"advertisedRoutes":{"198.51.100.0/24":{"network":"198.51.100.0/24","nextHop":"0.0.0.0","weight":32768,"path":"","origin":"IGP"}},"totalPrefixCounter":1}`
	rcvd := `{"receivedRoutes":{"203.0.113.0/24":{"nextHop":"192.0.2.1","metric":0,"path":"65001","origin":"IGP"},"10.0.0.0/8":{"nextHop":"192.0.2.1","path":"65001"}}}`
	filt := `{"receivedRoutes":{"10.0.0.0/8":{"nextHop":"192.0.2.1","path":"65001"}}}`
	accepted := `{"routes":{"203.0.113.0/24":[{"valid":true,"bestpath":true,"path":"65001","nexthops":[{"ip":"192.0.2.1"}]}]}}`
	soft := true
	var calls []string
	vtysh := func(cmd string) ([]byte, error) {
		calls = append(calls, cmd)
		p := "show bgp ipv4 unicast neighbors 192.0.2.1 "
		switch cmd {
		case "show bgp neighbors json":
			return []byte(neighbors), nil
		case p + "advertised-routes json":
			return []byte(adv), nil
		case p + "received-routes json":
			if !soft {
				return []byte(`{"warning":"Inbound soft reconfiguration not enabled"}`), nil
			}
			return []byte(rcvd), nil
		case p + "filtered-routes json":
			return []byte(filt), nil
		case p + "routes json":
			return []byte(accepted), nil
		}
		return nil, errors.New("unexpected " + cmd)
	}
	res, err := bgpNeighborRoutes(vtysh, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Advertised) != 1 || res.Advertised[0].Prefix != "198.51.100.0/24" ||
		len(res.Received) != 2 || res.Received[0].Prefix != "10.0.0.0/8" ||
		len(res.Filtered) != 1 || res.ReceivedAccepted || len(res.Notes) != 0 {
		t.Errorf("%+v", res)
	}
	soft = false
	res, err = bgpNeighborRoutes(vtysh, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if !res.ReceivedAccepted || len(res.Received) != 1 || res.Received[0].NextHop != "192.0.2.1" || len(res.Filtered) != 0 {
		t.Errorf("%+v", res)
	}
	calls = nil
	if _, err := bgpNeighborRoutes(vtysh, "192.0.2.1 json; x"); err == nil || len(calls) != 1 {
		t.Errorf("unknown neighbour: %v, calls %v", err, calls)
	}
}

func TestBGPNeighborDetail(t *testing.T) {
	neighbors := `{"192.0.2.1":{"remoteAs":65001,"bgpState":"Established"},
		"2001:db8::1":{"remoteAs":65002,"bgpState":"Active"}}`
	var calls []string
	vtysh := func(cmd string) ([]byte, error) {
		calls = append(calls, cmd)
		switch cmd {
		case "show bgp neighbors json":
			return []byte(neighbors), nil
		case "show bgp neighbors 192.0.2.1 json":
			return []byte(`{"192.0.2.1":{"remoteAs":65001,"bgpState":"Established","hostname":"r1"}}`), nil
		case "show bgp neighbors 2001:db8::1 json":
			return []byte(`{"2001:db8::1":{"remoteAs":65002,"bgpState":"Active"}}`), nil
		}
		return nil, errors.New("unexpected " + cmd)
	}
	for _, n := range []string{"192.0.2.1", "2001:db8::1"} {
		res, err := bgpNeighborDetail(vtysh, n)
		if err != nil {
			t.Fatal(err)
		}
		if res.Neighbor != n || !strings.Contains(string(res.Detail), `"remoteAs"`) {
			t.Errorf("%s: %+v", n, res)
		}
	}
	calls = nil
	if _, err := bgpNeighborDetail(vtysh, "192.0.2.1 json; x"); err == nil || len(calls) != 1 {
		t.Errorf("unknown neighbour: %v, calls %v", err, calls)
	}
}
