// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/confview"
	"github.com/abundo/portitor/internal/render"
	"github.com/abundo/portitor/models"
)

// statusAgent answers Status with a fixed list of NICs and anti-lockout rule.
type statusAgent struct {
	agentAPI
	nics        []agentapi.NICStatus
	antiLockout *render.AntiLockout
}

func (f *statusAgent) Status(context.Context) (*agentapi.Status, error) {
	return &agentapi.Status{NICs: f.nics, AntiLockout: f.antiLockout}, nil
}

func TestSyncNICs(t *testing.T) {
	env := newEnv(t)
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	main := env.instanceRow("")
	env.vf("lan")
	env.post("instance=lan/interface", map[string]any{"kind": "physical", "name": "eth9", "enabled": true})
	env.post("instance=lan/interface", map[string]any{"kind": "physical", "name": "eth3", "enabled": true})
	env.post("instance=main/ipam-prefix", map[string]any{"prefix": "10.0.0.0/8"})

	fake := &statusAgent{nics: []agentapi.NICStatus{
		{Name: "eth0", Up: true, DHCPv4: true, SLAAC: true, Addresses: []string{}},
		{Name: "eth1", Up: false, Addresses: []string{"10.1.2.1/24", "2001:db8::1/64", "10.1.3.0/24"}},
		{Name: "eth3", Netns: "fw-lan", Up: true, Addresses: []string{}},
		{Name: "eth4", Netns: "fw-lan", Up: true, Addresses: []string{}},
	}}
	env.srv.newAgent = func(*models.Firewall) (agentAPI, error) { return fake, nil }
	status := func() nicSync {
		t.Helper()
		rec := env.do("GET", "/api/agent/status", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("status: %d %s", rec.Code, rec.Body)
		}
		var out struct {
			NICSync nicSync `json:"nic_sync"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.NICSync
	}

	got := status()
	if len(got.Imported) != 2 || got.Imported[0] != "eth0" || got.Imported[1] != "eth1" ||
		len(got.Problems) != 1 || !strings.Contains(got.Problems[0], "10.1.3.0/24 not added") {
		t.Fatalf("first sync: %+v", got)
	}
	if len(got.Missing) != 1 || got.Missing[0] != (missingNIC{Instance: "lan", Name: "eth9"}) {
		t.Errorf("missing: %+v", got.Missing)
	}
	ifaces := confview.Of(env.view().Interfaces, main.ID)
	slices.SortFunc(ifaces, func(a, b models.Interface) int { return strings.Compare(a.Name, b.Name) })
	if len(ifaces) != 2 {
		t.Fatalf("interfaces: %+v", ifaces)
	}
	if e := ifaces[0]; !e.Enabled || e.Ipv4Mode != "none" || !e.Ipv6AcceptRA || e.Kind != "physical" {
		t.Errorf("eth0: %+v", e)
	}
	if e := ifaces[1]; e.Enabled || e.Ipv4Mode != "static" || e.Ipv6AcceptRA {
		t.Errorf("eth1: %+v", e)
	}
	// The addresses go on the interface; IPAM is left alone.
	if got := strings.Join(ifaces[1].Addresses, " "); got != "10.1.2.1/24 2001:db8::1/64" {
		t.Errorf("eth1 addresses: %s", got)
	}
	prefixes, addrs := len(env.view().IpamPrefixes), len(env.view().IpamAddresses)
	if prefixes != 1 || addrs != 0 {
		t.Errorf("IPAM: %d prefixes, %d addresses", prefixes, addrs)
	}

	// A deleted interface is not imported again; a new one is.
	env.mustCfg("DELETE", "instance=main/interface="+ifaces[0].Name, nil)
	fake.nics = append(fake.nics, agentapi.NICStatus{Name: "eth5", Addresses: []string{}})
	got = status()
	if len(got.Imported) != 1 || got.Imported[0] != "eth5" {
		t.Errorf("second sync: %+v", got)
	}
	if got = status(); len(got.Imported) != 0 {
		t.Errorf("third sync: %+v", got)
	}
}

// hostAgent answers Status with a hostname and the host's figures.
type hostAgent struct{ agentAPI }

func (hostAgent) Status(context.Context) (*agentapi.Status, error) {
	return &agentapi.Status{Hostname: "fw1", NICs: []agentapi.NICStatus{},
		Host: &agentapi.HostStatus{MemTotal: 4096, CPUs: 2, Load: [3]float64{0.5, 0.25, 0.1},
			Disks: []agentapi.DiskStatus{{Mount: "/", Total: 100, Free: 40, Used: 60}}}}, nil
}

// The merged status leaves out the host; the state's system/host is the
// first firewall's.
func TestStateSystemHost(t *testing.T) {
	env := newEnv(t)
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	env.srv.newAgent = func(*models.Firewall) (agentAPI, error) { return hostAgent{}, nil }
	rec := env.do("GET", "/api/config/state/system/host", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("state: %d %s", rec.Code, rec.Body)
	}
	for _, want := range []string{`"mem-total":"4096"`, `"cpus":2`, `"mount":"/"`, `"0.25"`} {
		if !strings.Contains(strings.ReplaceAll(rec.Body.String(), " ", ""), want) {
			t.Errorf("no %s in %s", want, rec.Body)
		}
	}
}
