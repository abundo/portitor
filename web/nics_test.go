// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
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
	var main models.Instance
	env.srv.db.First(&main)
	lan := env.create("/api/instances", map[string]any{"name": "lan"})
	env.create("/api/interfaces", map[string]any{"instance_id": lan, "name": "eth9", "enabled": true})
	env.create("/api/interfaces", map[string]any{"instance_id": lan, "name": "eth3", "enabled": true})
	env.create("/api/ipam/prefixes", map[string]any{"instance_id": main.ID, "prefix": "10.0.0.0/8"})

	fake := &statusAgent{nics: []agentapi.NICStatus{
		{Name: "eth0", Up: true, DHCPv4: true, SLAAC: true, Addresses: []string{}},
		{Name: "eth1", Up: false, Addresses: []string{"10.1.2.1/24", "2001:db8::1/64"}},
		{Name: "eth3", Netns: "fw-lan", Up: true, Addresses: []string{}},
		{Name: "eth4", Netns: "fw-lan", Up: true, Addresses: []string{}},
	}}
	env.srv.newAgent = func(*models.Settings) (agentAPI, error) { return fake, nil }
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
	if len(got.Imported) != 2 || got.Imported[0] != "eth0" || got.Imported[1] != "eth1" || len(got.Problems) != 0 {
		t.Fatalf("first sync: %+v", got)
	}
	if len(got.Missing) != 1 || got.Missing[0] != (missingNIC{Instance: "lan", Name: "eth9"}) {
		t.Errorf("missing: %+v", got.Missing)
	}
	var ifaces []models.Interface
	env.srv.db.Where("instance_id = ?", main.ID).Order("name").Find(&ifaces)
	if len(ifaces) != 2 {
		t.Fatalf("interfaces: %+v", ifaces)
	}
	if e := ifaces[0]; !e.Enabled || e.Ipv4Mode != "none" || !e.Ipv6AcceptRA || e.Kind != "physical" {
		t.Errorf("eth0: %+v", e)
	}
	if e := ifaces[1]; e.Enabled || e.Ipv4Mode != "static" || e.Ipv6AcceptRA {
		t.Errorf("eth1: %+v", e)
	}
	var prefixes []models.IpamPrefix
	env.srv.db.Where("instance_id = ?", main.ID).Order("prefix").Find(&prefixes)
	if len(prefixes) != 3 || prefixes[0].Prefix != "10.0.0.0/8" || prefixes[1].Prefix != "10.1.2.0/24" || prefixes[2].Prefix != "2001:db8::/64" {
		t.Errorf("prefixes: %+v", prefixes)
	}
	var addrs []models.IpamAddress
	env.srv.db.Where("interface_id = ?", ifaces[1].ID).Order("address").Find(&addrs)
	if len(addrs) != 2 || addrs[0].Address != "10.1.2.1" || addrs[1].Address != "2001:db8::1" {
		t.Errorf("addresses: %+v", addrs)
	}

	// A deleted interface is not imported again; a new one is.
	env.do("DELETE", "/api/interfaces/"+itoa(ifaces[0].ID), nil)
	fake.nics = append(fake.nics, agentapi.NICStatus{Name: "eth5", Addresses: []string{}})
	got = status()
	if len(got.Imported) != 1 || got.Imported[0] != "eth5" {
		t.Errorf("second sync: %+v", got)
	}
	if got = status(); len(got.Imported) != 0 {
		t.Errorf("third sync: %+v", got)
	}
}
