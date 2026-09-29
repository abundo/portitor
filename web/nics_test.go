// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
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
		{Name: "eth1", Up: false, Addresses: []string{"10.1.2.1/24", "2001:db8::1/64", "10.1.3.0/24"}},
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
	if len(got.Imported) != 2 || got.Imported[0] != "eth0" || got.Imported[1] != "eth1" ||
		len(got.Problems) != 1 || !strings.Contains(got.Problems[0], "10.1.3.0/24 not added") {
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
	// The addresses go on the interface; IPAM is left alone.
	if got := strings.Join(ifaces[1].Addresses, " "); got != "10.1.2.1/24 2001:db8::1/64" {
		t.Errorf("eth1 addresses: %s", got)
	}
	var prefixes, addrs int64
	env.srv.db.Model(&models.IpamPrefix{}).Count(&prefixes)
	env.srv.db.Model(&models.IpamAddress{}).Count(&addrs)
	if prefixes != 1 || addrs != 0 {
		t.Errorf("IPAM: %d prefixes, %d addresses", prefixes, addrs)
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
