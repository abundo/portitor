// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// applyAgent reports NICs and records the applied document.
type applyAgent struct {
	statusAgent
	applied *fwconfig.Document
}

func (f *applyAgent) Apply(_ context.Context, doc fwconfig.Document, _ int) (*agentapi.ApplyResult, error) {
	f.applied = &doc
	return &agentapi.ApplyResult{Generation: doc.Generation}, nil
}

func TestBootstrap(t *testing.T) {
	env := newEnv(t)
	fake := &applyAgent{statusAgent: statusAgent{nics: []agentapi.NICStatus{
		{Name: "enp1s0", Addresses: []string{}},
		{Name: "enp2s0", Addresses: []string{}},
	}}}
	env.srv.newAgent = func(*models.Settings) (agentAPI, error) { return fake, nil }
	opts := BootstrapOptions{
		AgentURL: "https://127.0.0.1:8443/", AgentToken: strings.Repeat("t", 43), AgentFingerprint: strings.Repeat("AB", 32),
		LAN: "enp2s0", Address: netip.MustParsePrefix("192.168.1.1/24"),
		Gateway: netip.MustParseAddr("192.168.1.254"), GUIPort: 443,
	}

	for _, bad := range []func(o *BootstrapOptions){
		func(o *BootstrapOptions) { o.Address = netip.MustParsePrefix("192.168.1.0/24") },
		func(o *BootstrapOptions) { o.Address = netip.MustParsePrefix("192.168.1.255/24") },
		func(o *BootstrapOptions) { o.Gateway = netip.MustParseAddr("10.0.0.1") },
		func(o *BootstrapOptions) { o.LAN = "eth0; reboot" },
	} {
		o := opts
		bad(&o)
		if _, err := Bootstrap(context.Background(), env.srv, o); err == nil {
			t.Errorf("accepted %+v", o)
		}
	}
	o := opts
	o.LAN = "enp9s0"
	if _, err := Bootstrap(context.Background(), env.srv, o); err == nil || !strings.Contains(err.Error(), "no interface enp9s0") {
		t.Errorf("unknown interface: %v", err)
	}

	dep, err := Bootstrap(context.Background(), env.srv, opts)
	if err != nil {
		t.Fatal(err)
	}
	if dep.Status != "applied" || dep.Username != "bootstrap" {
		t.Errorf("deployment %+v", dep)
	}
	st, _ := env.srv.settings()
	if st.AgentURL != "https://127.0.0.1:8443" || st.AgentFingerprint != strings.Repeat("ab", 32) || st.Generation != 1 {
		t.Errorf("settings %+v", st)
	}

	doc := fake.applied
	if doc == nil || len(doc.Instances) != 1 {
		t.Fatalf("applied %+v", doc)
	}
	in := doc.Instances[0]
	var lan *fwconfig.Interface
	for i := range in.Interfaces {
		if in.Interfaces[i].Name == "enp2s0" {
			lan = &in.Interfaces[i]
		}
	}
	if lan == nil || !lan.Enabled || !slices.Equal(lan.Addresses, []string{"192.168.1.1/24"}) {
		t.Errorf("LAN interface %+v", lan)
	}
	if len(in.Routes) != 1 || in.Routes[0].Gateway != "192.168.1.254" {
		t.Errorf("routes %+v", in.Routes)
	}
	var gui bool
	for _, r := range in.Rules {
		if r.Chain == fwconfig.ChainInput && r.Protocol == "tcp" && slices.Equal(r.InInterfaces, []string{"enp2s0"}) {
			gui = true
		}
	}
	if !gui {
		t.Errorf("no GUI rule in %+v", in.Rules)
	}

	if _, err := Bootstrap(context.Background(), env.srv, opts); err == nil {
		t.Error("a second bootstrap was accepted")
	}
}
