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
		func(o *BootstrapOptions) { o.WAN = "enp2s0" },
		func(o *BootstrapOptions) { o.WAN = "enp1s0" }, // DHCP with a gateway
		func(o *BootstrapOptions) { o.WANAddress = netip.MustParsePrefix("198.51.100.2/24") },
		func(o *BootstrapOptions) {
			o.WAN, o.WANAddress = "enp1s0", netip.MustParsePrefix("192.168.1.2/25")
		},
		func(o *BootstrapOptions) { // the gateway must be on the static WAN
			o.WAN, o.WANAddress = "enp1s0", netip.MustParsePrefix("198.51.100.2/24")
		},
		func(o *BootstrapOptions) { o.Address = netip.Prefix{} }, // DHCP with a gateway
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

func TestBootstrapWAN(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wanAddr string
		gateway string
		mode    string
		addrs   []string
		routes  int
	}{
		{"dhcp", "", "", fwconfig.ModeDHCP, nil, 0},
		{"static", "198.51.100.2/24", "198.51.100.1", fwconfig.ModeStatic, []string{"198.51.100.2/24"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnv(t)
			fake := &applyAgent{statusAgent: statusAgent{nics: []agentapi.NICStatus{
				{Name: "enp1s0", Addresses: []string{}},
				{Name: "enp2s0", Addresses: []string{}},
			}}}
			env.srv.newAgent = func(*models.Settings) (agentAPI, error) { return fake, nil }
			o := BootstrapOptions{
				AgentURL: "https://127.0.0.1:8443", AgentToken: strings.Repeat("t", 43), AgentFingerprint: strings.Repeat("ab", 32),
				LAN: "enp2s0", Address: netip.MustParsePrefix("192.168.1.1/24"), WAN: "enp1s0", GUIPort: 443,
			}
			if tc.wanAddr != "" {
				o.WANAddress = netip.MustParsePrefix(tc.wanAddr)
			}
			if tc.gateway != "" {
				o.Gateway = netip.MustParseAddr(tc.gateway)
			}
			if _, err := Bootstrap(context.Background(), env.srv, o); err != nil {
				t.Fatal(err)
			}
			in := fake.applied.Instances[0]
			var wan *fwconfig.Interface
			for i := range in.Interfaces {
				if in.Interfaces[i].Name == "enp1s0" {
					wan = &in.Interfaces[i]
				}
			}
			if wan == nil || !wan.Enabled || wan.IPv4Mode != tc.mode || !slices.Equal(wan.Addresses, tc.addrs) {
				t.Errorf("WAN interface %+v", wan)
			}
			if len(in.Routes) != tc.routes || (tc.routes == 1 && in.Routes[0].Gateway != tc.gateway) {
				t.Errorf("routes %+v", in.Routes)
			}
		})
	}
}

func TestBootstrapReconfigure(t *testing.T) {
	env := newEnv(t)
	fake := &applyAgent{statusAgent: statusAgent{nics: []agentapi.NICStatus{
		{Name: "enp1s0", Addresses: []string{}},
		{Name: "enp2s0", Addresses: []string{}},
	}}}
	env.srv.newAgent = func(*models.Settings) (agentAPI, error) { return fake, nil }
	o := BootstrapOptions{
		AgentURL: "https://127.0.0.1:8443", AgentToken: strings.Repeat("t", 43), AgentFingerprint: strings.Repeat("ab", 32),
		LAN: "enp2s0", Address: netip.MustParsePrefix("192.168.1.1/24"), WAN: "enp1s0", GUIPort: 443,
	}
	if _, err := Bootstrap(context.Background(), env.srv, o); err != nil {
		t.Fatal(err)
	}
	iface := func(name string) *fwconfig.Interface {
		in := fake.applied.Instances[0]
		for i := range in.Interfaces {
			if in.Interfaces[i].Name == name {
				return &in.Interfaces[i]
			}
		}
		t.Fatalf("no interface %s", name)
		return nil
	}

	// LAN and WAN swapped, the WAN static; the agent settings are kept.
	r := BootstrapOptions{
		LAN: "enp1s0", Address: netip.MustParsePrefix("192.168.1.1/24"),
		WAN: "enp2s0", WANAddress: netip.MustParsePrefix("198.51.100.2/24"), Gateway: netip.MustParseAddr("198.51.100.1"),
		GUIPort: 443,
	}
	if _, err := Bootstrap(context.Background(), env.srv, r); err == nil {
		t.Fatal("accepted without the agent fingerprint and Reconfigure")
	}
	r.Reconfigure = true
	if _, err := Bootstrap(context.Background(), env.srv, r); err != nil {
		t.Fatal(err)
	}
	if st, _ := env.srv.settings(); st.AgentFingerprint != strings.Repeat("ab", 32) {
		t.Errorf("agent settings changed: %+v", st)
	}
	if lan := iface("enp1s0"); lan.IPv4Mode != fwconfig.ModeStatic || !slices.Equal(lan.Addresses, []string{"192.168.1.1/24"}) {
		t.Errorf("LAN %+v", lan)
	}
	if wan := iface("enp2s0"); wan.IPv4Mode != fwconfig.ModeStatic || !slices.Equal(wan.Addresses, []string{"198.51.100.2/24"}) {
		t.Errorf("WAN %+v", wan)
	}
	in := fake.applied.Instances[0]
	if len(in.Routes) != 1 || in.Routes[0].Gateway != "198.51.100.1" {
		t.Errorf("routes %+v", in.Routes)
	}
	var rules int
	for _, r := range in.Rules {
		if r.Chain == fwconfig.ChainInput {
			rules++
			if !slices.Equal(r.InInterfaces, []string{"enp1s0"}) {
				t.Errorf("rule %+v", r)
			}
		}
	}
	if rules != 2 {
		t.Errorf("%d input rules: %+v", rules, in.Rules)
	}

	// Back to a DHCP WAN: no default route, no WAN address.
	r.WANAddress, r.Gateway = netip.Prefix{}, netip.Addr{}
	if _, err := Bootstrap(context.Background(), env.srv, r); err != nil {
		t.Fatal(err)
	}
	if wan := iface("enp2s0"); wan.IPv4Mode != fwconfig.ModeDHCP || len(wan.Addresses) != 0 {
		t.Errorf("WAN %+v", wan)
	}
	if routes := fake.applied.Instances[0].Routes; len(routes) != 0 {
		t.Errorf("routes %+v", routes)
	}
}

func TestBootstrapLANDHCP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wan     string
		noRoute bool
	}{
		{"with WAN", "enp1s0", true},
		{"without WAN", "", false}, // the LAN lease brings the default route
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnv(t)
			fake := &applyAgent{statusAgent: statusAgent{nics: []agentapi.NICStatus{
				{Name: "enp1s0", Addresses: []string{}},
				{Name: "enp2s0", Addresses: []string{"192.168.1.5/24"}},
			}}}
			env.srv.newAgent = func(*models.Settings) (agentAPI, error) { return fake, nil }
			o := BootstrapOptions{
				AgentURL: "https://127.0.0.1:8443", AgentToken: strings.Repeat("t", 43), AgentFingerprint: strings.Repeat("ab", 32),
				LAN: "enp2s0", WAN: tc.wan, GUIPort: 443,
			}
			if _, err := Bootstrap(context.Background(), env.srv, o); err != nil {
				t.Fatal(err)
			}
			in := fake.applied.Instances[0]
			for _, ifc := range in.Interfaces {
				switch ifc.Name {
				case "enp2s0":
					// The imported static address is unassigned.
					if ifc.IPv4Mode != fwconfig.ModeDHCP || len(ifc.Addresses) != 0 || ifc.DHCPNoDefaultRoute != tc.noRoute {
						t.Errorf("LAN %+v", ifc)
					}
				case "enp1s0":
					if tc.wan != "" && (ifc.IPv4Mode != fwconfig.ModeDHCP || ifc.DHCPNoDefaultRoute) {
						t.Errorf("WAN %+v", ifc)
					}
				}
			}
			if len(in.Routes) != 0 {
				t.Errorf("routes %+v", in.Routes)
			}
		})
	}
}
