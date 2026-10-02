// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/base64"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

func joinString(json string) string {
	return JoinPrefix + base64.RawURLEncoding.EncodeToString([]byte(json))
}

func TestParseJoin(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	good := joinString(`{"url":"https://192.168.1.1:8443","token":"tok","fingerprint":"` + fp +
		`","lan":"enp2s0","address":"192.168.1.1/24","wan":"enp1s0","wan_address":"198.51.100.2/24","gateway":"198.51.100.1",` +
		`"dhcp_range":"192.168.1.100-192.168.1.199","dhcp_dns":["1.1.1.1"]}`)
	// Wrapped by a terminal.
	o, err := ParseJoin(good[:30] + "\n  " + good[30:] + "\n")
	if err != nil {
		t.Fatal(err)
	}
	want := BootstrapOptions{AgentURL: "https://192.168.1.1:8443", AgentToken: "tok", AgentFingerprint: fp,
		LAN: "enp2s0", Address: netip.MustParsePrefix("192.168.1.1/24"), WAN: "enp1s0",
		WANAddress: netip.MustParsePrefix("198.51.100.2/24"), Gateway: netip.MustParseAddr("198.51.100.1"),
		DHCPStart: netip.MustParseAddr("192.168.1.100"), DHCPEnd: netip.MustParseAddr("192.168.1.199"),
		DHCPDNS: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	if !reflect.DeepEqual(o, want) {
		t.Errorf("got %+v", o)
	}

	for _, bad := range []string{
		"",
		strings.TrimPrefix(good, JoinPrefix),
		good[:len(good)-5],
		joinString(`{"url":"http://192.168.1.1:8443","token":"tok","fingerprint":"x","lan":"enp2s0","address":"192.168.1.1/24"}`),
		joinString(`{"url":"https://192.168.1.1:8443","fingerprint":"x","lan":"enp2s0","address":"192.168.1.1/24"}`),
		joinString(`{"url":"https://192.168.1.1:8443","token":"tok","fingerprint":"x","lan":"enp2s0","address":"dhcp"}`),
		joinString(`{"url":"https://192.168.1.1:8443","token":"tok","fingerprint":"x","lan":"enp2s0","address":"192.168.1.1/24","gateway":"x"}`),
	} {
		if _, err := ParseJoin(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// A firewall managed from another host gets no GUI rule.
func TestBootstrapNoGUIPort(t *testing.T) {
	env := newEnv(t)
	fake := &applyAgent{statusAgent: statusAgent{nics: []agentapi.NICStatus{
		{Name: "enp1s0", Addresses: []string{}},
		{Name: "enp2s0", Addresses: []string{}},
	}}}
	env.srv.newAgent = func(*models.Settings) (agentAPI, error) { return fake, nil }
	o, err := ParseJoin(joinString(`{"url":"https://192.168.1.1:8443","token":"` + strings.Repeat("t", 43) + `","fingerprint":"` +
		strings.Repeat("ab", 32) + `","lan":"enp2s0","address":"192.168.1.1/24","wan":"enp1s0"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Bootstrap(context.Background(), env.srv, o); err != nil {
		t.Fatal(err)
	}
	st, _ := env.srv.settings()
	if st.AgentURL != "https://192.168.1.1:8443" {
		t.Errorf("agent URL %q", st.AgentURL)
	}
	var n int64
	env.srv.db.Model(&models.Service{}).Where("name = ?", "portitor-web").Count(&n)
	if n != 0 {
		t.Error("a portitor-web service was created")
	}
	in := fake.applied.Instances[0]
	var input, forward int
	for _, r := range in.Rules {
		switch r.Chain {
		case fwconfig.ChainInput:
			input++
		case fwconfig.ChainForward:
			forward++
		}
	}
	if input != 2 || forward != 1 || len(in.NAT) != 1 {
		t.Errorf("rules %+v, NAT %+v", in.Rules, in.NAT)
	}
}
