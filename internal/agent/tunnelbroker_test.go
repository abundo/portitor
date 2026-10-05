// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

func TestPlanCreate6in4(t *testing.T) {
	tun := &fwconfig.Tunnel6in4{Remote: "216.66.80.90"}
	want := []fwconfig.Interface{{Name: "he0", Kind: fwconfig.Kind6in4, Tunnel: tun}}
	equal(t, planCreate("", want, nil),
		"ip link add name he0 type sit remote 216.66.80.90 local any ttl 255")

	links, err := parseLinks([]byte(`[{"ifname":"he0","linkinfo":{"info_kind":"sit","info_data":{"remote":"216.66.80.90","local":"any","ttl":255}}},
		{"ifname":"sit0","linkinfo":{"info_kind":"sit","info_data":{"remote":"any","local":"any","ttl":"inherit"}}}]`))
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]ipLink{}
	for _, l := range links {
		have[l.Ifname] = l
	}
	equal(t, planCreate("", want, have)) // unchanged
	if !fallbackDevice(have["sit0"]) || fallbackDevice(have["he0"]) {
		t.Error("sit0 is the fallback device, he0 not")
	}
	// A changed endpoint makes the tunnel again.
	want[0].Tunnel = &fwconfig.Tunnel6in4{Remote: "216.66.80.90", Local: "198.51.100.7"}
	equal(t, planCreate("", want, have),
		"ip link del dev he0",
		"ip link add name he0 type sit remote 216.66.80.90 local 198.51.100.7 ttl 255")
}

func TestParseTunnelBrokerAnswer(t *testing.T) {
	for _, tc := range []struct {
		body, addr string
		perm, fail bool
	}{
		{body: "good 198.51.100.7\n", addr: "198.51.100.7"},
		{body: "nochg 198.51.100.7", addr: "198.51.100.7"},
		{body: "badauth", perm: true},
		{body: "nohost", perm: true},
		{body: "abuse", perm: true},
		{body: "-ERROR: IP is not ICMP pingable", fail: true},
		{body: "", fail: true},
	} {
		addr, err := parseTunnelBrokerAnswer(tc.body)
		var perm permanentError
		switch {
		case tc.perm && !errors.As(err, &perm):
			t.Errorf("%q: want a permanent error, got %v", tc.body, err)
		case tc.fail && (err == nil || errors.As(err, &perm)):
			t.Errorf("%q: want a passing error, got %v", tc.body, err)
		case !tc.perm && !tc.fail && (err != nil || addr != tc.addr):
			t.Errorf("%q: got %q, %v", tc.body, addr, err)
		}
	}
}

func TestTunnelMyIP(t *testing.T) {
	tun := fwconfig.Tunnel6in4{Remote: "216.66.80.90"}
	for src, want := range map[string]string{"198.51.100.7": "198.51.100.7", "192.168.1.2": "", "100.64.1.1": ""} {
		if got := tunnelMyIP(tun, netip.MustParseAddr(src)); got != want {
			t.Errorf("%s: got %q, want %q", src, got, want)
		}
	}
	tun.Local = "203.0.113.5"
	if got := tunnelMyIP(tun, netip.MustParseAddr("192.168.1.2")); got != "203.0.113.5" {
		t.Errorf("local address: got %q", got)
	}
}

func TestTunnelBrokerUpdate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, key, _ := r.BasicAuth()
		if user != "alice" || key != "k3y" {
			w.Write([]byte("badauth"))
			return
		}
		if r.URL.Query().Get("hostname") != "123456" {
			w.Write([]byte("nohost"))
			return
		}
		w.Write([]byte("good " + r.URL.Query().Get("myip")))
	}))
	defer srv.Close()
	old := TunnelBrokerURL
	TunnelBrokerURL = srv.URL + "/nic/update"
	defer func() { TunnelBrokerURL = old }()

	tb := fwconfig.TunnelBroker{TunnelID: "123456", Username: "alice", UpdateKey: "k3y"}
	addr, err := tunnelBrokerUpdate(context.Background(), "", tb, "198.51.100.7")
	if err != nil || addr != "198.51.100.7" {
		t.Fatalf("got %q, %v", addr, err)
	}
	tb.UpdateKey = "wrong"
	if _, err := tunnelBrokerUpdate(context.Background(), "", tb, ""); err == nil || !strings.Contains(err.Error(), "update key") {
		t.Fatalf("wrong key: %v", err)
	}
}
