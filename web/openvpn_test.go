// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/models"
)

type openvpnAgent struct{ agentAPI }

func (openvpnAgent) OpenVPNCA(_ context.Context, instance string) (*agentapi.OpenVPNCA, error) {
	return &agentapi.OpenVPNCA{CA: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", CommonName: "vpn.example.com"}, nil
}

func TestOpenVPN(t *testing.T) {
	env := newEnv(t)
	env.srv.newAgent = func(*models.Firewall) (agentAPI, error) { return openvpnAgent{}, nil }
	env.host("main")
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "enabled": true, "ipv4-mode": "dhcp"})
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "enabled": true, "addresses": []string{"192.168.1.1/24"}})
	env.mustCfg("POST", "instance=main/certificate=vpn?action=generate", map[string]any{"domains": []string{"vpn.example.com"}, "key-type": "ec256", "days": 30})
	alice := env.create("/api/users", map[string]string{"username": "alice", "password": "a long password", "role": "none"})
	env.create("/api/users", map[string]string{"username": "bob", "password": "another long password", "role": "none"})
	role := env.create("/api/roles", map[string]any{"name": "vpn", "members": []map[string]any{{"user_id": alice, "level": "viewer"}}})

	base := map[string]any{"kind": "openvpn", "enabled": true, "ipv4-mode": "static",
		"addresses": []string{"10.8.0.1/24", "fd00:8::1/64"}, "ovpn-tcp-addresses": []string{"10.9.0.1/24", "fd00:9::1/64"},
		"ovpn-listen": "eth0", "ovpn-certificate": "vpn", "ovpn-role": "vpn", "ovpn-routes": []string{"192.168.1.0/24"}}
	for what, change := range map[string]map[string]any{
		"small prefix":  {"addresses": []string{"10.8.0.1/31"}},
		"two v4":        {"addresses": []string{"10.8.0.1/24", "10.7.0.1/24"}},
		"no tcp":        {"ovpn-tcp-addresses": []string{}},
		"tcp overlaps":  {"ovpn-tcp-addresses": []string{"10.8.0.129/25"}},
		"tcp invalid":   {"ovpn-tcp-addresses": []string{"10.9.0.0/24"}},
		"listen":        {"ovpn-listen": "eth9"},
		"mode":          {"ovpn-mode": "both"},
		"dns":           {"ovpn-dns": []string{"dns.example"}},
		"dhcp":          {"ipv4-mode": "dhcp"},
		"unknown cert":  {"ovpn-certificate": "nope"},
		"domain":        {"ovpn-dns-domain": "a b"},
		"listen itself": {"ovpn-listen": "ovpn0"},
		"two-factor":    {"ovpn-two-factor": "sms"},
	} {
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		for k, v := range change {
			body[k] = v
		}
		if rec := env.cfg("PUT", "instance=main/interface=ovpn0", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	env.put("instance=main/interface=ovpn0", base)
	if rec := env.do("GET", "/api/config/candidate/instance=main/interface=ovpn0", nil); strings.Contains(rec.Body.String(), "Static key") {
		t.Errorf("the tls-crypt key read back: %s", rec.Body)
	}
	if o := env.node("instance=main/interface=ovpn0"); o.Leaf("ovpn-mode") != "adaptive" || o.Leaf("ovpn-port") != "1194" || !on(o, "ovpn-require-role") {
		t.Errorf("defaults: %+v", o.Leaves)
	}
	if rec := env.cfg("PUT", "instance=main/interface=ovpn1", map[string]any{"kind": "openvpn", "enabled": true, "addresses": []string{"10.10.0.1/24"}, "ovpn-mode": "udp"}); rec.Code != http.StatusBadRequest {
		t.Errorf("second server: %d %s", rec.Code, rec.Body)
	}

	// The document: the role's members only, the certificate by name.
	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	o := doc.Instance("main").Interface("ovpn0").OpenVPN
	hashes := map[string]string{}
	for _, u := range o.Users {
		hashes[u.Name] = u.Hash
		if u.Name != "alice" && !u.Denied {
			t.Errorf("%s not denied", u.Name)
		}
	}
	if o == nil || o.Certificate != "vpn" || o.Listen != "eth0" || !o.RequireRole || !strings.HasPrefix(hashes["alice"], "$2") ||
		hashes["bob"] != "" || !strings.Contains(o.TLSCrypt, "Static key") || doc.Directory == nil {
		t.Fatalf("openvpn %+v", o)
	}
	if got := strings.Join(o.TCPAddresses, " "); got != "10.9.0.1/24 fd00:9::1/64" {
		t.Errorf("tcp addresses %s", got)
	}
	b, _ := json.Marshal(doc.Redacted())
	if strings.Contains(string(b), "Static key") || strings.Contains(string(b), hashes["alice"]) {
		t.Error("redacted document holds secrets")
	}
	// Without the role, every user with a password.
	env.patch("instance=main/interface=ovpn0", map[string]any{"ovpn-role": nil})
	doc, _ = builder.Build(env.input(), 1)
	for _, u := range doc.Instance("main").Interface("ovpn0").OpenVPN.Users {
		if u.Denied || u.Hash == "" {
			t.Errorf("without a role: %+v", u)
		}
	}
	env.patch("instance=main/interface=ovpn0", map[string]any{"ovpn-role": "vpn"})

	// References: the role, the certificate and the listen interface.
	if rec := env.do("DELETE", fmt.Sprintf("/api/roles/%d", role), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete role in use: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("DELETE", "instance=main/certificate=vpn", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete certificate in use: %d %s", rec.Code, rec.Body)
	}
	env.mustCfg("POST", "instance=main/interface=eth0?action=rename", map[string]any{"keys": []string{"wan0"}})
	if got := env.node("instance=main/interface=ovpn0").Leaf("ovpn-listen"); got != "wan0" {
		t.Errorf("listen after rename: %q", got)
	}
	if rec := env.cfg("DELETE", "instance=main/interface=wan0", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete listen interface: %d %s", rec.Code, rec.Body)
	}

	// The client config: UDP then TCP, the CA, the name and the key.
	client := func() string {
		rec := env.do("GET", "/api/config/candidate/instance=main/interface=ovpn0?action=openvpn-client", nil)
		var cc struct{ Config, Filename string }
		_ = json.Unmarshal(rec.Body.Bytes(), &cc)
		if cc.Filename != "main-ovpn0.ovpn" {
			t.Errorf("client config name %q (%s)", cc.Filename, rec.Body)
		}
		return cc.Config
	}
	conf := client()
	for _, want := range []string{"remote vpn.example.com 1194 udp\n", "remote vpn.example.com 1194 tcp-client\n",
		"verify-x509-name vpn.example.com name\n", "<ca>\n-----BEGIN CERTIFICATE-----", "<tls-crypt>\n-----BEGIN OpenVPN Static key V1-----"} {
		if !strings.Contains(conf, want) {
			t.Errorf("client config: missing %q in\n%s", want, conf)
		}
	}
	if strings.Index(conf, " udp\n") > strings.Index(conf, " tcp-client\n") {
		t.Error("client config order")
	}
	if strings.Contains(conf, "static-challenge") {
		t.Error("static-challenge without two-factor login")
	}

	// Two-factor login: alice's TOTP secret in the document (not in its
	// redacted copy), and the client asks for the code.
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	env.srv.db.Model(&models.User{}).Where("id = ?", alice).Update("totp_secret", secret)
	totps := func() map[string]string {
		doc, _ = builder.Build(env.input(), 1)
		m := map[string]string{}
		for _, u := range doc.Instance("main").Interface("ovpn0").OpenVPN.Users {
			m[u.Name] = u.TOTP
		}
		return m
	}
	if got := totps(); got["alice"] != "" {
		t.Errorf("TOTP without two-factor login: %v", got)
	}
	env.patch("instance=main/interface=ovpn0", map[string]any{"ovpn-two-factor": "user"})
	if got := totps(); got["alice"] != secret || got["bob"] != "" {
		t.Errorf("TOTP secrets %v", got)
	}
	if o = doc.Instance("main").Interface("ovpn0").OpenVPN; o.TwoFactor != "user" {
		t.Errorf("two-factor %q", o.TwoFactor)
	}
	if err := doc.Validate(); err != nil {
		t.Error(err)
	}
	if b, _ := json.Marshal(doc.Redacted()); strings.Contains(string(b), secret) {
		t.Error("redacted document holds the TOTP secret")
	}
	if !strings.Contains(client(), "auth-user-pass\nauth-nocache\nstatic-challenge \"Authenticator code\" 1\n") {
		t.Error("client config without static-challenge")
	}
}

// An instance admin's OpenVPN lets in their virtual firewall's role's
// members, not every user of the firewall.
func TestOpenVPNTenant(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.vf("a")
	tina := env.create("/api/users", map[string]string{"username": "tina", "password": "a long password", "role": "none"})
	env.create("/api/roles", map[string]any{"name": "other"})
	roleA := env.roles()["vf-a"].ID
	if rec := env.do("PUT", fmt.Sprintf("/api/roles/%d", roleA), map[string]any{
		"members": []map[string]any{{"user_id": tina, "level": "admin"}},
	}); rec.Code != http.StatusOK {
		t.Fatalf("role: %d %s", rec.Code, rec.Body)
	}
	env.login("tina", "a long password")
	server := map[string]any{"kind": "openvpn", "enabled": true, "addresses": []string{"10.8.0.1/24"}, "ovpn-mode": "udp", "ovpn-role": "other"}
	if rec := env.cfg("PUT", "instance=a/interface=ovpn0", server); rec.Code != http.StatusBadRequest {
		t.Errorf("another role: %d %s", rec.Code, rec.Body)
	}
	server["ovpn-role"] = "vf-a"
	env.put("instance=a/interface=ovpn0", server)
	if o := env.node("instance=a/interface=ovpn0"); !on(o, "ovpn-require-role") {
		t.Errorf("role not required: %v", o.Leaves)
	}
}

// Both hosts of an HA pair have the OpenVPN server's addresses.
func TestOpenVPNHA(t *testing.T) {
	env, _, pair := haPairConfigured(t)
	env.mustCfg("POST", "instance=main/certificate=vpn?action=generate", map[string]any{"domains": []string{"vpn.example.com"}, "key-type": "ec256", "days": 30})
	env.put("instance=main/interface=ovpn0", map[string]any{"kind": "openvpn", "enabled": true,
		"addresses": []string{"10.8.0.1/24", "fd00:8::1/64"}, "peer-addresses": []string{"10.8.0.2/24"},
		"ovpn-tcp-addresses": []string{"10.9.0.1/24"}, "ovpn-certificate": "vpn"})
	if got := env.node("instance=main/interface=ovpn0").LeafLists["peer-addresses"]; len(got) != 0 {
		t.Errorf("peer addresses kept: %v", got)
	}
	for _, fw := range []uint{1, pair} {
		doc, err := builder.BuildFirewall(env.input(), 1, fw)
		if err != nil {
			t.Fatalf("firewall %d: %v", fw, err)
		}
		if got := doc.Instance("main").Interface("ovpn0").Addresses; strings.Join(got, " ") != "10.8.0.1/24 fd00:8::1/64" {
			t.Errorf("firewall %d: %v", fw, got)
		}
	}
}
