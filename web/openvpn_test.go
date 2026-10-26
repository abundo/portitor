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
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "eth0", "kind": "physical", "enabled": true, "ipv4_mode": "dhcp"})
	cert := env.create("/api/certificates", map[string]any{"instance_id": inst, "name": "vpn", "enabled": true, "source": "import",
		"generate": map[string]any{"domains": []string{"vpn.example.com"}, "key_type": "ec256", "days": 30}})
	alice := env.create("/api/users", map[string]string{"username": "alice", "password": "a long password", "role": "none"})
	env.create("/api/users", map[string]string{"username": "bob", "password": "another long password", "role": "none"})
	role := env.create("/api/roles", map[string]any{"name": "vpn", "members": []map[string]any{{"user_id": alice, "level": "viewer"}}})

	base := map[string]any{"instance_id": inst, "name": "ovpn0", "kind": "openvpn", "enabled": true, "ipv4_mode": "static",
		"addresses": []string{"10.8.0.1/24", "fd00:8::1/64"}, "ovpn_listen": "eth0", "ovpn_certificate_id": cert,
		"ovpn_role_id": role, "ovpn_routes": []string{"192.168.1.0/24"}}
	for what, change := range map[string]map[string]any{
		"small prefix":  {"addresses": []string{"10.8.0.1/30"}},
		"two v4":        {"addresses": []string{"10.8.0.1/24", "10.9.0.1/24"}},
		"listen":        {"ovpn_listen": "eth9"},
		"mode":          {"ovpn_mode": "both"},
		"route":         {"ovpn_routes": []string{"192.168.1.1/24"}},
		"dns":           {"ovpn_dns": []string{"dns.example"}},
		"dhcp":          {"ipv4_mode": "dhcp"},
		"unknown cert":  {"ovpn_certificate_id": 999},
		"unknown role":  {"ovpn_role_id": 999},
		"domain":        {"ovpn_dns_domain": "a b"},
		"listen itself": {"ovpn_listen": "ovpn0"},
	} {
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		for k, v := range change {
			body[k] = v
		}
		if rec := env.do("POST", "/api/interfaces", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	rec := env.do("POST", "/api/interfaces", base)
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), "Static key") {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var ovpn models.Interface
	_ = json.Unmarshal(rec.Body.Bytes(), &ovpn)
	if ovpn.OvpnMode != "adaptive" || ovpn.OvpnPort != 1194 || !ovpn.OvpnRequireRole {
		t.Errorf("defaults: %+v", ovpn)
	}
	second := map[string]any{"instance_id": inst, "name": "ovpn1", "kind": "openvpn", "enabled": true, "addresses": []string{"10.9.0.1/24"}}
	if rec := env.do("POST", "/api/interfaces", second); rec.Code != http.StatusBadRequest {
		t.Errorf("second server: %d %s", rec.Code, rec.Body)
	}

	// The document: the role's members only, the certificate by name.
	doc, err := builder.Build(env.srv.db, 1)
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
	b, _ := json.Marshal(redactDoc(*doc))
	if strings.Contains(string(b), "Static key") || strings.Contains(string(b), hashes["alice"]) {
		t.Error("redacted document holds secrets")
	}
	// Without the role, every user with a password.
	path := fmt.Sprintf("/api/interfaces/%d", ovpn.ID)
	if rec := env.do("PUT", path, map[string]any{"ovpn_role_id": nil}); rec.Code != http.StatusOK {
		t.Fatalf("no role: %d %s", rec.Code, rec.Body)
	}
	doc, _ = builder.Build(env.srv.db, 1)
	for _, u := range doc.Instance("main").Interface("ovpn0").OpenVPN.Users {
		if u.Denied || u.Hash == "" {
			t.Errorf("without a role: %+v", u)
		}
	}
	env.do("PUT", path, map[string]any{"ovpn_role_id": role})

	// References: the role, the certificate and the listen interface.
	if rec := env.do("DELETE", fmt.Sprintf("/api/roles/%d", role), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete role in use: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", fmt.Sprintf("/api/certificates/%d", cert), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete certificate in use: %d %s", rec.Code, rec.Body)
	}
	var eth0 models.Interface
	env.srv.db.Where("name = ?", "eth0").First(&eth0)
	if rec := env.do("PUT", fmt.Sprintf("/api/interfaces/%d", eth0.ID), map[string]any{"name": "wan0"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&ovpn, ovpn.ID)
	if ovpn.OvpnListen != "wan0" {
		t.Errorf("listen after rename: %q", ovpn.OvpnListen)
	}
	if rec := env.do("DELETE", fmt.Sprintf("/api/interfaces/%d", eth0.ID), nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete listen interface: %d %s", rec.Code, rec.Body)
	}

	// The client config: UDP then TCP, the CA, the name and the key.
	rec = env.do("GET", path+"/openvpn-client", nil)
	var cc struct{ Config, Filename string }
	_ = json.Unmarshal(rec.Body.Bytes(), &cc)
	for _, want := range []string{"remote vpn.example.com 1194 udp\n", "remote vpn.example.com 1194 tcp-client\n",
		"verify-x509-name vpn.example.com name\n", "<ca>\n-----BEGIN CERTIFICATE-----", "<tls-crypt>\n-----BEGIN OpenVPN Static key V1-----"} {
		if !strings.Contains(cc.Config, want) {
			t.Errorf("client config: missing %q in\n%s", want, cc.Config)
		}
	}
	if strings.Index(cc.Config, " udp\n") > strings.Index(cc.Config, " tcp-client\n") || cc.Filename != "main-ovpn0.ovpn" {
		t.Errorf("client config order or name %q", cc.Filename)
	}
}

// An instance admin's OpenVPN lets in their virtual firewall's role's
// members, not every user of the firewall.
func TestOpenVPNTenant(t *testing.T) {
	env := newEnv(t)
	env.create("/api/instances", map[string]any{"name": "main"})
	a := env.create("/api/instances", map[string]any{"name": "a"})
	tina := env.create("/api/users", map[string]string{"username": "tina", "password": "a long password", "role": "none"})
	other := env.create("/api/roles", map[string]any{"name": "other"})
	roleA := env.roles()["vf-a"].ID
	if rec := env.do("PUT", fmt.Sprintf("/api/roles/%d", roleA), map[string]any{
		"members": []map[string]any{{"user_id": tina, "level": "admin"}},
	}); rec.Code != http.StatusOK {
		t.Fatalf("role: %d %s", rec.Code, rec.Body)
	}
	env.login("tina", "a long password")
	rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": a, "name": "ovpn0", "kind": "openvpn", "enabled": true,
		"addresses": []string{"10.8.0.1/24"}, "ovpn_role_id": other})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var ifc models.Interface
	_ = json.Unmarshal(rec.Body.Bytes(), &ifc)
	if ifc.OvpnRoleID == nil || *ifc.OvpnRoleID != roleA || !ifc.OvpnRequireRole {
		t.Errorf("role %v, required %v", ifc.OvpnRoleID, ifc.OvpnRequireRole)
	}
}

// Both hosts of an HA pair have the OpenVPN server's addresses.
func TestOpenVPNHA(t *testing.T) {
	env, _, pair := haPairConfigured(t)
	main := instanceID(t, env, "main")
	cert := env.create("/api/certificates", map[string]any{"instance_id": main, "name": "vpn", "enabled": true, "source": "import",
		"generate": map[string]any{"domains": []string{"vpn.example.com"}, "key_type": "ec256", "days": 30}})
	if rec := env.do("POST", "/api/interfaces", map[string]any{"instance_id": main, "name": "ovpn0", "kind": "openvpn", "enabled": true,
		"addresses": []string{"10.8.0.1/24", "fd00:8::1/64"}, "peer_addresses": []string{"10.8.0.2/24"}, "ovpn_certificate_id": cert}); rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var ifc models.Interface
	env.srv.db.Where("name = ?", "ovpn0").First(&ifc)
	if len(ifc.PeerAddresses) != 0 {
		t.Errorf("peer addresses kept: %v", ifc.PeerAddresses)
	}
	for _, fw := range []uint{1, pair} {
		doc, err := builder.BuildFirewall(env.srv.db, 1, fw)
		if err != nil {
			t.Fatalf("firewall %d: %v", fw, err)
		}
		if got := doc.Instance("main").Interface("ovpn0").Addresses; strings.Join(got, " ") != "10.8.0.1/24 fd00:8::1/64" {
			t.Errorf("firewall %d: %v", fw, got)
		}
	}
}
