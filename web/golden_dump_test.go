// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

var pemBlock = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----[^"]*?-----END [A-Z0-9 ]+-----\\n?`)

// dumpApplied writes every document the fake agents were applied, redacted
// and with generated key material blanked, to GOLDEN_OUT/<name>.json.
func dumpApplied(t *testing.T, name string, agents map[uint]*fleetAgent) {
	out := os.Getenv("GOLDEN_OUT")
	if out == "" {
		t.Skip("GOLDEN_OUT not set")
	}
	ids := make([]int, 0, len(agents))
	for id := range agents {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	all := map[string][]fwconfig.Document{}
	for _, id := range ids {
		var docs []fwconfig.Document
		for _, d := range agents[uint(id)].applied {
			docs = append(docs, d.Redacted())
		}
		all[string(rune('a'+id))] = docs
	}
	b, err := json.MarshalIndent(all, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	b = pemBlock.ReplaceAll(b, []byte("PEM"))
	if err := os.WriteFile(filepath.Join(out, name+".json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestGoldenOpenVPNDirectory(t *testing.T) {
	env, agents, _ := twoFirewalls(t)
	env.put("instance=main/interface=eth0", map[string]any{"kind": "physical", "enabled": true, "ipv4-mode": "dhcp"})
	env.put("instance=main/interface=eth1", map[string]any{"kind": "physical", "enabled": true, "addresses": []string{"192.168.1.1/24"}})
	env.mustCfg("POST", "instance=main/certificate=vpn?action=generate", map[string]any{"domains": []string{"vpn.example.com"}, "key-type": "ec256", "days": 30})
	alice := env.create("/api/users", map[string]string{"username": "alice", "password": "a long password", "role": "none"})
	env.create("/api/users", map[string]string{"username": "bob", "password": "another long password", "role": "none"})
	role := env.create("/api/roles", map[string]any{"name": "vpn", "members": []map[string]any{{"user_id": alice, "level": "viewer"}}})
	env.create("/api/directory/servers", map[string]any{"name": "ad", "enabled": true, "server_type": "ad", "host": "dc1.example.com",
		"tls_mode": "ldaps", "bind_dn": "CN=svc,DC=example,DC=com", "new_bind_password": "bindpw", "base_dn": "dc=example,dc=com"})
	env.create("/api/directory/mappings", map[string]any{"group_dn": "CN=VPN,OU=Groups,DC=example,DC=com", "role_id": role, "level": "viewer"})
	env.put("instance=main/interface=ovpn0", map[string]any{"kind": "openvpn", "enabled": true, "ipv4-mode": "static",
		"addresses": []string{"10.8.0.1/24", "fd00:8::1/64"}, "ovpn-tcp-addresses": []string{"10.9.0.1/24", "fd00:9::1/64"},
		"ovpn-listen": "eth0", "ovpn-certificate": "vpn", "ovpn-role": "vpn", "ovpn-routes": []string{"192.168.1.0/24"}})
	env.post("instance=main/rule", map[string]any{"chain": "input", "action": "accept", "enabled": true})
	env.post("instance=shop/rule", map[string]any{"chain": "input", "action": "drop", "enabled": true})
	// Fixed hashes, so nothing is random.
	for _, name := range []string{"alice", "bob"} {
		u := env.userNamed(name)
		u.PasswordHash = "$2a$10$" + strings.Repeat("a", 53)
		if err := env.srv.rec.SaveUser(&u, false); err != nil {
			t.Fatal(err)
		}
	}
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	env.post("instance=main/rule", map[string]any{"chain": "forward", "action": "drop", "enabled": true})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("second commit: %d %s", rec.Code, rec.Body)
	}
	dumpApplied(t, "openvpn", agents)
}

func TestGoldenHAPair(t *testing.T) {
	env, agents, _ := haPairConfigured(t)
	env.post("instance=main/rule", map[string]any{"chain": "input", "action": "drop", "enabled": true})
	env.setFirewall("fw1b", map[string]any{"ha-secret": strings.Repeat("P", 43)})
	env.setFirewall("firewall", map[string]any{"ha-witness-secret": strings.Repeat("W", 43)})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	dumpApplied(t, "hapair", agents)
}
