// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/ldapauth"
	"github.com/abundo/portitor/models"
)

// fakeDirectory stands in for the directory servers: host "down" fails,
// the others know users by name with "<name>pass" and the groups given.
type fakeDirectory map[string][]string

func (f fakeDirectory) auth(_ context.Context, cfg ldapauth.Config, user, password string) (bool, *ldapauth.UserInfo, error) {
	if cfg.Host == "down" {
		return false, nil, errors.New("dial: connection refused")
	}
	groups, ok := f[user]
	if !ok || password != user+"pass" {
		return false, nil, nil
	}
	return true, &ldapauth.UserInfo{DN: "uid=" + user + ",dc=example,dc=com", Email: user + "@example.com", DisplayName: strings.ToUpper(user), Groups: groups}, nil
}

const vpnGroup = "cn=vpn,ou=groups,dc=example,dc=com"

func withDirectory(t *testing.T, f fakeDirectory) {
	old := directoryAuth
	directoryAuth = f.auth
	t.Cleanup(func() { directoryAuth = old })
}

func TestDirectoryLogin(t *testing.T) {
	env := newEnv(t)
	dir := fakeDirectory{"dave": {"CN=VPN,OU=Groups,DC=example,DC=com"}, "erin": nil}
	withDirectory(t, dir)
	role := env.create("/api/roles", map[string]any{"name": "vpn"})
	other := env.create("/api/roles", map[string]any{"name": "other"})

	// Servers: the bind password is write-only, the order is the order
	// they were added in; a server that is down is passed over.
	const bindPW = "s3cret-bind"
	rec := env.do("POST", "/api/directory/servers", map[string]any{"name": "down", "enabled": true, "host": "down",
		"base_dn": "dc=example,dc=com"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("server: %d %s", rec.Code, rec.Body)
	}
	rec = env.do("POST", "/api/directory/servers", map[string]any{"name": "ad", "enabled": true, "server_type": "ad", "host": "dc1.example.com",
		"tls_mode": "ldaps", "bind_dn": "CN=svc,DC=example,DC=com", "new_bind_password": bindPW, "base_dn": "dc=example,dc=com"})
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), bindPW) || !strings.Contains(rec.Body.String(), `"has_bind_password":true`) {
		t.Fatalf("server: %d %s", rec.Code, rec.Body)
	}
	var ad models.LdapServer
	_ = json.Unmarshal(rec.Body.Bytes(), &ad)
	if ad.Position != 2 || ad.Port != 636 {
		t.Errorf("position %d port %d", ad.Position, ad.Port)
	}
	for what, body := range map[string]map[string]any{
		"filter":      {"name": "x", "host": "h", "base_dn": "dc=x", "user_filter": "(uid=bob)"},
		"bind no pw":  {"name": "x", "host": "h", "base_dn": "dc=x", "bind_dn": "cn=a"},
		"no base":     {"name": "x", "host": "h"},
		"tls":         {"name": "x", "host": "h", "base_dn": "dc=x", "tls_mode": "ssl"},
		"bad host":    {"name": "x", "host": "a b", "base_dn": "dc=x"},
		"duplicate":   {"name": "ad", "host": "h", "base_dn": "dc=x"},
		"server type": {"name": "x", "host": "h", "base_dn": "dc=x", "server_type": "novell"},
	} {
		if rec := env.do("POST", "/api/directory/servers", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", what, rec.Code, rec.Body)
		}
	}
	if rec := env.do("GET", "/api/directory/servers", nil); strings.Contains(rec.Body.String(), bindPW) {
		t.Error("list holds the bind password")
	}
	env.create("/api/directory/mappings", map[string]any{"group_dn": vpnGroup, "role_id": role, "level": "viewer"})
	if rec := env.do("POST", "/api/directory/mappings", map[string]any{"group_dn": strings.ToUpper(vpnGroup), "role_id": role}); rec.Code != http.StatusBadRequest {
		t.Errorf("duplicate mapping: %d", rec.Code)
	}

	// A user the firewall doesn't have: copied in, with no global role,
	// their group's role, and the server they came from.
	env.login("dave", "davepass")
	var dave models.User
	env.srv.db.Where("username = ?", "dave").First(&dave)
	if dave.PasswordHash != models.LDAPPassword || dave.LdapServer != "ad" || dave.Role != models.RoleNone || dave.FullName != "DAVE" || dave.Email != "dave@example.com" {
		t.Fatalf("dave: %+v", dave)
	}
	memberOf := func(u, r uint) bool {
		var n int64
		env.srv.db.Model(&models.RoleMember{}).Where("user_id = ? AND role_id = ?", u, r).Count(&n)
		return n > 0
	}
	if !memberOf(dave.ID, role) {
		t.Error("dave not in his group's role")
	}
	// Their password is the directory's: checked there, not changed here.
	if rec := env.do("POST", "/api/me/password", map[string]string{"current": "davepass", "new": "a new long password"}); rec.Code != http.StatusBadRequest {
		t.Errorf("change a directory password: %d %s", rec.Code, rec.Body)
	}
	env.login("admin", "correct horse battery")
	for _, c := range []struct{ user, pass string }{{"dave", "wrong"}, {"nobody", "x"}, {"admin", "wrong"}} {
		if rec := env.do("POST", "/api/login", map[string]string{"username": c.user, "password": c.pass}); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s/%s: %d", c.user, c.pass, rec.Code)
		}
	}
	// A role an admin gave by hand stays; the mapped role follows the
	// group at the next login.
	env.srv.db.Create(&models.RoleMember{RoleID: other, UserID: dave.ID, Level: models.RoleViewer})
	dir["dave"] = nil
	env.login("dave", "davepass")
	if memberOf(dave.ID, role) || !memberOf(dave.ID, other) {
		t.Errorf("after leaving the group: vpn %v, other %v", memberOf(dave.ID, role), memberOf(dave.ID, other))
	}
	env.login("admin", "correct horse battery")

	// With no server enabled, a copied user can't log in.
	env.srv.db.Model(&models.LdapServer{}).Where("1 = 1").Update("enabled", false)
	if rec := env.do("POST", "/api/login", map[string]string{"username": "dave", "password": "davepass"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("no server: %d", rec.Code)
	}
	env.srv.db.Model(&models.LdapServer{}).Where("1 = 1").Update("enabled", true)

	// The login order.
	var down models.LdapServer
	env.srv.db.Where("name = ?", "down").First(&down)
	if rec := env.do("POST", "/api/directory/servers/reorder", map[string]any{"ids": []uint{ad.ID, down.ID}}); rec.Code != http.StatusNoContent {
		t.Fatalf("reorder: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/directory/servers/reorder", map[string]any{"ids": []uint{ad.ID}}); rec.Code != http.StatusBadRequest {
		t.Errorf("reorder with one missing: %d", rec.Code)
	}
	env.srv.db.First(&ad, ad.ID)
	if ad.Position != 1 {
		t.Errorf("ad at %d", ad.Position)
	}

	// OpenVPN: the role's group goes to the agent with the directory.
	env.srv.db.Create(&models.Instance{Name: "main", IsDefault: true, FirewallID: 1})
	var inst models.Instance
	env.srv.db.Where("name = ?", "main").First(&inst)
	cert := env.create("/api/certificates", map[string]any{"instance_id": inst.ID, "name": "vpn", "enabled": true, "source": "import",
		"generate": map[string]any{"domains": []string{"vpn.example.com"}, "key_type": "ec256", "days": 30}})
	env.create("/api/interfaces", map[string]any{"instance_id": inst.ID, "name": "ovpn0", "kind": "openvpn", "enabled": true,
		"addresses": []string{"10.8.0.1/24"}, "ovpn_tcp_addresses": []string{"10.9.0.1/24"}, "ovpn_certificate_id": cert, "ovpn_role_id": role})
	doc, err := builder.Build(env.srv.db, 1)
	if err != nil {
		t.Fatal(err)
	}
	o := doc.Instance("main").Interface("ovpn0").OpenVPN
	if len(o.RoleGroups) != 1 || o.RoleGroups[0] != vpnGroup || doc.Directory == nil || len(doc.Directory.Servers) != 2 ||
		doc.Directory.Servers[0].Name != "ad" || doc.Directory.Servers[0].BindPassword != bindPW {
		t.Fatalf("openvpn %+v, directory %+v", o, doc.Directory)
	}
	for _, u := range o.Users {
		if u.Name == "dave" && (!u.LDAP || !u.Denied || u.Hash != "") {
			t.Errorf("dave: %+v", u)
		}
	}
	b, _ := json.Marshal(redactDoc(*doc))
	if strings.Contains(string(b), bindPW) {
		t.Error("redacted document holds the bind password")
	}
}

type directoryAgent struct {
	agentAPI
	logins []agentapi.DirectoryLogin
}

func (a *directoryAgent) DirectoryLogins(_ context.Context, after int64) (*agentapi.DirectoryLoginsResponse, error) {
	out := &agentapi.DirectoryLoginsResponse{}
	for _, l := range a.logins {
		if l.ID > after {
			out.Logins = append(out.Logins, l)
		}
	}
	return out, nil
}

// The users the directory let in to OpenVPN are copied in from the agent.
func TestDirectoryLoginsFromAgent(t *testing.T) {
	env := newEnv(t)
	role := env.create("/api/roles", map[string]any{"name": "vpn"})
	env.create("/api/directory/mappings", map[string]any{"group_dn": vpnGroup, "role_id": role, "level": "admin"})
	fake := &directoryAgent{logins: []agentapi.DirectoryLogin{
		{ID: 1, User: "frank", Server: "ad", DisplayName: "Frank", Groups: []string{vpnGroup}},
		{ID: 2, User: "admin", Server: "ad"}, // a local user: left alone
		{ID: 3, User: "a b", Server: "ad"},   // not a name OpenVPN takes
	}}
	env.srv.newAgent = func(*models.Firewall) (agentAPI, error) { return fake, nil }
	var fw models.Firewall
	env.srv.db.First(&fw)
	after := map[uint]int64{}
	env.srv.syncDirectoryLogins(context.Background(), &fw, after)
	if after[fw.ID] != 3 {
		t.Errorf("cursor %d", after[fw.ID])
	}
	var frank, admin models.User
	env.srv.db.Where("username = ?", "frank").First(&frank)
	env.srv.db.Where("username = ?", "admin").First(&admin)
	if frank.PasswordHash != models.LDAPPassword || frank.LdapServer != "ad" || frank.Role != models.RoleNone {
		t.Errorf("frank: %+v", frank)
	}
	var m models.RoleMember
	if err := env.srv.db.Where("user_id = ? AND role_id = ?", frank.ID, role).First(&m).Error; err != nil || m.Level != models.RoleAdmin {
		t.Errorf("frank's role: %+v %v", m, err)
	}
	if admin.PasswordHash == models.LDAPPassword || admin.LdapServer != "" {
		t.Errorf("admin: %+v", admin)
	}
	var n int64
	env.srv.db.Model(&models.User{}).Where("username = ?", "a b").Count(&n)
	if n != 0 {
		t.Error("a b copied")
	}
}
