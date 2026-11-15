// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/datastore"

	"github.com/abundo/portitor/internal/records"
	"github.com/abundo/portitor/models"
)

// A user is made in what runs and in the candidate together, so the next full
// commit neither loses nor undoes them.
func TestUsersRunAndAreTheCandidates(t *testing.T) {
	env := newEnv(t)
	id := env.create("/api/users", map[string]string{"username": "ann", "password": "a long password", "role": "viewer"})
	if u := env.userID(id); u.Username != "ann" || u.Role != models.RoleViewer {
		t.Fatalf("running: %+v", u)
	}
	if env.node("user=ann") == nil {
		t.Error("the candidate lacks the user")
	}
	if rec := env.do("GET", "/api/config/changes", nil); strings.Contains(rec.Body.String(), "ann") {
		t.Errorf("a made user shows as a change: %s", rec.Body)
	}
	// The password hash is a secret: never read back over /api/config.
	if rec := env.do("GET", "/api/config/candidate/user=ann", nil); strings.Contains(rec.Body.String(), "$2") {
		t.Errorf("the hash was read back: %s", rec.Body)
	}
	// A viewer reads no user over the tree.
	env.login("ann", "a long password")
	if rec := env.do("GET", "/api/config/candidate/user", nil); rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "ann") {
		t.Errorf("a viewer read the users: %d %s", rec.Code, rec.Body)
	}
	env.login("admin", "correct horse battery")
}

// Whoever writes a user, a changed role or password ends their sessions, and
// the last admin can't be taken away.
func TestUsersWrittenOverTheTree(t *testing.T) {
	env := newEnv(t)
	id := env.create("/api/users", map[string]string{"username": "ann", "password": "a long password", "role": "viewer"})
	before := env.userID(id).TokenVersion
	env.put("user=ann", map[string]any{"role": "admin", "password-hash": env.userID(id).PasswordHash})
	env.commitScope("user")
	if got := env.userID(id); got.Role != models.RoleAdmin || got.TokenVersion <= before {
		t.Errorf("after a role change over the tree: %+v (was version %d)", got, before)
	}
	// Not the last admin: ann is one too now; taking her away too is refused.
	env.put("user=admin", map[string]any{"role": "viewer"})
	if rec := env.cfg("PUT", "user=ann", map[string]any{"role": "viewer"}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "role admin") {
		t.Errorf("the last admin was taken away: %d %s", rec.Code, rec.Body)
	}
}

// A login that changes nothing writes nothing: the candidate's generation (and
// the replica's ETag) stay.
func TestDirectoryLoginWritesNothingWhenNothingChanged(t *testing.T) {
	env := newEnv(t)
	env.create("/api/directory/servers", map[string]any{"name": "ad", "enabled": true, "host": "dc.example.com", "base_dn": "dc=x"})
	d := records.DirectoryUser{DisplayName: "Dave", Email: "dave@example.com"}
	u, err := env.srv.rec.CopyDirectoryUser("dave", "ad", d)
	if err != nil || u == nil || u.ID == 0 {
		t.Fatalf("copy: %+v %v", u, err)
	}
	tr, _ := env.srv.tree()
	gen := tr.store.Gen()
	for range 3 {
		if err := env.srv.rec.UpdateDirectoryUser(u, "ad", d); err != nil {
			t.Fatal(err)
		}
		if again, err := env.srv.rec.CopyDirectoryUser("dave", "ad", d); err != nil || again == nil || again.ID != u.ID {
			t.Fatalf("copy again: %+v %v", again, err)
		}
	}
	if tr.store.Gen() != gen {
		t.Error("a login that changed nothing wrote the candidate")
	}
	// A user copied from a server that is gone is no one's.
	if g, err := env.srv.rec.CopyDirectoryUser("erin", "gone", d); err != nil || g == nil || g.LdapServer != "" {
		t.Errorf("a user of a deleted server: %+v %v", g, err)
	}
}

// A used recovery code is the session state's, not a write of the user.
func TestRecoveryCodeUseWritesNoTree(t *testing.T) {
	env := newEnv(t)
	id := env.create("/api/users", map[string]string{"username": "ann", "password": "a long password", "role": "viewer"})
	u := env.userID(id)
	if err := env.srv.rec.EnableTOTP(&u, 5, `["aa","bb","cc"]`); err != nil {
		// no pending secret: set one first
		_ = env.srv.rec.BeginTOTP(&u, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
		if err := env.srv.rec.EnableTOTP(&u, 5, `["aa","bb","cc"]`); err != nil {
			t.Fatal(err)
		}
	}
	tr, _ := env.srv.tree()
	gen := tr.store.Gen()
	u = env.userID(id)
	if ok, err := env.srv.rec.UseRecoveryCode(id, u.RecoveryCodes, `["aa","cc"]`); err != nil || !ok {
		t.Fatalf("use: %v %v", ok, err)
	}
	if ok, _ := env.srv.rec.UseRecoveryCode(id, u.RecoveryCodes, `["aa","cc"]`); ok {
		t.Error("a code was used twice")
	}
	if tr.store.Gen() != gen {
		t.Error("using a recovery code wrote the candidate")
	}
	if got := env.userID(id); got.RecoveryCodes != `["aa","cc"]` {
		t.Errorf("left: %q", got.RecoveryCodes)
	}
	// New codes forget the used ones.
	if err := env.srv.rec.SetRecoveryCodes(&u, `["aa","dd"]`); err != nil {
		t.Fatal(err)
	}
	if got := env.userID(id); got.RecoveryCodes != `["aa","dd"]` {
		t.Errorf("new codes: %q", got.RecoveryCodes)
	}
}

// A user or role renamed in the candidate alone (the CLI, /api/config) would
// leave what runs and the candidate with two ids for one entry: refused.
func TestRenamingAGlobalEntryInTheCandidateAlone(t *testing.T) {
	env := newEnv(t)
	env.create("/api/users", map[string]string{"username": "ann", "password": "a long password", "role": "viewer"})
	tr, _ := env.srv.tree()
	err := tr.store.Edit(context.Background(), "", func(work *datastore.Tree) error {
		return work.Rename(datastore.Path{{Name: "user", Keys: []string{"ann"}}}, []string{"anna"})
	})
	if err == nil || !strings.Contains(err.Error(), "renamed where it is made") {
		t.Errorf("a rename in the candidate alone: %v", err)
	}
	if env.node("user=ann") == nil || env.node("user=anna") != nil {
		t.Error("the refused rename changed the candidate")
	}
	// A role is renamed through the roles' own write, in both.
	role := env.create("/api/roles", map[string]any{"name": "ops"})
	if rec := env.do("PUT", "/api/roles/"+itoa(role), map[string]any{"name": "ops2"}); rec.Code != http.StatusOK {
		t.Fatalf("rename: %d %s", rec.Code, rec.Body)
	}
	if env.node("role=ops2") == nil {
		t.Error("the candidate did not follow the rename")
	}
}

// Adopted data whose admins are all directory users has a problem the rule
// would refuse today; changing a user is still allowed (only what a change
// adds is refused).
func TestAdminRuleRefusesOnlyWhatIsAdded(t *testing.T) {
	env := newEnv(t)
	id := env.create("/api/users", map[string]string{"username": "ann", "password": "a long password", "role": "viewer"})
	tr, _ := env.srv.tree()
	g, err := env.srv.globalsTree(tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range g.Root.Lists["user"] {
		u.Leaves["password-hash"] = models.LDAPPassword
	}
	if err := env.srv.writeGlobalsFile(tr, g); err != nil {
		t.Fatal(err)
	}
	env.srv.forgetRunning()
	if errs := tr.problemsOf(g); len(errs) == 0 {
		t.Fatal("no problem to start from")
	}
	// A change that adds none (ann's name) goes through; one that adds a
	// bad hash does not.
	u := env.userID(id)
	u.FullName = "Ann"
	if err := env.srv.rec.SaveUser(&u, false); err != nil {
		t.Errorf("a harmless change of a configuration with a problem: %v", err)
	}
	u.PasswordHash = "not a hash"
	if err := env.srv.rec.SaveUser(&u, false); err == nil {
		t.Error("a bad hash was written")
	}
}

// A firewall renamed in the candidate alone (the CLI) is refused, as a user's
// is: its id is what its deployments and generation are named by.
func TestRenamingAFirewallInTheCandidateAlone(t *testing.T) {
	env, _, _ := twoFirewalls(t)
	fp := strings.Repeat("ab", 32)
	env.create("/api/firewalls", map[string]any{"name": "fw1x", "ha_primary_id": 1, "agent_url": "https://192.0.2.3:8443", "agent_fingerprint": fp})
	tr, _ := env.srv.tree()
	err := tr.store.Edit(context.Background(), "", func(work *datastore.Tree) error {
		return work.Rename(datastore.Path{{Name: "firewall", Keys: []string{"fw1x"}}}, []string{"fw1b"})
	})
	if err == nil || !strings.Contains(err.Error(), "renamed where it is made") {
		t.Errorf("a rename in the candidate alone: %v", err)
	}
}
