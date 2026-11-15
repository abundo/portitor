// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package records

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/confview"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/internal/dbmigrate"
	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/models"
)

// implementations are the Stores the contract is checked on; a new
// implementation adds itself here, with a way to make a firewall it can
// attach deployments to.
type harness struct {
	store    Store
	firewall func(t *testing.T, name string) uint
	// add makes a firewall of the given fields (an HA pair's, say).
	add func(t *testing.T, fw models.Firewall) uint
	// put stores a row (a role, a mapping) a test needs to exist.
	put func(t *testing.T, row any)
}

func gormHarness(t *testing.T) harness {
	t.Helper()
	db, err := dbmigrate.Open(filepath.Join(t.TempDir(), "db.sqlite"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := dbmigrate.Up(db); err != nil {
		t.Fatal(err)
	}
	h := harness{
		store: NewGORM(db, ""),
		add: func(t *testing.T, fw models.Firewall) uint {
			if err := db.Create(&fw).Error; err != nil {
				t.Fatal(err)
			}
			return fw.ID
		},
	}
	h.put = func(t *testing.T, row any) {
		if err := db.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	h.firewall = func(t *testing.T, name string) uint { return h.add(t, models.Firewall{Name: name}) }
	return h
}

var implementations = map[string]func(*testing.T) harness{"gorm": gormHarness}

func each(t *testing.T, f func(t *testing.T, h harness)) {
	for name, mk := range implementations {
		t.Run(name, func(t *testing.T) { f(t, mk(t)) })
	}
}

func TestDeploymentsLatestAndLive(t *testing.T) {
	each(t, func(t *testing.T, h harness) {
		a, b := h.firewall(t, "a"), h.firewall(t, "b")
		if dep, err := h.store.LatestDeployment(a); err != nil || dep != nil {
			t.Fatalf("no deployments: %v %v", dep, err)
		}
		add := func(fw uint, commit int64, status string) *models.Deployment {
			d := &models.Deployment{FirewallID: fw, CommitID: commit, Generation: commit, Status: status}
			if err := h.store.RecordDeployment(d); err != nil || d.ID == 0 {
				t.Fatalf("record: %v, id %d", err, d.ID)
			}
			return d
		}
		add(a, 1, "applied")
		add(a, 2, "confirmed")
		add(a, 3, "failed")
		add(b, 4, "pending")

		// The latest is the newest whatever its status; the live one skips
		// a failed or rolled back deployment.
		if d, _ := h.store.LatestDeployment(a); d == nil || d.CommitID != 3 {
			t.Errorf("latest: %+v", d)
		}
		if d, _ := h.store.LiveDeployment(a); d == nil || d.CommitID != 2 {
			t.Errorf("live: %+v", d)
		}
		if d, _ := h.store.LiveDeployment(b); d == nil || d.Status != "pending" {
			t.Errorf("live of b: %+v", d)
		}

		// A status written back is read back.
		d, _ := h.store.LatestDeployment(a)
		d.Status, d.Message = "rolled_back", "rolled back by ann"
		if err := h.store.UpdateDeployment(d); err != nil {
			t.Fatal(err)
		}
		if got, _ := h.store.LatestDeployment(a); got.Status != "rolled_back" || got.Message != "rolled back by ann" {
			t.Errorf("updated: %+v", got)
		}

		recent, err := h.store.RecentDeployments(3)
		if err != nil || len(recent) != 3 || recent[0].CommitID != 4 {
			t.Errorf("recent: %v %+v", err, recent)
		}
		// Commits some deployment runs: 3 was rolled back above.
		if c, _ := h.store.LiveCommits(10); !slices.Equal(c, []int64{4, 2, 1}) {
			t.Errorf("live commits: %v", c)
		}
		if c, _ := h.store.LiveCommits(2); !slices.Equal(c, []int64{4, 2}) {
			t.Errorf("two live commits: %v", c)
		}
	})
}

func TestKnownNICs(t *testing.T) {
	each(t, func(t *testing.T, h harness) {
		a, b := h.firewall(t, "a"), h.firewall(t, "b")
		if err := h.store.RememberNICs(a, []string{"eth0", "eth1"}); err != nil {
			t.Fatal(err)
		}
		// Remembering a name again keeps it once.
		if err := h.store.RememberNICs(a, []string{"eth1", "eth2"}); err != nil {
			t.Fatal(err)
		}
		got, _ := h.store.KnownNICs(a)
		slices.Sort(got)
		if !slices.Equal(got, []string{"eth0", "eth1", "eth2"}) {
			t.Errorf("known: %v", got)
		}
		if other, _ := h.store.KnownNICs(b); len(other) != 0 {
			t.Errorf("another firewall's: %v", other)
		}
	})
}

func TestCounters(t *testing.T) {
	each(t, func(t *testing.T, h harness) {
		own, err := h.store.Own()
		if err != nil || own.LastCommit != 0 || own.WebCertificateID != nil {
			t.Fatalf("new: %+v %v", own, err)
		}
		if err := h.store.SetLastCommit(7); err != nil {
			t.Fatal(err)
		}
		id := uint(3)
		if err := h.store.SetWebCertificate(&id); err != nil {
			t.Fatal(err)
		}
		own, _ = h.store.Own()
		if own.LastCommit != 7 || own.WebCertificateID == nil || *own.WebCertificateID != 3 {
			t.Errorf("set: %+v", own)
		}
		if err := h.store.SetWebCertificate(nil); err != nil {
			t.Fatal(err)
		}
		if own, _ = h.store.Own(); own.WebCertificateID != nil {
			t.Errorf("cleared: %+v", own)
		}
	})
}

func TestFirewalls(t *testing.T) {
	each(t, func(t *testing.T, h harness) {
		if _, err := h.store.Firewall(9999); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a missing firewall: %v", err)
		}
		// Added when there is none, and only then (a new database has its
		// first firewall already, or EnsureFirewall makes it).
		if err := h.store.EnsureFirewall("first"); err != nil {
			t.Fatal(err)
		}
		before, _ := h.store.Firewalls()
		if len(before) != 1 {
			t.Fatalf("after EnsureFirewall: %+v", before)
		}
		if err := h.store.EnsureFirewall("other"); err != nil {
			t.Fatal(err)
		}
		second := h.firewall(t, "second")
		fws, err := h.store.Firewalls()
		if err != nil || len(fws) != 2 || fws[0].ID != before[0].ID || fws[1].ID != second {
			t.Fatalf("firewalls: %v %+v", err, fws)
		}

		if err := h.store.SetAgentConnection(second, "https://192.0.2.2:8443", "tok", "ab12"); err != nil {
			t.Fatal(err)
		}
		if err := h.store.SetGeneration(second, 9); err != nil {
			t.Fatal(err)
		}
		got, _ := h.store.Firewall(second)
		if got.AgentURL != "https://192.0.2.2:8443" || got.AgentToken != "tok" || got.AgentFingerprint != "ab12" {
			t.Errorf("second: %+v", got)
		}
		gens, _ := h.store.Generations()
		if gens[second] != 9 || gens[fws[0].ID] != 0 {
			t.Errorf("generations: %v", gens)
		}
		// Only raised.
		_ = h.store.SetGeneration(second, 3)
		if gens, _ = h.store.Generations(); gens[second] != 9 {
			t.Errorf("a generation was lowered: %v", gens)
		}
		if one, _ := h.store.Firewall(fws[0].ID); one.AgentURL != "" {
			t.Errorf("the first one changed: %+v", one)
		}
	})
}

// A promotion swaps the pair in one go: the secondary becomes the primary
// with the old primary's witness, the old primary its secondary at the
// next epoch with the pair's secret.
func TestPromoteFirewalls(t *testing.T) {
	each(t, func(t *testing.T, h harness) {
		prim := h.add(t, models.Firewall{Name: "prim", HAWitness: models.HAWitnessExternal, HAWitnessSecret: "w"})
		pid := prim
		sec := h.add(t, models.Firewall{Name: "sec", HAPrimaryID: &pid, HASecret: "pair", HAEpoch: 4})
		p, _ := h.store.Firewall(prim)
		s, _ := h.store.Firewall(sec)
		if err := h.store.PromoteFirewalls(s, p); err != nil {
			t.Fatal(err)
		}
		np, _ := h.store.Firewall(prim)
		ns, _ := h.store.Firewall(sec)
		if ns.HAPrimaryID != nil || ns.HASecret != "" || ns.HAEpoch != 0 || ns.HAWitness != models.HAWitnessExternal || ns.HAWitnessSecret != "w" {
			t.Errorf("new primary: %+v", ns)
		}
		if np.HAPrimaryID == nil || *np.HAPrimaryID != sec || np.HASecret != "pair" || np.HAEpoch != 5 || np.HAWitness != models.HAWitnessLocal || np.HAWitnessSecret != "" {
			t.Errorf("new secondary: %+v", np)
		}
	})
}

func TestUsers(t *testing.T) {
	each(t, func(t *testing.T, h harness) {
		if _, err := h.store.User(9999); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a missing user: %v", err)
		}
		if _, err := h.store.UserNamed("nobody"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a missing user by name: %v", err)
		}
		u := &models.User{Username: "ann", FullName: "Ann", Role: models.RoleViewer, PasswordHash: "x"}
		if err := h.store.CreateUser(u); err != nil || u.ID == 0 {
			t.Fatalf("create: %v", err)
		}
		if err := h.store.CreateUser(&models.User{Username: "ann", PasswordHash: "x", Role: models.RoleViewer}); err == nil {
			t.Error("a second ann was made")
		}
		bob := &models.User{Username: "bob", PasswordHash: "x", Role: models.RoleAdmin}
		if err := h.store.CreateUser(bob); err != nil {
			t.Fatal(err)
		}
		list, _ := h.store.Users()
		if len(list) < 2 || list[len(list)-2].Username != "ann" {
			t.Errorf("users by name: %+v", list)
		}

		// A save of the configuration leaves the runtime values alone: a
		// stale copy doesn't undo a step another request accepted.
		stale, _ := h.store.User(u.ID)
		if ok, err := h.store.UseTOTPStep(u.ID, 100); !ok || err != nil {
			t.Fatalf("step: %v %v", ok, err)
		}
		stale.FullName = "Ann A"
		if err := h.store.SaveUser(stale, false); err != nil {
			t.Fatal(err)
		}
		if ok, _ := h.store.UseTOTPStep(u.ID, 100); ok {
			t.Error("a save of the user let a step be used twice")
		}
		got, _ := h.store.User(u.ID)
		if got.FullName != "Ann A" || got.TOTPLastStep != 100 || got.TokenVersion != 0 {
			t.Errorf("after save: %+v", got)
		}

		// Revoking counts up, in the stored user and the one saved.
		if err := h.store.SaveUser(got, true); err != nil || got.TokenVersion != 1 {
			t.Fatalf("revoke: %v, version %d", err, got.TokenVersion)
		}
		if again, _ := h.store.User(u.ID); again.TokenVersion != 1 {
			t.Errorf("stored version %d", again.TokenVersion)
		}

		if err := h.store.DeleteUser(u.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := h.store.User(u.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("after delete: %v", err)
		}
	})
}

// A TOTP step and a recovery code are each good once, even when two
// requests present them together.
func TestTOTPUsedOnce(t *testing.T) {
	each(t, func(t *testing.T, h harness) {
		u := &models.User{Username: "ann", PasswordHash: "x", Role: models.RoleViewer}
		if err := h.store.CreateUser(u); err != nil {
			t.Fatal(err)
		}
		if err := h.store.BeginTOTP(u, "SECRET"); err != nil || u.TOTPPending != "SECRET" {
			t.Fatalf("begin: %v %q", err, u.TOTPPending)
		}
		if err := h.store.EnableTOTP(u, 50, `["a","b"]`); err != nil {
			t.Fatal(err)
		}
		got, _ := h.store.User(u.ID)
		if got.TOTPSecret != "SECRET" || got.TOTPPending != "" || got.TOTPLastStep != 50 || got.RecoveryCodes != `["a","b"]` {
			t.Fatalf("enabled: %+v", got)
		}
		if ok, _ := h.store.UseTOTPStep(u.ID, 50); ok {
			t.Error("the step of enabling was accepted again")
		}
		if ok, _ := h.store.UseTOTPStep(u.ID, 51); !ok {
			t.Error("a newer step was refused")
		}
		if ok, _ := h.store.UseTOTPStep(u.ID, 51); ok {
			t.Error("a step was accepted twice")
		}

		if ok, _ := h.store.UseRecoveryCode(u.ID, `["a","b"]`, `["b"]`); !ok {
			t.Error("a recovery code was refused")
		}
		// The second request read the same list: refused.
		if ok, _ := h.store.UseRecoveryCode(u.ID, `["a","b"]`, `["a"]`); ok {
			t.Error("a recovery code was used twice")
		}
		got, _ = h.store.User(u.ID)
		if got.RecoveryCodes != `["b"]` {
			t.Errorf("codes: %q", got.RecoveryCodes)
		}

		if err := h.store.SetRecoveryCodes(got, `["c"]`); err != nil {
			t.Fatal(err)
		}
		if err := h.store.ClearTOTP(got); err != nil {
			t.Fatal(err)
		}
		got, _ = h.store.User(u.ID)
		if got.TOTPSecret != "" || got.TOTPLastStep != 0 || got.RecoveryCodes != "" {
			t.Errorf("cleared: %+v", got)
		}
	})
}

func TestPlanMemberships(t *testing.T) {
	mappings := []models.LdapRoleMapping{
		{GroupDn: "CN=ops,DC=x", RoleID: 1, Level: models.RoleViewer},
		{GroupDn: "CN=root,DC=x", RoleID: 1, Level: models.RoleAdmin},
		{GroupDn: "CN=lab,DC=x", RoleID: 2, Level: models.RoleViewer},
		{GroupDn: "CN=gone,DC=x", RoleID: 3, Level: models.RoleViewer},
	}
	have := []models.RoleMember{
		{Base: models.Base{ID: 10}, RoleID: 1, UserID: 7, Level: models.RoleViewer},
		{Base: models.Base{ID: 11}, RoleID: 3, UserID: 7, Level: models.RoleViewer},
		{Base: models.Base{ID: 12}, RoleID: 9, UserID: 7, Level: models.RoleAdmin}, // not mapped: kept
	}
	// In ops and root (the higher level wins) and lab; no longer in gone.
	p := PlanMemberships(7, mappings, have, []string{"CN=ops,DC=x", "CN=root,DC=x", "CN=lab,DC=x"})
	if p.Level[10] != models.RoleAdmin || !slices.Equal(p.Remove, []uint{11}) {
		t.Errorf("plan: %+v", p)
	}
	if len(p.Add) != 1 || p.Add[0].RoleID != 2 || p.Add[0].UserID != 7 || p.Add[0].Level != models.RoleViewer {
		t.Errorf("added: %+v", p.Add)
	}
}

func TestDirectoryUsers(t *testing.T) {
	each(t, func(t *testing.T, h harness) {
		role := &models.Role{Name: "ops"}
		h.put(t, role)
		h.put(t, &models.LdapRoleMapping{GroupDn: "CN=ops,DC=x", RoleID: role.ID, Level: models.RoleAdmin})

		u, err := h.store.CopyDirectoryUser("carol", "corp", DirectoryUser{DisplayName: "Carol", Email: "c@x", Groups: []string{"CN=ops,DC=x"}})
		if err != nil || u == nil || u.Role != models.RoleNone || u.PasswordHash != models.LDAPPassword || u.LdapServer != "corp" {
			t.Fatalf("copy: %+v %v", u, err)
		}
		grants, _ := h.store.UserGrants(u.ID)
		_ = grants // the role names no instance, so there is no grant yet
		again, err := h.store.CopyDirectoryUser("carol", "corp", DirectoryUser{DisplayName: "Carol C"})
		if err != nil || again == nil || again.FullName != "Carol C" {
			t.Fatalf("copy again: %+v %v", again, err)
		}
		// A local user of that name is theirs: nothing is copied over it.
		local := &models.User{Username: "dave", PasswordHash: "bcrypt", Role: models.RoleViewer}
		if err := h.store.CreateUser(local); err != nil {
			t.Fatal(err)
		}
		if got, err := h.store.CopyDirectoryUser("dave", "corp", DirectoryUser{DisplayName: "Dave"}); err != nil || got != nil {
			t.Fatalf("copy over a local user: %+v %v", got, err)
		}
		if err := h.store.UpdateDirectoryUser(again, "other", DirectoryUser{Email: "new@x"}); err != nil {
			t.Fatal(err)
		}
		if got, _ := h.store.User(u.ID); got.LdapServer != "other" || got.Email != "new@x" || got.FullName != "Carol C" {
			t.Errorf("updated: %+v", got)
		}
	})
}

func TestRoles(t *testing.T) {
	each(t, func(t *testing.T, h harness) {
		ann := &models.User{Username: "ann", PasswordHash: "x", Role: models.RoleViewer}
		if err := h.store.CreateUser(ann); err != nil {
			t.Fatal(err)
		}
		shop := "shop"
		own := &models.Role{Name: "vf-shop", Instance: &shop}
		if err := h.store.SaveRole(own, []models.RoleMember{{UserID: ann.ID, Level: models.RoleAdmin}}, []string{"ignored"}); err != nil {
			t.Fatal(err)
		}
		// An instance's role grants its instance, whatever is asked.
		if !slices.Equal(own.Instances, []string{"shop"}) || len(own.Members) != 1 {
			t.Errorf("own role: %+v", own)
		}
		byHand := &models.Role{Name: "ops"}
		if err := h.store.SaveRole(byHand, nil, []string{"a", "b"}); err != nil || byHand.ID == 0 {
			t.Fatalf("by hand: %v", err)
		}
		// Updating replaces members and grants.
		byHand.Description = "operators"
		if err := h.store.SaveRole(byHand, []models.RoleMember{{UserID: ann.ID, Level: models.RoleViewer}}, []string{"b"}); err != nil {
			t.Fatal(err)
		}
		roles, err := h.store.Roles()
		if err != nil || len(roles) != 2 || roles[0].Name != "vf-shop" || roles[1].Name != "ops" {
			t.Fatalf("roles (instance roles first): %v %+v", err, roles)
		}
		if !slices.Equal(roles[1].Instances, []string{"b"}) || len(roles[1].Members) != 1 || roles[1].Description != "operators" {
			t.Errorf("ops: %+v", roles[1])
		}
		grants, _ := h.store.UserGrants(ann.ID)
		if len(grants) != 2 {
			t.Errorf("grants: %+v", grants)
		}
		if err := h.store.SaveRole(&models.Role{Name: "bad"}, []models.RoleMember{{UserID: 9999, Level: models.RoleViewer}}, nil); !errors.Is(err, ErrNoSuchUser) {
			t.Errorf("a member that is no user: %v", err)
		}
		if members, _ := h.store.RoleMembers(); len(members) != 2 {
			t.Errorf("members after the refused save: %+v", members)
		}

		// The roles of instances gone from the configuration go, hand-made
		// roles stay (their grants of a gone instance go).
		if err := h.store.DropInstanceRoles([]string{"b"}); err != nil {
			t.Fatal(err)
		}
		roles, _ = h.store.Roles()
		if len(roles) != 1 || roles[0].Name != "ops" || !slices.Equal(roles[0].Instances, []string{"b"}) {
			t.Errorf("after drop: %+v", roles)
		}
		if err := h.store.DeleteRole(byHand.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := h.store.Role(byHand.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("after delete: %v", err)
		}
	})
}

// treeOf is a tree with the named instances.
func treeOf(t *testing.T, names ...string) *datastore.Tree {
	t.Helper()
	tree := datastore.New(schema.MustLoad())
	for _, n := range names {
		if err := tree.EditJSON(datastore.Path{{Name: "instance"}}, datastore.EditCreate, []byte(`{"name":"`+n+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	return tree
}

func idOf(t *testing.T, ids sqlmap.IDs, path string) int64 {
	t.Helper()
	id, ok := ids.ID(path)
	if !ok {
		t.Fatalf("no id for %s", path)
	}
	return id
}

// The ids and the counters are in files next to the database: a new
// Store on the same directory sees them, and the first one seeds them from
// the old tables.
func TestStateFiles(t *testing.T) {
	dir := t.TempDir()
	db, err := dbmigrate.Open(filepath.Join(dir, "db.sqlite"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := dbmigrate.Up(db); err != nil {
		t.Fatal(err)
	}
	// An installation from before the files: its ids and counters are in
	// tables.
	for _, q := range []string{
		"INSERT INTO config_ids (path, tbl, id) VALUES ('/instance[name=main]', 'instances', 7)",
		"INSERT OR IGNORE INTO settings (id) VALUES (1)",
		"UPDATE settings SET last_commit = 5, web_certificate_id = 3 WHERE id = 1",
	} {
		if err := db.Exec(q).Error; err != nil {
			t.Fatal(err)
		}
	}
	g := NewGORM(db, dir)
	ids, err := g.IDs()
	if err != nil || idOf(t, ids, "/instance[name=main]") != 7 {
		t.Fatalf("seeded ids: %v", err)
	}
	own, _ := g.Own()
	if own.LastCommit != 5 || own.WebCertificateID == nil || *own.WebCertificateID != 3 {
		t.Fatalf("seeded state: %+v", own)
	}
	for _, f := range []string{"entry-ids.json", "state.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s was not written: %v", f, err)
		}
	}

	// The tables no longer matter: the files do.
	db.Exec("DELETE FROM config_ids")
	db.Exec("UPDATE settings SET last_commit = 0")
	if err := g.SetLastCommit(9); err != nil {
		t.Fatal(err)
	}
	m, err := confview.Mapping()
	if err != nil {
		t.Fatal(err)
	}
	tree := treeOf(t, "main", "shop")
	if err := g.FollowChange(m, tree); err != nil {
		t.Fatal(err)
	}
	again := NewGORM(db, dir)
	ids, _ = again.IDs()
	if idOf(t, ids, "/instance[name=main]") != 7 {
		t.Error("main lost its id")
	}
	shop := idOf(t, ids, "/instance[name=shop]")
	if shop == 7 || shop == 0 {
		t.Errorf("shop's id %d", shop)
	}
	if own, _ := again.Own(); own.LastCommit != 9 {
		t.Errorf("counter after reopening: %+v", own)
	}

	// The counter is the highest given anywhere: a deployment, or a kept
	// commit's file, beyond the file's own.
	fw, _ := g.Firewalls()
	again.RecordDeployment(&models.Deployment{FirewallID: fw[0].ID, CommitID: 12, Status: "applied"})
	if own, _ := again.Own(); own.LastCommit != 12 {
		t.Errorf("counter with a deployment of 12: %+v", own)
	}
	os.MkdirAll(filepath.Join(dir, "deployed"), 0o700)
	os.WriteFile(filepath.Join(dir, "deployed", "15-config.json"), []byte("{}"), 0o600)
	if own, _ := again.Own(); own.LastCommit != 15 {
		t.Errorf("counter with a commit file of 15: %+v", own)
	}

	// A rename keeps the entry's id, and one deleted keeps its id for the
	// same path.
	renamed := treeOf(t, "main", "shop")
	if err := renamed.Rename(datastore.Path{{Name: "instance", Keys: []string{"shop"}}}, []string{"store"}); err != nil {
		t.Fatal(err)
	}
	if err := again.FollowChange(m, renamed); err != nil {
		t.Fatal(err)
	}
	ids, _ = again.IDs()
	if idOf(t, ids, "/instance[name=store]") != shop {
		t.Errorf("the renamed instance got another id")
	}

	// A copy carries the ids; a copy without them takes the database's table.
	files, _ := again.ExportState(false)
	other := NewGORM(db, t.TempDir())
	if err := other.ImportState(files); err != nil {
		t.Fatal(err)
	}
	oids, _ := other.IDs()
	if idOf(t, oids, "/instance[name=store]") != shop {
		t.Error("the copy's ids were not taken")
	}
	db.Exec("INSERT INTO config_ids (path, tbl, id) VALUES ('/instance[name=old]', 'instances', 4)")
	if err := other.ImportState(map[string][]byte{}); err != nil {
		t.Fatal(err)
	}
	oids, _ = other.IDs()
	if idOf(t, oids, "/instance[name=old]") != 4 {
		t.Error("a copy with no ids did not take the table's")
	}
}

func openIn(t *testing.T, dir string) (*GORM, *gorm.DB) {
	t.Helper()
	db, err := dbmigrate.Open(filepath.Join(dir, "db.sqlite"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := dbmigrate.Up(db); err != nil {
		t.Fatal(err)
	}
	return NewGORM(db, dir), db
}

// The deployments are a log in a file: a new Store on the directory has
// them, a change of status is a line of its own, a last line cut short by a
// crash is ignored, and pruning keeps what a firewall runs.
func TestDeploymentLog(t *testing.T) {
	dir := t.TempDir()
	g, db := openIn(t, dir)
	fw := g.firewallOrFail(t)
	add := func(commit int64, status string) *models.Deployment {
		d := &models.Deployment{FirewallID: fw, CommitID: commit, Status: status, Document: `{"secret":"redacted"}`, DocHash: "h", Instances: models.StringList{"a"}}
		if err := g.RecordDeployment(d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	a := add(1, "applied")
	b := add(2, "pending")
	b.Status, b.Message = "confirmed", "ok"
	if err := g.UpdateDeployment(b); err != nil {
		t.Fatal(err)
	}
	add(3, "failed")

	again, _ := NewGORM(db, dir), 0
	got, _ := again.LiveDeployment(fw)
	if got == nil || got.CommitID != 2 || got.Status != "confirmed" || got.Message != "ok" || got.Document != `{"secret":"redacted"}` || got.DocHash != "h" || len(got.Instances) != 1 {
		t.Fatalf("reread: %+v", got)
	}
	if c := add(4, "applied"); c.ID <= a.ID+2 {
		t.Errorf("ids not increasing: %d", c.ID)
	}

	// A crash in the middle of a line.
	f, _ := os.OpenFile(filepath.Join(dir, "deployments.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"add": {"id": 99, "commit_id"`)
	f.Close()
	cut := NewGORM(db, dir)
	if recent, _ := cut.RecentDeployments(0); len(recent) != 4 {
		t.Errorf("a cut line changed the log: %d", len(recent))
	}

	// Pruning keeps the newest and the one the firewall runs; an id is not
	// given twice after it.
	if err := cut.PruneDeployments(1, time.Time{}); err != nil {
		t.Fatal(err)
	}
	recent, _ := cut.RecentDeployments(0)
	if len(recent) != 1 || recent[0].CommitID != 4 {
		t.Fatalf("after pruning to 1: %+v", recent)
	}
	cut.RecordDeployment(&models.Deployment{FirewallID: fw, CommitID: 5, Status: "failed"})
	if err := cut.PruneDeployments(1, time.Time{}); err != nil {
		t.Fatal(err)
	}
	recent, _ = cut.RecentDeployments(0)
	if len(recent) != 2 || recent[1].CommitID != 4 || recent[0].CommitID != 5 || recent[0].ID <= 4 {
		t.Errorf("the running deployment was not kept: %+v", recent)
	}
	// By age.
	if err := cut.PruneDeployments(0, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// (the latest stays too, a failed one here).
	if recent, _ = cut.RecentDeployments(0); len(recent) != 2 || recent[0].CommitID != 5 || recent[1].CommitID != 4 {
		t.Errorf("after pruning by age: %+v", recent)
	}
	reopened := NewGORM(db, dir)
	if recent, _ = reopened.RecentDeployments(0); len(recent) != 2 {
		t.Errorf("pruning was not written: %+v", recent)
	}
}

func (g *GORM) firewallOrFail(t *testing.T) uint {
	t.Helper()
	fws, err := g.Firewalls()
	if err != nil || len(fws) == 0 {
		g.EnsureFirewall("fw")
		fws, err = g.Firewalls()
	}
	if err != nil || len(fws) == 0 {
		t.Fatalf("no firewall: %v", err)
	}
	return fws[0].ID
}

// An installation from before the log has its deployments and known
// interfaces in tables: the first use takes them, and the replica's copy
// carries both files.
func TestDeploymentLogSeedAndReplica(t *testing.T) {
	dir := t.TempDir()
	g, db := openIn(t, dir)
	fw := g.firewallOrFail(t)
	db.Create(&models.Deployment{FirewallID: fw, CommitID: 3, Generation: 3, Status: "applied", Document: "{}"})
	db.Create(&models.KnownInterface{FirewallID: fw, Name: "eth0"})
	db.Create(&models.KnownInterface{FirewallID: fw, Name: "eth1"})
	g = NewGORM(db, dir)
	if d, _ := g.LiveDeployment(fw); d == nil || d.CommitID != 3 {
		t.Fatalf("seeded deployment: %+v", d)
	}
	if n, _ := g.KnownNICs(fw); !slices.Equal(n, []string{"eth0", "eth1"}) {
		t.Fatalf("seeded NICs: %v", n)
	}
	// What is in the files wins from now on.
	db.Exec("DELETE FROM deployments")
	db.Exec("DELETE FROM known_interfaces")
	if d, _ := NewGORM(db, dir).LiveDeployment(fw); d == nil {
		t.Error("the table was read again")
	}

	backup, _ := g.ExportState(false)
	if _, ok := backup["deployments.jsonl"]; ok {
		t.Error("a backup carries the deployments")
	}
	replica, _ := g.ExportState(true)
	other, odb := openIn(t, t.TempDir())
	ofw := other.firewallOrFail(t)
	_ = odb
	if err := other.ImportState(replica); err != nil {
		t.Fatal(err)
	}
	if d, _ := other.LiveDeployment(fw); d == nil || d.CommitID != 3 {
		t.Errorf("the copy's deployment: %+v (firewall %d)", d, ofw)
	}
	if n, _ := other.KnownNICs(fw); len(n) != 2 {
		t.Errorf("the copy's NICs: %v", n)
	}
	// A backup's import leaves the installation's own history.
	if err := other.ImportState(backup); err != nil {
		t.Fatal(err)
	}
	if d, _ := other.LiveDeployment(fw); d == nil {
		t.Error("a backup replaced the deployments")
	}
}

// A pending deployment can be rolled back: what then runs is the newest
// settled one, however old, and pruning at the default settings (a year)
// must leave it.
func TestPruneKeepsTheRollbackTarget(t *testing.T) {
	dir := t.TempDir()
	g, _ := openIn(t, dir)
	fw := g.firewallOrFail(t)
	old := &models.Deployment{FirewallID: fw, CommitID: 1, Status: "confirmed"}
	g.RecordDeployment(old)
	g.files.mu.Lock()
	g.files.deps[0].CreatedAt = time.Now().AddDate(-2, 0, 0)
	g.files.mu.Unlock()
	g.RecordDeployment(&models.Deployment{FirewallID: fw, CommitID: 2, Status: "pending"})
	if err := g.PruneDeployments(500, time.Now().AddDate(0, 0, -365)); err != nil {
		t.Fatal(err)
	}
	recent, _ := g.RecentDeployments(0)
	if len(recent) != 2 {
		t.Fatalf("the rollback target was pruned: %+v", recent)
	}
	// Rolled back: the old one runs.
	pending, _ := g.LatestDeployment(fw)
	pending.Status = "rolled_back"
	g.UpdateDeployment(pending)
	if live, _ := g.LiveDeployment(fw); live == nil || live.CommitID != 1 {
		t.Errorf("after the rollback: %+v", live)
	}
	// A skipped latest one stays for catching up.
	g.RecordDeployment(&models.Deployment{FirewallID: fw, CommitID: 3, Status: "skipped"})
	if err := g.PruneDeployments(1, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if latest, _ := g.LatestDeployment(fw); latest == nil || latest.Status != "skipped" {
		t.Errorf("the skipped deployment was pruned: %+v", latest)
	}
}

// The console commands (createadmin, commit, cli) run a Server of their own
// beside the daemon, on the same files: what one writes the other reads, and
// neither gives an id or a number the other has given.
func TestTwoStoresOnOneDirectory(t *testing.T) {
	dir := t.TempDir()
	a, db := openIn(t, dir)
	b := NewGORM(db, dir)
	fw := a.firewallOrFail(t)
	m, err := confview.Mapping()
	if err != nil {
		t.Fatal(err)
	}

	// Both have read the files before the other writes.
	if _, err := a.IDs(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.IDs(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Own(); err != nil {
		t.Fatal(err)
	}

	if err := a.FollowChange(m, treeOf(t, "one", "two")); err != nil {
		t.Fatal(err)
	}
	if err := b.FollowChange(m, treeOf(t, "three")); err != nil {
		t.Fatal(err)
	}
	ids, _ := a.IDs()
	seen := map[int64]string{}
	for _, name := range []string{"one", "two", "three"} {
		id := idOf(t, ids, "/instance[name="+name+"]")
		if other, dup := seen[id]; dup {
			t.Errorf("%s and %s have the id %d", name, other, id)
		}
		seen[id] = name
	}

	d1 := &models.Deployment{FirewallID: fw, CommitID: 1, Status: "applied"}
	d2 := &models.Deployment{FirewallID: fw, CommitID: 2, Status: "pending"}
	a.RecordDeployment(d1)
	b.RecordDeployment(d2)
	if d1.ID == d2.ID || d2.ID == 0 {
		t.Errorf("deployment ids %d %d", d1.ID, d2.ID)
	}
	d2.Status = "confirmed"
	if err := a.UpdateDeployment(d2); err != nil {
		t.Fatal(err)
	}
	if live, _ := b.LiveDeployment(fw); live == nil || live.CommitID != 2 || live.Status != "confirmed" {
		t.Errorf("b's view of the live deployment: %+v", live)
	}

	if err := a.SetLastCommit(9); err != nil {
		t.Fatal(err)
	}
	if own, _ := b.Own(); own.LastCommit != 9 {
		t.Errorf("b's counter %d", own.LastCommit)
	}
	b.RememberNICs(fw, []string{"eth9"})
	a.RememberNICs(fw, []string{"eth8"})
	if n, _ := b.KnownNICs(fw); len(n) != 2 {
		t.Errorf("known interfaces: %v", n)
	}
}

// The users' runtime values are in sessions.json, not the users' rows: an
// installation from before has them in the table and they are taken from
// there, a save of a user leaves them alone, a deleted user's version stays,
// and the replica's copy merges them by maximum.
func TestSessions(t *testing.T) {
	dir := t.TempDir()
	g, db := openIn(t, dir)
	u := &models.User{Username: "ann", PasswordHash: "x", Role: models.RoleViewer}
	if err := g.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	// From before: the table's columns.
	db.Exec("UPDATE users SET token_version = 4, totp_last_step = 77, totp_pending = 'PEND' WHERE id = ?", u.ID)
	g = NewGORM(db, dir)
	got, _ := g.User(u.ID)
	if got.TokenVersion != 4 || got.TOTPLastStep != 77 || got.TOTPPending != "PEND" {
		t.Fatalf("seeded: %+v", got)
	}
	db.Exec("UPDATE users SET token_version = 0, totp_last_step = 0, totp_pending = ''")
	if again, _ := NewGORM(db, dir).User(u.ID); again.TokenVersion != 4 {
		t.Errorf("the table was read again: %+v", again)
	}

	// A save leaves the values; a revoke raises the version in the user too.
	got.FullName = "Ann"
	if err := g.SaveUser(got, true); err != nil || got.TokenVersion != 5 {
		t.Fatalf("revoke: %v %d", err, got.TokenVersion)
	}
	stale := *got
	stale.TokenVersion = 0
	if err := g.SaveUser(&stale, false); err != nil {
		t.Fatal(err)
	}
	if now, _ := g.User(u.ID); now.TokenVersion != 5 || now.TOTPLastStep != 77 {
		t.Errorf("a save changed the runtime values: %+v", now)
	}

	// A deleted user's version stays above the sessions it ended.
	if err := g.DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	reopened := NewGORM(db, dir)
	ghost := &models.User{Base: models.Base{ID: u.ID}}
	reopened.withRuntime(ghost)
	if ghost.TokenVersion != 6 {
		t.Errorf("version after the delete: %d", ghost.TokenVersion)
	}

	// The copy the replica takes: each value the larger.
	other, _ := openIn(t, t.TempDir())
	other.changeSession(u.ID, func(r *sessionRec) bool { r.TokenVersion, r.TOTPLastStep = 9, 5; return true })
	files, _ := g.ExportState(true)
	if _, ok := files["sessions.json"]; !ok {
		t.Fatal("the replica's copy lacks the sessions")
	}
	if backup, _ := g.ExportState(false); backup["sessions.json"] != nil {
		t.Error("a backup carries the sessions")
	}
	if err := other.ImportState(files); err != nil {
		t.Fatal(err)
	}
	merged := &models.User{Base: models.Base{ID: u.ID}}
	other.withRuntime(merged)
	if merged.TokenVersion != 9 || merged.TOTPLastStep != 77 {
		t.Errorf("merged: %+v", merged)
	}
}
