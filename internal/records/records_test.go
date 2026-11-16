// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package records

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/confview"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/models"
)

// harness is a Kept the contract is checked on, with a way to number the
// firewalls deployments are attached to (they are the tree's: here only ids).
type harness struct {
	store    Kept
	firewall func(t *testing.T, name string) uint
}

func filesHarness(dir string) func(t *testing.T) harness {
	return func(t *testing.T) harness {
		d := dir
		if d == "disk" {
			d = t.TempDir()
		}
		var next uint
		return harness{store: NewFiles(d), firewall: func(*testing.T, string) uint { next++; return next }}
	}
}

var implementations = map[string]func(*testing.T) harness{"memory": filesHarness(""), "files": filesHarness("disk")}

func each(t *testing.T, f func(t *testing.T, h harness)) {
	for name, mk := range implementations {
		t.Run(name, func(t *testing.T) { f(t, mk(t)) })
	}
}

// openIn is a Files on dir, and the id of a firewall to attach deployments to.
func openIn(t *testing.T, dir string) *Files {
	t.Helper()
	return NewFiles(dir)
}

const fw = uint(1)

// A TOTP step is good once.
func TestTOTPUsedOnce(t *testing.T) {
	each(t, func(t *testing.T, h harness) {
		if err := h.store.EnableTOTPState(7, 50); err != nil {
			t.Fatal(err)
		}
		if ok, _ := h.store.UseTOTPStep(7, 50); ok {
			t.Error("the step of enabling was accepted again")
		}
		if ok, _ := h.store.UseTOTPStep(7, 51); !ok {
			t.Error("a newer step was refused")
		}
		if ok, _ := h.store.UseTOTPStep(7, 51); ok {
			t.Error("a step was accepted twice")
		}
		if ok, _ := h.store.MarkRecoveryCodeUsed(7, "a"); !ok {
			t.Error("a recovery code was refused")
		}
		if ok, _ := h.store.MarkRecoveryCodeUsed(7, "a"); ok {
			t.Error("a recovery code was used twice")
		}
		u := &models.User{Base: models.Base{ID: 7}, RecoveryCodes: `["a","b"]`}
		if err := h.store.Runtime(u); err != nil || u.RecoveryCodes != `["b"]` || u.TOTPLastStep != 51 {
			t.Errorf("runtime: %v %+v", err, u)
		}
		if err := h.store.ClearTOTPState(7); err != nil {
			t.Fatal(err)
		}
		u = &models.User{Base: models.Base{ID: 7}}
		if h.store.Runtime(u); u.TOTPLastStep != 0 {
			t.Errorf("cleared: %+v", u)
		}
	})
}

// The ids and the counters are in files: a new Files on the same directory
// sees them.
func TestStateFiles(t *testing.T) {
	dir := t.TempDir()
	g := openIn(t, dir)
	if err := g.Seed(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"entry-ids.json", "state.json", "deployments.jsonl", "known-nics.json", "sessions.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s was not made: %v", f, err)
		}
	}
	if err := g.SetLastCommit(9); err != nil {
		t.Fatal(err)
	}
	m, err := confview.Mapping()
	if err != nil {
		t.Fatal(err)
	}
	if err := g.FollowChange(m, treeOf(t, "main", "shop")); err != nil {
		t.Fatal(err)
	}
	again := openIn(t, dir)
	ids, _ := again.IDs()
	main, shop := idOf(t, ids, "/instance[name=main]"), idOf(t, ids, "/instance[name=shop]")
	if main == shop || shop == 0 {
		t.Errorf("ids %d %d", main, shop)
	}
	if own, _ := again.Own(); own.LastCommit != 9 {
		t.Errorf("counter after reopening: %+v", own)
	}

	// The counter is the highest given anywhere: a deployment, or a kept
	// commit's file, beyond the file's own.
	again.RecordDeployment(&models.Deployment{FirewallID: fw, CommitID: 12, Status: "applied"})
	if own, _ := again.Own(); own.LastCommit != 12 {
		t.Errorf("counter with a deployment of 12: %+v", own)
	}
	os.MkdirAll(filepath.Join(dir, "deployed"), 0o700)
	os.WriteFile(filepath.Join(dir, "deployed", "15-config.json"), []byte("{}"), 0o600)
	if own, _ := again.Own(); own.LastCommit != 15 {
		t.Errorf("counter with a commit file of 15: %+v", own)
	}

	// A rename keeps the entry's id.
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

	// A copy carries the ids; a copy without them is refused.
	files, _ := again.ExportState(false)
	other := openIn(t, t.TempDir())
	if err := other.ImportState(files); err != nil {
		t.Fatal(err)
	}
	oids, _ := other.IDs()
	if idOf(t, oids, "/instance[name=store]") != shop {
		t.Error("the copy's ids were not taken")
	}
	if err := other.ImportState(map[string][]byte{}); err == nil {
		t.Error("a copy with no ids was taken")
	}
}

// The replica's copy carries the deployments and known interfaces; a
// backup's import leaves the installation's own history.
func TestDeploymentLogReplica(t *testing.T) {
	g := openIn(t, t.TempDir())
	g.RecordDeployment(&models.Deployment{FirewallID: fw, CommitID: 3, Generation: 3, Status: "applied", Document: "{}"})
	g.RememberNICs(fw, []string{"eth0", "eth1"})

	backup, _ := g.ExportState(false)
	if _, ok := backup["deployments.jsonl"]; ok {
		t.Error("a backup carries the deployments")
	}
	replica, _ := g.ExportState(true)
	other := openIn(t, t.TempDir())
	if err := other.ImportState(replica); err != nil {
		t.Fatal(err)
	}
	if d, _ := other.LiveDeployment(fw); d == nil || d.CommitID != 3 {
		t.Errorf("the copy's deployment: %+v", d)
	}
	if n, _ := other.KnownNICs(fw); len(n) != 2 {
		t.Errorf("the copy's NICs: %v", n)
	}
	if err := other.ImportState(backup); err != nil {
		t.Fatal(err)
	}
	if d, _ := other.LiveDeployment(fw); d == nil {
		t.Error("a backup replaced the deployments")
	}
}

// The users' runtime values are in sessions.json: a deleted user's version
// stays, and the replica's copy merges them by maximum.
func TestSessions(t *testing.T) {
	dir := t.TempDir()
	g := openIn(t, dir)
	const id = 3
	for range 4 {
		g.Revoke(id)
	}
	g.UseTOTPStep(id, 77)
	g.SetTOTPPending(id, "PEND")
	got := &models.User{Base: models.Base{ID: id}}
	if openIn(t, dir).Runtime(got); got.TokenVersion != 4 || got.TOTPLastStep != 77 || got.TOTPPending != "PEND" {
		t.Fatalf("reopened: %+v", got)
	}

	// The copy the replica takes: each value the larger.
	other := openIn(t, t.TempDir())
	other.changeSession(id, func(r *sessionRec) bool { r.TokenVersion, r.TOTPLastStep = 9, 5; return true })
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
	merged := &models.User{Base: models.Base{ID: id}}
	other.Runtime(merged)
	if merged.TokenVersion != 9 || merged.TOTPLastStep != 77 {
		t.Errorf("merged: %+v", merged)
	}

	// Generations only rise.
	g.SetGeneration(fw, 5)
	g.SetGeneration(fw, 2)
	if gens, _ := openIn(t, dir).Generations(); gens[fw] != 5 {
		t.Errorf("generations: %v", gens)
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

// The deployments are a log in a file: a new Store on the directory has
// them, a change of status is a line of its own, a last line cut short by a
// crash is ignored, and pruning keeps what a firewall runs.
func TestDeploymentLog(t *testing.T) {
	dir := t.TempDir()
	g := openIn(t, dir)
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

	again := openIn(t, dir)
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
	cut := openIn(t, dir)
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
	reopened := openIn(t, dir)
	if recent, _ = reopened.RecentDeployments(0); len(recent) != 2 {
		t.Errorf("pruning was not written: %+v", recent)
	}
}

// A pending deployment can be rolled back: what then runs is the newest
// settled one, however old, and pruning at the default settings (a year)
// must leave it.
func TestPruneKeepsTheRollbackTarget(t *testing.T) {
	dir := t.TempDir()
	g := openIn(t, dir)
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
	a := openIn(t, dir)
	b := openIn(t, dir)
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

// A write whose lock can't be taken is refused, never done unlocked.
func TestWriteNeedsLock(t *testing.T) {
	dir := t.TempDir()
	f := NewFiles(dir)
	if err := os.Mkdir(filepath.Join(dir, ".records.lock"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := f.SetLastCommit(7); err == nil || !strings.Contains(err.Error(), "locking") {
		t.Fatalf("write without the lock: %v", err)
	}
}
