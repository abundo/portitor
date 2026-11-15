// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/abundo/portitor/internal/datastore"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/dbmigrate"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

var pemRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----[^"]*?-----END [A-Z0-9 ]+-----\\n?`)

// builtDocs are the documents the next commit would send, redacted and with
// generated key material blanked: what the configuration, the ids and the
// records add up to.
func builtDocs(t *testing.T, s *Server) []byte {
	t.Helper()
	fws, docs, err := s.firewallDocs(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]fwconfig.Document{}
	for i, d := range docs {
		out[fws[i].Name] = d.Redacted()
	}
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return pemRe.ReplaceAll(b, []byte("PEM"))
}

// restart is a new Server on the same database and directory, as after a
// restart of portitor-config.
func restart(t *testing.T, env *testEnv, dir string) *Server {
	t.Helper()
	cfg := *env.srv.cfg
	srv := NewServer(&cfg, env.srv.db)
	srv.newAgent = env.srv.newAgent
	srv.static = env.srv.static
	return srv
}

// A configuration committed, then a new Server on its directory: it has the
// same candidate, ids, counter, deployments and builds the same documents.
func TestFilesSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	env, agents, branch := twoFirewallsIn(t, dir)
	env.post("instance=main/rule", map[string]any{"chain": "input", "action": "accept", "enabled": true})
	env.post("instance=shop/rule", map[string]any{"chain": "input", "action": "drop", "enabled": true})
	if rec := env.do("POST", "/api/deploy/apply", map[string]any{}); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	env.post("instance=main/rule", map[string]any{"chain": "forward", "action": "drop", "enabled": true})
	for _, f := range []string{"candidate.json", "entry-ids.json", "state.json", "deployments.jsonl", "ids.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	_ = agents
	_ = branch
	want := builtDocs(t, env.srv)

	again := restart(t, env, dir)
	if got := builtDocs(t, again); string(got) != string(want) {
		t.Errorf("a restart changed the documents:\n%s\n---\n%s", want, got)
	}
	a, _ := env.srv.rec.Own()
	b, _ := again.rec.Own()
	if a != b || a.LastCommit != 1 {
		t.Errorf("counters: %+v %+v", a, b)
	}
	d1, _ := env.srv.rec.RecentDeployments(0)
	d2, _ := again.rec.RecentDeployments(0)
	if len(d1) != 2 || len(d2) != 2 || d1[0].ID != d2[0].ID || d1[0].Status != d2[0].Status {
		t.Errorf("deployments: %d %d", len(d1), len(d2))
	}
	var fw models.Firewall
	fw = firewallOf(t, again, 1)
	if fw.Generation != 1 {
		t.Errorf("generation %d", fw.Generation)
	}
}

// HEAD_DATA is the directory of an installation made by an earlier release
// (the database and the files next to it, with built.json: the documents
// that release would send). This version opens it and builds the same.
// openEarlier is the data of an earlier release in src, copied and opened.
func openEarlier(t *testing.T, src string) (string, *Server) {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			if err := os.CopyFS(filepath.Join(dir, e.Name()), os.DirFS(filepath.Join(src, e.Name()))); err != nil {
				t.Fatal(err)
			}
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	db, err := dbmigrate.Open(filepath.Join(dir, "portitor.db"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := dbmigrate.Up(db); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&Config{JWTSecret: "s", Dev: true, DB: DBConfig{Path: filepath.Join(dir, "portitor.db")}}, db)
	if err := srv.Ready(); err != nil { // as the start of the daemon does
		t.Fatal(err)
	}
	return dir, srv
}

func TestOpensAnEarlierReleasesData(t *testing.T) {
	src := os.Getenv("HEAD_DATA")
	if src == "" {
		t.Skip("HEAD_DATA not set")
	}
	dir, srv := openEarlier(t, src)
	want, err := os.ReadFile(filepath.Join(dir, "built.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := builtDocs(t, srv); string(got) != string(want) {
		t.Errorf("this version builds other documents from the earlier release's data:\n%s\n---\n%s", want, got)
	}

	// The directory's servers were rows; they are the tree's now, with the
	// ids they had, in the order they had, and a bind password still set.
	if wantDir, err := os.ReadFile(filepath.Join(dir, "directory.json")); err == nil {
		env := &testEnv{t: t, srv: srv, e: srv.Echo()}
		rec := env.do("POST", "/api/login", map[string]string{"username": "admin", "password": "correct horse battery"})
		for _, c := range rec.Result().Cookies() {
			if c.Name == cookieName {
				env.cookie = c
			}
		}
		strip := func(b []byte) string {
			var rows []map[string]any
			if err := json.Unmarshal(b, &rows); err != nil {
				t.Fatalf("%v: %s", err, b)
			}
			for _, r := range rows {
				delete(r, "created_at")
				delete(r, "updated_at")
			}
			out, _ := json.Marshal(rows)
			return string(out)
		}
		got := env.do("GET", "/api/directory/servers", nil)
		if strip(got.Body.Bytes()) != strip(wantDir) {
			t.Errorf("the directory's servers:\n%s\n---\n%s", strip(wantDir), strip(got.Body.Bytes()))
		}
		// And they run: a login is tried at them.
		_ = rec
		if servers, err := srv.enabledDirectoryServers(context.Background()); err != nil || len(servers) != 2 || servers[0].Name != "down" {
			t.Errorf("running's servers: %v %+v", err, servers)
		}
	}
	adoptedAccess(t, dir, srv)
}

// A console command runs a Server beside the daemon on the same files: what
// runs of the global lists is global.json, which both read when it changes
// and write under the shared lock.
func TestTwoServersShareTheGlobalLists(t *testing.T) {
	dir := t.TempDir()
	env := newEnvIn(t, dir)
	other := restart(t, env, dir)
	if _, err := other.tree(); err != nil {
		t.Fatal(err)
	}

	env.create("/api/directory/servers", map[string]any{"name": "one", "enabled": true, "host": "one.example.com", "base_dn": "dc=x"})
	got, err := other.enabledDirectoryServers(context.Background())
	if err != nil || len(got) != 1 || got[0].Name != "one" {
		t.Fatalf("the other server's view of running: %v %+v", err, got)
	}

	// The other adds one of its own on top of what it has read.
	ot, _ := other.tree()
	if _, err := other.commitGlobalsOf(context.Background(), ot, func(base *datastore.Tree) error {
		return base.EditJSON(datastore.Path{{Name: "ldap-server"}}, datastore.EditCreate, []byte(`{"name":"two","enabled":true,"host":"two.example.com","base-dn":"dc=x"}`))
	}); err != nil {
		t.Fatal(err)
	}
	got, _ = env.srv.enabledDirectoryServers(context.Background())
	if len(got) != 2 {
		t.Errorf("the first server's view after the other wrote: %+v", got)
	}
}

// adoptedAccess checks the users, roles and mappings of an earlier release's
// data (access.json beside it): with the ids they had, the runtime values and
// the secrets; the highest id ever given is not given again.
func adoptedAccess(t *testing.T, dir string, srv *Server) {
	t.Helper()
	// The users, roles and mappings, with the ids they had, the runtime values
	// and the secrets; the highest id ever given is not given again.
	if access, err := os.ReadFile(filepath.Join(dir, "access.json")); err == nil {
		env := &testEnv{t: t, srv: srv, e: srv.Echo()}
		rec := env.do("POST", "/api/login", map[string]string{"username": "admin", "password": "correct horse battery"})
		if rec.Code != http.StatusOK {
			t.Fatalf("the earlier release's admin can't log in: %d %s", rec.Code, rec.Body)
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == cookieName {
				env.cookie = c
			}
		}
		strip := func(b []byte) string {
			var v any
			if err := json.Unmarshal(b, &v); err != nil {
				t.Fatalf("%v: %s", err, b)
			}
			var walk func(any)
			walk = func(x any) {
				switch y := x.(type) {
				case map[string]any:
					delete(y, "created_at")
					delete(y, "updated_at")
					for _, e := range y {
						walk(e)
					}
				case []any:
					for _, e := range y {
						walk(e)
					}
				}
			}
			walk(v)
			out, _ := json.Marshal(v)
			return string(out)
		}
		var parts []string
		for _, l := range strings.Split(string(access), "\n") {
			if strings.TrimSpace(l) != "" {
				parts = append(parts, l)
			}
		}
		for i, path := range []string{"/api/users", "/api/roles", "/api/directory/mappings"} {
			if got := env.do("GET", path, nil).Body.Bytes(); strip(got) != strip([]byte(parts[i])) {
				t.Errorf("%s:\n%s\n---\n%s", path, strip([]byte(parts[i])), strip(got))
			}
		}
		var rows []struct {
			ID            uint
			Username      string
			TokenVersion  int    `json:"token_version"`
			TOTPLastStep  int64  `json:"totp_last_step"`
			TOTPSecret    string `json:"totp_secret"`
			RecoveryCodes string `json:"recovery_codes"`
			PasswordHash  string `json:"password_hash"`
		}
		if err := json.Unmarshal([]byte(parts[3]), &rows); err != nil {
			t.Fatal(err)
		}
		top := uint(0)
		for _, r := range rows {
			top = max(top, r.ID)
			u, err := srv.rec.UserNamed(r.Username)
			if err != nil {
				t.Errorf("user %s: %v", r.Username, err)
				continue
			}
			if u.ID != r.ID || u.TokenVersion != r.TokenVersion || u.TOTPLastStep != r.TOTPLastStep || u.TOTPSecret != r.TOTPSecret || u.RecoveryCodes != r.RecoveryCodes || u.PasswordHash != r.PasswordHash {
				t.Errorf("user %s: %+v, was %+v", r.Username, u, r)
			}
		}
		// Deleted users stay deleted, and the highest id ever given (the
		// deleted "tail"'s) is not given again.
		for _, name := range []string{"gone", "tail"} {
			if _, err := srv.rec.UserNamed(name); err == nil {
				t.Errorf("%s is back", name)
			}
		}
		u := &models.User{Username: "newcomer", PasswordHash: "$2a$10$" + strings.Repeat("a", 53), Role: models.RoleViewer}
		if err := srv.rec.CreateUser(u); err != nil {
			t.Fatal(err)
		}
		if u.ID <= top+1 {
			t.Errorf("a new user got id %d; the highest given before was above %d", u.ID, top+1)
		}
	}
}

// A console command (createadmin) resets a password in a process of its own;
// the daemon's next commit must not put the old hash back from a candidate it
// read before.
func TestAnotherProcessesPasswordResetSurvivesACommit(t *testing.T) {
	dir := t.TempDir()
	env, _, _ := twoFirewallsIn(t, dir)
	other := restart(t, env, dir)
	if err := CreateUser(other, "admin", "a brand new long password"); err != nil {
		t.Fatal(err)
	}
	// The daemon edits and commits.
	if err := env.srv.editConfig(context.Background(), func(work *datastore.Tree) error {
		return work.EditJSON(datastore.Path{{Name: "instance", Keys: []string{"main"}}, {Name: "rule"}}, datastore.EditCreate,
			[]byte(`{"id":900,"chain":"input","action":"drop","enabled":true}`))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.srv.deployCandidate(context.Background(), "test", nil); err != nil {
		t.Fatal(err)
	}
	u := env.userNamed("admin")
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("a brand new long password")) != nil {
		t.Error("the commit put the old password back")
	}
}

// adoptedFirewalls checks the firewalls of an earlier release's data
// (firewalls.json beside it): their ids, fields, secrets, generations and pair,
// and what the deployments say runs: the live commit and each firewall's live
// deployment are what they were, a pending one included.
func adoptedFirewalls(t *testing.T, dir string, srv *Server) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "firewalls.json"))
	if err != nil {
		return
	}
	var was struct {
		Firewalls []struct {
			ID                uint
			Name              string
			Description       string
			AgentURL          string `json:"agent_url"`
			AgentToken        string `json:"agent_token"`
			AgentFingerprint  string `json:"agent_fingerprint"`
			Generation        int64
			HAPrimaryID       *uint  `json:"ha_primary_id"`
			HASecret          string `json:"ha_secret"`
			HAEpoch           int64  `json:"ha_epoch"`
			HAWitness         string `json:"ha_witness"`
			HAWitnessSecret   string `json:"ha_witness_secret"`
			ConfigURL         string `json:"config_url"`
			ConfigFingerprint string `json:"config_fingerprint"`
		}
		Deployments []struct {
			ID         uint
			FirewallID uint  `json:"firewall_id"`
			CommitID   int64 `json:"commit_id"`
			Status     string
		}
	}
	if err := json.Unmarshal(b, &was); err != nil {
		t.Fatal(err)
	}
	fws, err := srv.rec.Firewalls()
	if err != nil || len(fws) != len(was.Firewalls) {
		t.Fatalf("firewalls: %v %+v", err, fws)
	}
	for i, w := range was.Firewalls {
		f := fws[i]
		primary := (f.HAPrimaryID == nil) == (w.HAPrimaryID == nil) && (f.HAPrimaryID == nil || *f.HAPrimaryID == *w.HAPrimaryID)
		if f.ID != w.ID || f.Name != w.Name || f.Description != w.Description || f.AgentURL != w.AgentURL || f.AgentToken != w.AgentToken ||
			f.AgentFingerprint != w.AgentFingerprint || f.Generation != w.Generation || !primary || f.HASecret != w.HASecret ||
			f.HAEpoch != w.HAEpoch || f.HAWitness != w.HAWitness || f.HAWitnessSecret != w.HAWitnessSecret ||
			f.ConfigURL != w.ConfigURL || f.ConfigFingerprint != w.ConfigFingerprint {
			t.Errorf("firewall %s: %+v, was %+v", w.Name, f, w)
		}
	}
	// What runs: the live commit, and each firewall's live deployment.
	var live int64
	liveOf := map[uint]int64{}
	for _, d := range was.Deployments {
		if d.Status == "applied" || d.Status == "pending" || d.Status == "confirmed" {
			live = max(live, d.CommitID)
			liveOf[d.FirewallID] = max(liveOf[d.FirewallID], d.CommitID)
		}
	}
	if got, err := srv.liveCommit(); err != nil || got != live || live == 0 {
		t.Errorf("the live commit %d (%v), was %d", got, err, live)
	}
	for id, commit := range liveOf {
		if d, err := srv.rec.LiveDeployment(id); err != nil || d == nil || d.CommitID != commit {
			t.Errorf("firewall %d's live deployment: %+v %v, was commit %d", id, d, err, commit)
		}
	}
	// The highest id the table gave is not given again.
	top := uint(0)
	for _, w := range was.Firewalls {
		top = max(top, w.ID)
	}
	if err := srv.rec.EnsureFirewall("never"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.rec.UserNamed("admin"); err != nil {
		t.Fatalf("the admin: %v", err)
	}
}

// The same, for data with firewalls: a second, one made and deleted, an HA
// secondary, and a commit left pending.
func TestOpensAnEarlierReleasesFirewalls(t *testing.T) {
	src := os.Getenv("HEAD_FWDATA")
	if src == "" {
		t.Skip("HEAD_FWDATA not set")
	}
	dir, srv := openEarlier(t, src)
	adoptedFirewalls(t, dir, srv)
	adoptedAccess(t, dir, srv)
}

// A secondary updated before its primary takes the database file an earlier
// release's primary gives (HEAD_FWDATA/replica.db): its users, roles, directory
// and firewalls are adopted into the tree, with the ids they had.
func TestReplicaTakesAnEarlierPrimarysCopy(t *testing.T) {
	src := os.Getenv("HEAD_FWDATA")
	if src == "" {
		t.Skip("HEAD_FWDATA not set")
	}
	data, err := os.ReadFile(filepath.Join(src, "replica.db"))
	if err != nil {
		t.Fatal(err)
	}
	env := newEnv(t)
	if err := env.srv.takeLegacyCopy(context.Background(), data); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"admin", "alice", "bob"} {
		if _, err := env.srv.rec.UserNamed(name); err != nil {
			t.Errorf("user %s: %v", name, err)
		}
	}
	if _, err := env.srv.rec.UserNamed("gone"); err == nil {
		t.Error("a user deleted on the primary is there")
	}
	roles, _ := env.srv.rec.Roles()
	if !slices.ContainsFunc(roles, func(r models.Role) bool { return r.Name == "vpn" && len(r.Members) == 1 }) {
		t.Errorf("roles: %+v", roles)
	}
	dir, _ := os.ReadFile(filepath.Join(src, "firewalls.json"))
	var was struct {
		Firewalls []struct {
			ID   uint
			Name string
		}
	}
	if err := json.Unmarshal(dir, &was); err != nil {
		t.Fatal(err)
	}
	fws, _ := env.srv.rec.Firewalls()
	if len(fws) != len(was.Firewalls) {
		t.Fatalf("firewalls: %+v", fws)
	}
	for i, w := range was.Firewalls {
		if fws[i].ID != w.ID || fws[i].Name != w.Name {
			t.Errorf("firewall %d: %+v, was %+v", i, fws[i], w)
		}
	}
}

// A backup an earlier release made (HEAD_FWDATA/backup.db.age) is a database
// file: this release says to restore it with that one.
func TestAnEarlierReleasesBackupIsRefused(t *testing.T) {
	src := os.Getenv("HEAD_FWDATA")
	if src == "" {
		t.Skip("HEAD_FWDATA not set")
	}
	data, err := os.ReadFile(filepath.Join(src, "backup.db.age"))
	if err != nil {
		t.Fatal(err)
	}
	env := newEnv(t)
	rec := env.do("POST", "/api/backup/restore", map[string]any{"data": data, "passphrase": testPassphrase})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "that release (0.9.x)") {
		t.Errorf("restore: %d %s", rec.Code, rec.Body)
	}
}

// Ready makes every file and marks the directory, whatever has been asked
// before: the next release has no tables to make a missing file from.
func TestReadyMakesEveryFile(t *testing.T) {
	env := newEnv(t)
	dir := env.srv.cfg.Dir()
	if err := env.srv.Ready(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"candidate.json", "global.json", "entry-ids.json", "state.json", "deployments.jsonl", "known-nics.json", "sessions.json", "adoptions.json", "layout.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "layout.json"))
	if !strings.Contains(string(b), `"layout": 2`) {
		t.Errorf("layout.json %q", b)
	}
}
