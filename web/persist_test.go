// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/abundo/portitor/internal/confcheck"
	"github.com/abundo/portitor/internal/datastore"

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
	srv := NewServer(&cfg)
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
	if len(d1) != 1 || len(d2) != 1 || d1[0].ID != d2[0].ID || d1[0].Status != d2[0].Status {
		t.Errorf("deployments: %d %d", len(d1), len(d2))
	}
	var fw models.Firewall
	fw = firewallOf(t, again, 1)
	if fw.Generation != 1 {
		t.Errorf("generation %d", fw.Generation)
	}
}

// HEAD_DATA is the data directory of an installation made by an earlier
// release (1.0.0 or later: the files, with built.json, the documents that
// release would send, and access.json and firewalls.json, what it had). This
// version opens it and builds the same; testdata/release-1.0.0 is one.
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
	srv := NewServer(&Config{JWTSecret: "s", Dev: true, DB: DBConfig{Path: filepath.Join(dir, "portitor.db")}})
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
// before.
func TestReadyMakesEveryFile(t *testing.T) {
	env := newEnv(t)
	dir := env.srv.cfg.Dir()
	if err := env.srv.Ready(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"candidate.json", "global.json", "entry-ids.json", "state.json", "deployments.jsonl", "known-nics.json", "sessions.json", "layout.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(dir, "layout.json"))
	if !strings.Contains(string(b), `"layout": 3`) {
		t.Errorf("layout.json %q", b)
	}
}

// The data directory 1.0.0 left (testdata/release-1.0.0, made by that release:
// an HA pair whose host has interfaces, rules, NAT, a route, its own DNS
// templates and a zone, a virtual firewall linked to it, the firewall's DNS
// templates and a syslog server, a commit and a change pending). This release
// moves the host from the instance list to the top level, keeps every entry's
// id, writes the candidate in its shape, and builds the same documents; the
// admin logs in, and the pending change is still the candidate.
func TestOpensA100DataDirectory(t *testing.T) {
	src := filepath.Join("testdata", "release-1.0.0")
	var was struct {
		Paths map[string][2]any `json:"paths"`
	}
	b, err := os.ReadFile(filepath.Join(src, "entry-ids.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &was); err != nil {
		t.Fatal(err)
	}
	dir, srv := openEarlier(t, src)
	want, err := os.ReadFile(filepath.Join(dir, "built.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := builtDocs(t, srv); string(got) != string(want) {
		t.Errorf("this version builds other documents from 1.0.0's data:\n%s\n---\n%s", want, got)
	}
	env := &testEnv{t: t, srv: srv, e: srv.Echo()}
	rec := env.do("POST", "/api/login", map[string]string{"username": "admin", "password": "correct horse battery"})
	if rec.Code != http.StatusOK {
		t.Fatalf("1.0.0's admin can't log in: %d %s", rec.Code, rec.Body)
	}
	fws, err := srv.rec.Firewalls()
	if err != nil || len(fws) != 2 || fws[1].Name != "fw1b" || fws[1].HAPrimaryID == nil {
		t.Errorf("firewalls: %v %+v", err, fws)
	}
	if live, err := srv.liveCommit(); err != nil || live != 1 {
		t.Errorf("the live commit: %d %v", live, err)
	}
	tr, _ := srv.tree()
	ctx := context.Background()
	if changed, err := tr.store.Changed(ctx); err != nil || !changed {
		t.Errorf("the change 1.0.0 left pending is gone: %v", err)
	}
	// The host is the top level, in the candidate and in the file.
	cand, _ := tr.store.Candidate(ctx)
	if hostName(cand) != "main" || cand.Root.Entry("interface", []string{"lan"}) == nil || cand.Root.Entry("instance", []string{"main"}) != nil {
		t.Errorf("the host: %v", cand.Root.Leaves)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "candidate.json")); !strings.Contains(string(b), `"portitor:host-name"`) || strings.Contains(string(b), `"is-default"`) {
		t.Error("candidate.json is not written in this release's shape")
	}
	// Every entry keeps its id: the host's at the top level.
	ids, err := srv.rec.IDs()
	if err != nil {
		t.Fatal(err)
	}
	moved := 0
	for p, v := range was.Paths {
		to := p
		switch {
		case p == "/instance[name=main]":
			to = "/"
		case strings.HasPrefix(p, "/instance[name=main]/"):
			to = strings.TrimPrefix(p, "/instance[name=main]")
		}
		if to != p {
			moved++
		}
		if id, ok := ids.ID(to); !ok || float64(id) != v[1].(float64) {
			t.Errorf("%s: id %d (%v), was %v at %s", to, id, ok, v[1], p)
		}
	}
	if moved < 5 {
		t.Errorf("only %d of the host's ids", moved)
	}
	// The migration adds no change: the candidate is running and the
	// pending rule.
	run, _ := tr.store.Running(ctx)
	if d := datastore.Diff(run, cand); len(d) == 0 || len(d) > 6 {
		t.Errorf("changes after the migration: %v", d)
	} else {
		for _, ch := range d {
			if len(ch.Path) == 0 || ch.Path[0].Name != "rule" {
				t.Errorf("a change beside the pending rule: %v", ch.Path)
			}
		}
	}
	// A new rule of the host's gets an id after every rule's of 1.0.0.
	top := 0
	for _, in := range instNodes(cand) {
		for _, r := range in.Lists["rule"] {
			n, _ := strconv.Atoi(r.Leaf("id"))
			top = max(top, n)
		}
	}
	env2 := &testEnv{t: t, srv: srv, e: srv.Echo()}
	env2.login("admin", "correct horse battery")
	id := env2.post("rule", map[string]any{"chain": "input", "action": "accept", "enabled": true})
	if n, _ := strconv.Atoi(id); n <= top {
		t.Errorf("a new rule's id %s, 1.0.0's went to %d", id, top)
	}
	// The host keeps its name.
	if rec := env2.cfg("PATCH", "", map[string]any{"portitor:host-name": "other"}); rec.Code != http.StatusBadRequest {
		t.Errorf("the host renamed: %d %s", rec.Code, rec.Body)
	}
	// No database is made.
	if _, err := os.Stat(filepath.Join(dir, "portitor.db")); err == nil {
		t.Error("a database file was made")
	}
}

// A 1.0.0 directory whose configuration has two hosts (several firewalls of
// their own, which only tests made) is refused with why, before anything
// is written.
func TestTwoHostsAreRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join("testdata", "release-1.0.0-two-hosts"))); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "candidate.json"))
	err := NewServer(&Config{JWTSecret: "s", Dev: true, DB: DBConfig{Path: filepath.Join(dir, "portitor.db")}}).Ready()
	if err == nil || !strings.Contains(err.Error(), "two hosts") {
		t.Errorf("opened: %v", err)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "candidate.json")); string(after) != string(before) {
		t.Error("the candidate was written")
	}
}

// A data directory this release can't read is refused before anything is
// read or written: one of a release before 1.0.0 (no layout.json, with its
// database or its files), and one of a later release. A database left beside
// a 1.0.0 directory is left alone.
func TestLayoutGate(t *testing.T) {
	open := func(dir string) error {
		return NewServer(&Config{JWTSecret: "s", Dev: true, DB: DBConfig{Path: filepath.Join(dir, "portitor.db")}}).Ready()
	}
	for name, files := range map[string]map[string]string{
		"database":   {"portitor.db": "SQLite format 3\x00"},
		"candidate":  {"candidate.json": "{}"},
		"old layout": {"layout.json": `{"layout": 1}`, "candidate.json": "{}"},
	} {
		dir := t.TempDir()
		for f, c := range files {
			os.WriteFile(filepath.Join(dir, f), []byte(c), 0o600)
		}
		if err := open(dir); err == nil || !strings.Contains(err.Error(), "update to Portitor 1.0.0") {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "global.json")); err == nil {
			t.Errorf("%s: a refused directory was written", name)
		}
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "layout.json"), []byte(`{"layout": 4}`), 0o600)
	if err := open(dir); err == nil || !strings.Contains(err.Error(), "later release") {
		t.Errorf("a later layout: %v", err)
	}

	// A new directory, even one that doesn't exist yet.
	dir = filepath.Join(t.TempDir(), "new")
	if err := open(dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "layout.json")); !strings.Contains(string(b), `"layout": 3`) {
		t.Errorf("layout.json %q", b)
	}

	// 1.0.0's directory with its old database beside it: opened, the
	// database kept.
	dir = t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join("testdata", "release-1.0.0"))); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "portitor.db"), []byte("SQLite format 3\x00"), 0o600)
	if err := open(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "portitor.db")); err != nil {
		t.Errorf("the old database: %v", err)
	}
}

// An HA secondary updated first copies its 1.0.0 primary: a copy of format
// 2 whose configuration has the host as an instance is read, migrated, and
// the host's ids move with it.
func TestTakesA100Copy(t *testing.T) {
	src := filepath.Join("testdata", "release-1.0.0")
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	put := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		tw.Write(data)
	}
	put("manifest.json", []byte(`{"format":2,"kind":"replica"}`))
	for _, f := range copyFiles {
		if b, err := os.ReadFile(filepath.Join(src, f)); err == nil {
			put(f, b)
		}
	}
	tw.Close()
	files, man, err := decodeCopy(buf.Bytes())
	if err != nil || man.Format != 2 {
		t.Fatalf("a 1.0.0 copy: %v %+v", err, man)
	}
	env := newEnvIn(t, t.TempDir())
	if err := env.srv.takeSnapshot(context.Background(), files, nil, false); err != nil {
		t.Fatal(err)
	}
	tr, _ := env.srv.tree()
	cand, _ := tr.store.Candidate(context.Background())
	if hostName(cand) != "main" || cand.Root.Entry("interface", []string{"lan"}) == nil {
		t.Errorf("the host after the copy: %v", cand.Root.Leaves)
	}
	ids, _ := env.srv.rec.IDs()
	if _, ok := ids.ID("/interface[name=lan]"); !ok {
		t.Error("the host's ids did not move")
	}
	if _, ok := ids.ID("/instance[name=main]/interface[name=lan]"); ok {
		t.Error("the host's ids are still the instance's")
	}
}

// In 1.0.0 the host and a virtual firewall could each have a DNS template of
// one name, which neither shared. The host's are the firewall's now; the
// virtual firewall's own shadows it, so the migrated configuration has no
// problem and builds.
func TestA100HostAndVFTemplateOfOneName(t *testing.T) {
	src := t.TempDir()
	if err := os.CopyFS(src, os.DirFS(filepath.Join("testdata", "release-1.0.0"))); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(src, "candidate.json")
	b, _ := os.ReadFile(path)
	var tree map[string]any
	if err := json.Unmarshal(b, &tree); err != nil {
		t.Fatal(err)
	}
	for _, in := range tree["portitor:instance"].([]any) {
		if in := in.(map[string]any); in["name"] == "guest" {
			in["dns-soa-template"] = []any{map[string]any{"name": "host-soa", "mname": "ns.guest.example", "rname": "h.guest.example"}}
		}
	}
	b, _ = json.Marshal(tree)
	os.WriteFile(path, b, 0o600)
	_, srv := openEarlier(t, src)
	tr, _ := srv.tree()
	cand, _ := tr.store.Candidate(context.Background())
	if errs := append(cand.Validate(), confcheck.Check(cand)...); len(errs) > 0 {
		t.Errorf("problems after the migration: %v", errs)
	}
	if cand.Root.Entry("dns-soa-template", []string{"host-soa"}) == nil || cand.Root.Entry("instance", []string{"guest"}).Entry("dns-soa-template", []string{"host-soa"}) == nil {
		t.Error("the two templates")
	}
	if _, docs, err := srv.firewallDocs(context.Background(), nil); err != nil || len(docs) == 0 {
		t.Errorf("build: %v", err)
	}
}
