// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/cli"
	"github.com/abundo/portitor/internal/confcheck"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/netconf"
	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/models"
)

// The configuration tree (dev/design-model-driven.md): the YANG schema's
// datastore, which every frontend edits in one candidate (candidate.json
// in the data directory) and commits. A commit keeps the configuration it
// deploys (deployed/<commit>-config.json); running is the live commit's.

type treeState struct {
	coreOnce sync.Once
	err      error
	// migrateOnce: migrateHost, once core is there (it reads running).
	migrateOnce sync.Once
	migrateErr  error
	schema      *schema.Node
	mapping     *sqlmap.Mapping
	store       *datastore.Store

	dir       string            // the data directory, where the candidate and ids.json are; "" in memory
	idMarks   map[string]uint64 // assignID's high-water marks, by list path
	runMu     sync.Mutex
	runCommit int64
	running   *datastore.Tree
	runStamp  datastore.FileStamp // of global.json, when running was read
	globals   []string            // the global lists (globals.go)
}

// core is the configuration tree's set-up that needs nothing else: the
// schema, the mapping, the store (which reads running lazily). Running and
// what it reads use it, so the adoptions that tree() makes after it can read
// running too.
func (s *Server) core() (*treeState, error) {
	t := &s.treeState
	t.coreOnce.Do(func() {
		if t.schema, t.err = schema.Load(); t.err != nil {
			return
		}
		if t.mapping, t.err = sqlmap.New(t.schema); t.err != nil {
			return
		}
		dir := configDir(s.cfg)
		t.dir = dir
		if t.err = checkLayout(dir, s.cfg.DB.Path); t.err != nil {
			return
		}
		t.globals = slices.Clone(globalLists)
		t.store = datastore.NewStore(t.schema, treeBackend{s}, dir)
		t.store.Normalize, t.store.Check = confcheck.Normalize, confcheck.Check
		// The roles name the virtual firewalls: they follow a rename, and
		// a new one gets its role. New entries get their ids.
		t.store.OnChange = func(c *datastore.Tree) error { return s.rec.FollowChange(t.mapping, c) }
	})
	return t, t.err
}

// migrateHost finishes, once, what reading a configuration of 1.0.0 began
// (datastore.Migrate, hostToRoot): the candidate is written again in this
// release's shape, and the kept ids of the host's entries move with them
// to the top level, so they keep their ids (a rule's is its connection
// mark).
func (s *Server) migrateHost(t *treeState) error {
	ctx := context.Background()
	cand, err := t.store.Candidate(ctx)
	if err != nil {
		return err
	}
	if !cand.Migrated {
		return nil
	}
	if err := s.migrateEntryIDs(cand); err != nil {
		return err
	}
	cand.Migrated = false
	return t.store.Replace(ctx, cand)
}

// migrateEntryIDs moves the kept ids of the host of tree, a tree read in
// 1.0.0's shape (Migrated), from the instance it was (/instance[name=<host>])
// to the top level. An id already kept at the new path stays.
func (s *Server) migrateEntryIDs(tree *datastore.Tree) error {
	host := tree.Root.Leaf("host-name")
	if !tree.Migrated || host == "" || tree.Root.Entry("instance", []string{host}) != nil {
		return nil
	}
	return s.rec.UpdateIDs(func(ids sqlmap.IDs) {
		type kept struct {
			tbl string
			id  int64
		}
		have := map[string]kept{}
		var paths []string
		ids.Each("/instance[", func(p, tbl string, id int64) {
			paths = append(paths, p)
			have[p] = kept{tbl, id}
		})
		datastore.MigrateIDPaths(paths, host, func(from, to string) {
			if _, taken := ids.ID(to); taken {
				return
			}
			k := have[from]
			ids.Delete(from)
			ids.Set(to, k.tbl, k.id)
		})
	})
}

// Ready sets the configuration up now (tree), refusing a data directory
// this release can't read before the first request; called once a Server is
// made, before it serves.
func (s *Server) Ready() error {
	if _, err := s.tree(); err != nil {
		return err
	}
	// Every file now, and the mark of the layout.
	if err := s.rec.Seed(); err != nil {
		return err
	}
	// A new installation has its first firewall from the start (set-agent
	// sets its agent before anything else runs), as the database's
	// migrations of earlier releases gave it.
	if err := s.ensureFirewall(); err != nil {
		return err
	}
	return s.writeLayout()
}

// layoutVersion is the layout of the data directory: 2 has the files
// (candidate, global lists, ids, deployments, ...) and no configuration in the
// database. 1.0.0 wrote it first, after taking what the database held into
// the files; a directory without it is older and refused (checkLayout). 3
// (1.1.0) has the host at the top level of the configuration, which 1.0.0
// would misread, so it refuses it; this release reads 2 and migrates it
// (migrateHost) until 1.2.0.
const layoutVersion = 3

// layoutOldest is the oldest layout this release reads.
const layoutOldest = 2

// errBefore100 refuses a data directory of a release before 1.0.0.
func errBefore100(dir string) error {
	return fmt.Errorf("the data directory %s is from a release before 1.0.0, which kept its data in a database this release no longer reads: update to Portitor 1.0.0 and start it once, then to this release", dir)
}

// checkLayout refuses a data directory this release can't read: one of a
// release before 1.0.0 (no layout.json, but the database or the files there)
// or of a later release (a higher layout). A new one gets its layout.json now,
// so that a restart before Ready still knows it. dbPath is the database file
// of earlier releases (db.path).
func checkLayout(dir, dbPath string) error {
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, "layout.json")
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		var l struct {
			Layout int `json:"layout"`
		}
		if err := json.Unmarshal(b, &l); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		switch {
		case l.Layout > layoutVersion:
			return fmt.Errorf("the data directory %s has layout %d, of a later release (this one reads %d): update Portitor", dir, l.Layout, layoutVersion)
		case l.Layout < layoutOldest:
			return errBefore100(dir)
		}
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	old := []string{"candidate.json", "global.json", "entry-ids.json", "deployed"}
	if dbPath != "" {
		old = append(old, filepath.Base(dbPath))
	}
	for _, name := range old {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return errBefore100(dir)
		}
	}
	// A new installation.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return datastore.WriteFile(path, []byte(fmt.Sprintf("{\"layout\": %d}\n", layoutVersion)))
}

// writeLayout marks the directory as having layout layoutVersion.
func (s *Server) writeLayout() error {
	dir := s.cfg.Dir()
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, "layout.json")
	want := fmt.Sprintf("{\"layout\": %d}\n", layoutVersion)
	if got, err := os.ReadFile(path); err == nil && string(got) == want {
		return nil
	}
	return datastore.WriteFile(path, []byte(want))
}

// tree is the configuration tree, set up on first use (core).
func (s *Server) tree() (*treeState, error) {
	t, err := s.core()
	if err != nil {
		return nil, err
	}
	t.migrateOnce.Do(func() { t.migrateErr = s.migrateHost(t) })
	return t, t.migrateErr
}

type treeBackend struct{ s *Server }

// Initial is the first candidate: running.
func (b treeBackend) Initial(ctx context.Context) (*datastore.Tree, error) {
	return b.Running(ctx)
}

// Running is the live commit's configuration, or an empty one before the
// first commit.
func (b treeBackend) Running(context.Context) (*datastore.Tree, error) {
	s := b.s
	// Not s.tree(): its adoptions read running.
	t, err := s.core()
	if err != nil {
		return nil, err
	}
	commit, err := s.liveCommit()
	if err != nil {
		return nil, err
	}
	// What runs of the global lists may have been written by another process.
	stamp := s.globalsStamp()
	t.runMu.Lock()
	defer t.runMu.Unlock()
	if t.running != nil && t.runCommit == commit && t.runStamp == stamp {
		return t.running.Clone(), nil
	}
	tree := datastore.New(t.schema)
	if commit > 0 {
		loaded, err := s.loadCommit(t.schema, commit)
		switch {
		case err == nil:
			tree = loaded
		case !errors.Is(err, os.ErrNotExist):
			return nil, err
		}
	}
	if err := s.overlayGlobals(t, tree); err != nil {
		return nil, err
	}
	t.running, t.runCommit, t.runStamp = tree, commit, stamp
	return tree.Clone(), nil
}

// forgetRunning drops running's cache: its commit's file has come since.
func (s *Server) forgetRunning() {
	t := &s.treeState
	t.runMu.Lock()
	t.running = nil
	t.runMu.Unlock()
}

// Commit deploys the tree, as the GUI's commit does.
func (b treeBackend) Commit(ctx context.Context, tree *datastore.Tree, o datastore.CommitOptions) (string, error) {
	s := b.s
	if s.isReplica() {
		return "", errors.New("this is the HA secondary: its configuration is a read-only copy of the primary's")
	}
	if len(o.Scope) > 0 {
		res, err := s.commitScoped(ctx, o.User, tree, o.Scope, !o.NoDeploy)
		if err != nil {
			return "", err
		}
		return res.message(), nil
	}
	if o.Validate {
		fws, err := s.firewalls()
		if err != nil {
			return "", err
		}
		var problems []string
		for _, fw := range fws {
			if _, err := s.buildDoc(builder.Input{Rec: s.rec, Tree: tree}, &fw, fw.Generation+1, o.Only); err != nil {
				problems = append(problems, firewallProblem(fws, fw, err.Error()))
			}
		}
		if len(problems) > 0 {
			return "", errors.New(strings.Join(problems, "\n"))
		}
		return "The candidate is valid.", nil
	}
	res, err := s.deploy(ctx, o.User, o.Confirm, o.Only, tree)
	if err != nil {
		var ve *fwconfig.ValidationError
		if errors.As(err, &ve) {
			return "", fmt.Errorf("the configuration is not valid:\n  %s", strings.Join(ve.Problems, "\n  "))
		}
		return "", err
	}
	msg := fmt.Sprintf("Commit %d: %s.", res.Commit, res.Status)
	for _, d := range res.Deployments {
		if d.Message != "" {
			msg += "\n  " + d.Message
		}
	}
	if res.Status == "pending" {
		msg += "\nConfirm it (confirm), or it is rolled back."
	}
	return msg, nil
}

// deployCandidate commits the candidate as the GUI's commit does.
func (s *Server) deployCandidate(ctx context.Context, user string, timeout *int) (*commitResult, error) {
	t, err := s.tree()
	if err != nil {
		return nil, err
	}
	tree, err := t.store.Prepare(ctx, "")
	if err != nil {
		return nil, err
	}
	return s.deploy(ctx, user, timeout, nil, tree)
}

// treeAccess is a user's access, by path: global admins all, global
// viewers to read; others the virtual firewalls of their roles and the
// shared objects, to read, and to change those they are admins of.
type treeAccess struct {
	a        *access
	read     map[string]bool // instance names
	write    map[string]bool
	readOnly bool
	// host is the host's name: its configuration is the top level's lists
	// and leaves that a virtual firewall has too (hostScope), global
	// admins' alone (to change; viewers read it), by either path.
	host string
}

// hostScope reports whether p is in the host's configuration, the top
// level's (or named as its instance of 1.0.0), and the path below.
func (t treeAccess) hostScope(p datastore.Path) (datastore.Path, bool) {
	if len(p) > 0 && p[0].Name == "instance" && len(p[0].Keys) == 1 && t.host != "" && p[0].Keys[0] == t.host {
		return p[1:], true
	}
	if len(p) == 0 || p[0].Name == "instance" || slices.Contains(sharedReadable, p[0].Name) || slices.Contains(adminLists, p[0].Name) {
		return p, false
	}
	return p, hostSchema().Child("instance").Child(p[0].Name) != nil || p[0].Name == "host-name"
}

// hostSchema is the configuration's schema (its top level).
func hostSchema() *schema.Node { return schema.MustLoad() }

// sharedReadable are the top-level lists everyone reads, as the API's
// shared resources.
var sharedReadable = []string{"host", "address-list", "ip-list", "object-folder", "service", "port-name", "dns-soa-template", "dnssec-policy", "dns-template"}

// adminLists are the top-level lists only global admins read: they hold
// what logs people in.
var adminLists = []string{"ldap-server", "user", "role", "ldap-role-mapping"}

func (t treeAccess) CanRead(p datastore.Path) bool {
	if len(p) > 0 && slices.Contains(adminLists, p[0].Name) {
		return t.a.isAdmin()
	}
	if t.a.readsAll() || len(p) == 0 {
		return true
	}
	if _, ok := t.hostScope(p); ok {
		return false // readsAll above
	}
	if p[0].Name == "instance" {
		return len(p[0].Keys) == 0 || t.read[p[0].Keys[0]]
	}
	return slices.Contains(sharedReadable, p[0].Name)
}

func (t treeAccess) CanWrite(p datastore.Path) bool {
	if t.readOnly {
		return false
	}
	if t.a.isAdmin() {
		return true
	}
	// The host's: global admins' alone (above), also named as its
	// instance of 1.0.0.
	if _, ok := t.hostScope(p); ok {
		return false
	}
	// An instance admin changes their virtual firewall, but not where it
	// runs or what it is.
	if len(p) < 2 || p[0].Name != "instance" || len(p[0].Keys) == 0 || !t.write[p[0].Keys[0]] {
		return false
	}
	return p[1].Name != "firewall"
}

// cliEnv is the CLI's environment for the user u.
func (s *Server) cliEnv(ctx context.Context, u *models.User) (*cli.Env, error) {
	t, err := s.tree()
	if err != nil {
		return nil, err
	}
	a, err := s.accessOf(u)
	if err != nil {
		return nil, err
	}
	read, write := a.readableNames(), a.writableNames()
	if s.cfg.Local {
		s.checkRole(ctx)
	}
	acc := treeAccess{a: a, read: read, write: write, host: s.currentHostName()}
	env := &cli.Env{
		Store: t.store, Schema: t.schema, User: u.Username, Access: acc, Version: buildinfo.Version,
		API: func(ctx context.Context, method, path string, body []byte) (int, []byte) {
			return s.requestAs(ctx, u, method, path, body)
		},
		Action: s.actionAs(u),
	}
	env.Host, _ = os.Hostname()
	if i := strings.IndexByte(env.Host, '.'); i > 0 {
		env.Host = env.Host[:i]
	}
	finish := func(path string) func(ctx context.Context) (string, error) {
		return func(ctx context.Context) (string, error) {
			code, body := s.requestAs(ctx, u, "POST", path, nil)
			if code/100 != 2 {
				return "", fmt.Errorf("%s", apiError(body))
			}
			return strings.TrimPrefix(path, "/api/deploy/") + ": done", nil
		}
	}
	env.Confirm, env.Rollback = finish("/api/deploy/confirm"), finish("/api/deploy/rollback")
	env.State = func(ctx context.Context) (*datastore.Tree, error) { return s.stateTree(ctx, u) }
	env.Pending = func(context.Context) bool {
		deps, err := s.pendingDeployments()
		return err == nil && len(deps) > 0
	}
	switch {
	case s.isReplica():
		env.ReadOnly = "this is the HA secondary: its configuration is a read-only copy of the primary's"
		acc.readOnly = true
	case !a.writesAny():
		env.ReadOnly = "you may read the configuration, not change it"
		acc.readOnly = true
	}
	if !a.isAdmin() {
		env.Only = write
	}
	env.Access = acc
	return env, nil
}

// apiError is the error of an API answer.
func apiError(body []byte) string {
	msg := strings.TrimSpace(string(body))
	if i := strings.Index(msg, `"error":"`); i >= 0 {
		msg = msg[i+9:]
		if j := strings.Index(msg, `"`); j >= 0 {
			msg = msg[:j]
		}
	}
	return msg
}

// ConsoleCLI is the CLI for the console: as the console admin.
func (s *Server) ConsoleCLI(ctx context.Context) (*cli.Env, error) {
	if err := s.ensureDefaultInstance(); err != nil {
		return nil, err
	}
	return s.cliEnv(ctx, consoleUser)
}

// cliLogin checks an SSH login to the CLI as the GUI's login does: the
// same users and directory, two-factor codes and failure limits.
func (s *Server) cliLogin(ctx context.Context, addr net.Addr, username, password, code string) (*cli.Env, bool, error) {
	ip := addr.String()
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h
	}
	if s.limiter.blocked(ip) {
		return nil, false, errors.New("too many failed logins; try again later")
	}
	u, err := authenticateUser(ctx, s, username, password)
	if err != nil {
		return nil, false, err
	}
	if u == nil {
		s.limiter.fail(ip)
		return nil, false, errors.New("wrong username or password")
	}
	if u.TOTPSecret != "" {
		if strings.TrimSpace(code) == "" {
			return nil, true, nil
		}
		ok, err := checkSecondFactor(s.rec, u, code)
		if err != nil {
			return nil, false, err
		}
		if !ok {
			s.limiter.fail(ip)
			return nil, false, errors.New("wrong code")
		}
	} else if u.TOTPRequired {
		return nil, false, errors.New("set up two-factor login in the GUI first")
	}
	s.limiter.reset(ip)
	env, err := s.cliEnv(ctx, u)
	return env, false, err
}

// runSSH serves the CLI over SSH on the config's ssh_listen.
func (s *Server) runSSH(ctx context.Context) {
	if s.cfg.SSHListen == "" {
		return
	}
	keyFile := filepath.Join(s.cfg.Dir(), "ssh_host_ed25519_key")
	key, err := cli.LoadHostKey(keyFile)
	if err != nil {
		slog.Error("CLI: the SSH host key", "file", keyFile, "err", err)
		return
	}
	srv := &cli.SSHServer{Addr: s.cfg.SSHListen, HostKey: key, Login: s.cliLogin,
		Subsystems: map[string]func(context.Context, *cli.Env, io.ReadWriter) error{"netconf": netconf.Serve}}
	if err := srv.Serve(ctx); err != nil {
		slog.Error("CLI: SSH", "err", err)
	}
}
