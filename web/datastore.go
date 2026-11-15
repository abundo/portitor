// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
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
// next to the database) and commits. A commit keeps the configuration it
// deploys (deployed/<commit>-config.json); running is the live commit's.

type treeState struct {
	once     sync.Once // the adoptions
	coreOnce sync.Once
	err      error
	schema   *schema.Node
	mapping  *sqlmap.Mapping
	store    *datastore.Store

	dir       string            // the database's, where the candidate and ids.json are; "" in memory
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
		if t.err = s.refuseLegacyConfig(); t.err != nil {
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

// Ready sets the configuration up now (tree), so that what an earlier release
// kept in the database is in the tree before the first request; called once a
// Server is made, before it serves.
func (s *Server) Ready() error {
	if _, err := s.tree(); err != nil {
		return err
	}
	// Every file now, and the mark that this directory has them: the next
	// release has no tables to make them from, and refuses a directory
	// without it (update through this release first).
	if err := s.rec.Seed(); err != nil {
		return err
	}
	return s.writeLayout()
}

// layoutVersion is the layout of the data directory: 2 has the files
// (candidate, global lists, ids, deployments, ...) and no configuration in the
// database.
const layoutVersion = 2

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

// tree is the configuration tree, set up on first use: core, then what an
// earlier release kept in the database moved into it before anything is
// served (the others wait for this).
func (s *Server) tree() (*treeState, error) {
	t, err := s.core()
	if err != nil {
		return nil, err
	}
	t.once.Do(func() {
		if t.err = s.adoptFirewalls(context.Background(), t, false); t.err == nil {
			t.err = s.adoptAccess(context.Background(), t, false)
		}
	})
	return t, t.err
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
}

// sharedReadable are the top-level lists everyone reads, as the API's
// shared resources.
var sharedReadable = []string{"host", "address-list", "ip-list", "object-folder", "service", "port-name"}

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
	// An instance admin changes their virtual firewall, but not where it
	// runs or what it is.
	if len(p) < 2 || p[0].Name != "instance" || len(p[0].Keys) == 0 || !t.write[p[0].Keys[0]] {
		return false
	}
	return p[1].Name != "firewall" && p[1].Name != "is-default"
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
	acc := treeAccess{a: a, read: read, write: write}
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

// refuseLegacyConfig stops a database that 0.9.0 migrated but did not start
// on: its configuration is still in config_snapshot, waiting to be taken
// into the tree (as 0.9.0 does at its first start), which this release no
// longer does.
func (s *Server) refuseLegacyConfig() error {
	if !s.db.Migrator().HasTable(snapshotTable) {
		return nil
	}
	var n int64
	if err := s.db.Table(snapshotTable).Where("name = ?", "legacy-import").Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return errors.New("the database holds a configuration 0.9.0 read from its old tables and nothing has taken it yet: start Portitor 0.9.0 once, then update to this release")
	}
	return nil
}
