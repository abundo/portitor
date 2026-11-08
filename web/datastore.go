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
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/cli"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/internal/dbmigrate"
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
	once    sync.Once
	err     error
	schema  *schema.Node
	mapping *sqlmap.Mapping
	store   *datastore.Store

	runMu     sync.Mutex
	runCommit int64
	running   *datastore.Tree
}

// tree is the configuration tree, set up on first use.
func (s *Server) tree() (*treeState, error) {
	t := &s.treeState
	t.once.Do(func() {
		if t.schema, t.err = schema.Load(); t.err != nil {
			return
		}
		if t.mapping, t.err = sqlmap.New(t.schema); t.err != nil {
			return
		}
		dir := ""
		if s.cfg.DB.Path != "" {
			dir = filepath.Dir(s.cfg.DB.Path)
		}
		t.store = datastore.NewStore(t.schema, treeBackend{s}, dir)
		// The bridge to the code that still reads the tables.
		t.store.OnChange = func(c *datastore.Tree) error {
			if !s.db.Migrator().HasTable("instances") {
				return nil
			}
			return s.db.Transaction(func(tx *gorm.DB) error { return t.mapping.Write(tx, c) })
		}
	})
	return t, t.err
}

type treeBackend struct{ s *Server }

// Initial is the first candidate: an old database's configuration, read
// once from its tables, or running.
func (b treeBackend) Initial(ctx context.Context) (*datastore.Tree, error) {
	if tree, ok, err := b.s.importTables(b.s.db); ok || err != nil {
		return tree, err
	}
	return b.Running(ctx)
}

// importTables reads the configuration from db's tables when it has them
// (a database from before the tree, or its snapshot); ok is false when
// it has none.
func (s *Server) importTables(db *gorm.DB) (*datastore.Tree, bool, error) {
	return tablesTree(db)
}

// tablesTree is importTables without a server.
func tablesTree(db *gorm.DB) (*datastore.Tree, bool, error) {
	if !db.Migrator().HasTable("instances") {
		return nil, false, nil
	}
	var n int64
	if err := db.Table("instances").Count(&n).Error; err != nil || n == 0 {
		return nil, false, err
	}
	root, err := schema.Load()
	if err != nil {
		return nil, false, err
	}
	m, err := sqlmap.New(root)
	if err != nil {
		return nil, false, err
	}
	tree, _, err := m.Import(db)
	if err != nil {
		return nil, false, fmt.Errorf("reading the configuration from the database's tables: %w", err)
	}
	return tree, true, nil
}

// Running is the live commit's configuration, or an empty one before the
// first commit. A commit from before the tree is read from its database
// snapshot.
func (b treeBackend) Running(context.Context) (*datastore.Tree, error) {
	s := b.s
	t, err := s.tree()
	if err != nil {
		return nil, err
	}
	commit, err := s.liveCommit()
	if err != nil {
		return nil, err
	}
	t.runMu.Lock()
	defer t.runMu.Unlock()
	if t.running != nil && t.runCommit == commit {
		return t.running.Clone(), nil
	}
	tree := datastore.New(t.schema)
	if commit > 0 {
		loaded, err := s.loadCommit(t.schema, commit)
		switch {
		case err == nil:
			tree = loaded
		case errors.Is(err, os.ErrNotExist):
			if old, ok, err := s.oldSnapshot(commit); err != nil {
				return nil, err
			} else if ok {
				tree = old
			}
		default:
			return nil, err
		}
	}
	t.running, t.runCommit = tree, commit
	return tree.Clone(), nil
}

// oldSnapshot reads a commit's configuration from its database snapshot
// (deployed/<commit>.db), as commits were kept before the tree.
func (s *Server) oldSnapshot(commit int64) (*datastore.Tree, bool, error) {
	dir, err := s.snapshotDir()
	if err != nil {
		return nil, false, nil
	}
	path := filepath.Join(dir, fmt.Sprintf("%d.db", commit))
	if _, err := os.Stat(path); err != nil {
		return nil, false, nil
	}
	db, err := dbmigrate.Open(path, &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return nil, false, err
	}
	defer func() {
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.Close()
		}
	}()
	return s.importTables(db)
}

// Commit deploys the tree, as the GUI's commit does.
func (b treeBackend) Commit(ctx context.Context, tree *datastore.Tree, o datastore.CommitOptions) (string, error) {
	s := b.s
	if s.isReplica() {
		return "", errors.New("this is the HA secondary: its configuration is a read-only copy of the primary's")
	}
	if o.Validate {
		fws, err := s.firewalls()
		if err != nil {
			return "", err
		}
		var problems []string
		for _, fw := range fws {
			if _, err := s.buildDoc(builder.Input{DB: s.db, Tree: tree}, &fw, fw.Generation+1, o.Only); err != nil {
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

// syncFromTables reads the tables into the candidate. It bridges the
// code that still writes the tables (the CRUD resources, bootstrap,
// promotion, bundles) until it writes the tree (step C and E of the
// cut-over, dev/design-model-driven.md).
func (s *Server) syncFromTables(ctx context.Context) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	tree, ok, err := s.importTables(s.db)
	if err != nil || !ok {
		return err
	}
	return t.store.Replace(ctx, tree)
}

// syncTables runs syncFromTables after an API request that may have
// written the tables.
func (s *Server) syncTables(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		err := next(c)
		m, path := c.Request().Method, c.Request().URL.Path
		if err == nil && m != http.MethodGet && m != http.MethodHead && !strings.HasPrefix(path, "/api/deploy/") {
			if serr := s.syncFromTables(c.Request().Context()); serr != nil {
				slog.Warn("reading the tables into the candidate", "err", serr)
			}
		}
		return err
	}
}

// deployCandidate commits the candidate as the GUI's commit does.
func (s *Server) deployCandidate(ctx context.Context, user string, timeout *int) (*commitResult, error) {
	if err := s.syncFromTables(ctx); err != nil {
		return nil, err
	}
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

func (t treeAccess) CanRead(p datastore.Path) bool {
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
	a, err := accessOf(s.db, u)
	if err != nil {
		return nil, err
	}
	read, err := s.instanceNames(a.readable())
	if err != nil {
		return nil, err
	}
	write, err := s.instanceNames(a.writable())
	if err != nil {
		return nil, err
	}
	if s.cfg.Local {
		s.checkRole(ctx)
	}
	acc := treeAccess{a: a, read: read, write: write}
	env := &cli.Env{
		Store: t.store, Schema: t.schema, User: u.Username, Access: acc, Version: buildinfo.Version,
		API: func(ctx context.Context, method, path string, body []byte) (int, []byte) {
			return s.requestAs(ctx, u, method, path, body)
		},
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
	u, err := authenticateUser(ctx, s.db, username, password)
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
		ok, err := checkSecondFactor(s.db, u, code)
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
	keyFile := filepath.Join(filepath.Dir(s.cfg.DB.Path), "ssh_host_ed25519_key")
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
