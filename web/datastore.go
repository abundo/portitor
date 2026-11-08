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

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/cli"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/netconf"
	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/models"
)

// The configuration tree (dev/design-model-driven.md): the YANG schema's
// datastore over the tables, which the CLI (and NETCONF) edit in a shared
// candidate. A commit writes the tree into the tables (sqlmap) and deploys
// as the GUI's commit does, so the two meet in the database: the GUI's
// edits are in the candidate's base, which the candidate is rebased on.

type treeState struct {
	once    sync.Once
	err     error
	schema  *schema.Node
	mapping *sqlmap.Mapping
	store   *datastore.Store
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
	})
	return t, t.err
}

type treeBackend struct{ s *Server }

func (b treeBackend) Current(context.Context) (*datastore.Tree, error) {
	t, err := b.s.tree()
	if err != nil {
		return nil, err
	}
	tree, _, err := t.mapping.Import(b.s.db)
	return tree, err
}

// Running is the live commit's snapshot, or an empty configuration
// before the first commit.
func (b treeBackend) Running(context.Context) (*datastore.Tree, error) {
	t, err := b.s.tree()
	if err != nil {
		return nil, err
	}
	commit, err := b.s.liveCommit()
	if err != nil {
		return nil, err
	}
	dir, err := b.s.snapshotDir()
	if err != nil || commit == 0 {
		return datastore.New(t.schema), nil
	}
	path := snapshotPath(dir, commit)
	if _, err := os.Stat(path); err != nil {
		return datastore.New(t.schema), nil
	}
	db, err := openSnapshot(path)
	if err != nil {
		return nil, err
	}
	defer closeDB(db)
	tree, _, err := t.mapping.Import(db)
	if err != nil {
		return nil, fmt.Errorf("the running configuration (commit %d): %w", commit, err)
	}
	return tree, nil
}

var errValidated = errors.New("validated")

// Commit writes the tree into the tables and deploys it. When that fails
// the tables get back what they held.
func (b treeBackend) Commit(ctx context.Context, tree *datastore.Tree, o datastore.CommitOptions) (string, error) {
	s := b.s
	t, err := s.tree()
	if err != nil {
		return "", err
	}
	if s.isReplica() {
		return "", errors.New("this is the HA secondary: its configuration is a read-only copy of the primary's")
	}
	if o.Validate {
		var problems []string
		err := s.db.Transaction(func(tx *gorm.DB) error {
			if err := writeTree(tx, t.mapping, tree); err != nil {
				return err
			}
			fws, err := s.firewalls()
			if err != nil {
				return err
			}
			for _, fw := range fws {
				if _, err := s.buildDoc(tx, &fw, fw.Generation+1, o.Only); err != nil {
					problems = append(problems, firewallProblem(fws, fw, err.Error()))
				}
			}
			return errValidated
		})
		if !errors.Is(err, errValidated) {
			return "", err
		}
		if len(problems) > 0 {
			return "", errors.New(strings.Join(problems, "\n"))
		}
		return "The candidate is valid.", nil
	}
	prev, _, err := t.mapping.Import(s.db)
	if err != nil {
		return "", err
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error { return writeTree(tx, t.mapping, tree) }); err != nil {
		return "", err
	}
	res, err := s.deploy(ctx, o.User, o.Confirm, o.Only)
	if err != nil {
		if rerr := s.db.Transaction(func(tx *gorm.DB) error { return writeTree(tx, t.mapping, prev) }); rerr != nil {
			slog.Error("restoring the configuration after a failed commit", "err", rerr)
			return "", fmt.Errorf("%w (restoring the configuration from before the commit failed too: %v)", err, rerr)
		}
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

// writeTree writes the tree into the tables, and gives a new virtual
// firewall its role.
func writeTree(tx *gorm.DB, m *sqlmap.Mapping, tree *datastore.Tree) error {
	if err := m.Write(tx, tree); err != nil {
		return err
	}
	var missing []models.Instance
	if err := tx.Where("is_default = ? AND id NOT IN (SELECT instance_id FROM roles WHERE instance_id IS NOT NULL)", false).
		Find(&missing).Error; err != nil {
		return err
	}
	for i := range missing {
		if err := createInstanceRole(tx, &missing[i]); err != nil {
			return err
		}
	}
	return nil
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
