// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/cli"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/netconf"
)

// The portal's configuration is reached as a firewall's is: the CLI
// (`portitor-web cli`, and over SSH on ssh_listen) and NETCONF (the SSH
// subsystem), on the candidate of PortalStore. Every portal user may read
// and change all of it.

type portalAccess struct{}

func (portalAccess) CanRead(datastore.Path) bool  { return true }
func (portalAccess) CanWrite(datastore.Path) bool { return true }

var errNoConfirm = errors.New("the portal has no commit that waits for confirmation")

// CLIEnv is the CLI's environment for user.
func (s *PortalStore) CLIEnv(user string) *cli.Env {
	host, _ := os.Hostname()
	if i := strings.IndexByte(host, '.'); i > 0 {
		host = host[:i]
	}
	return &cli.Env{
		Store: s.Store, Schema: s.schema, User: user, Host: host, Access: portalAccess{}, Version: buildinfo.Version,
		Confirm:  func(context.Context) (string, error) { return "", errNoConfirm },
		Rollback: func(context.Context) (string, error) { return "", errNoConfirm },
		Pending:  func(context.Context) bool { return false },
		API: func(context.Context, string, string, []byte) (int, []byte) {
			return 404, []byte("the portal has no API behind show api")
		},
	}
}

// cliLogin checks an SSH login as the portal's own login does.
func (p *Portal) cliLogin(_ context.Context, addr net.Addr, user, password, _ string) (*cli.Env, bool, error) {
	ip := addr.String()
	if h, _, err := net.SplitHostPort(ip); err == nil {
		ip = h
	}
	if p.limits.blocked(ip) {
		return nil, false, errors.New("too many failed logins; try again later")
	}
	hash, ok := p.store.PasswordHash(user)
	h := []byte(hash)
	if !ok {
		h = dummyHash
	}
	if bcrypt.CompareHashAndPassword(h, []byte(password)) != nil || !ok {
		p.limits.fail(ip)
		return nil, false, errors.New("wrong username or password")
	}
	return p.store.CLIEnv(user), false, nil
}

// runSSH serves the CLI and NETCONF over SSH on ssh_listen.
func (p *Portal) runSSH(ctx context.Context) {
	if p.cfg.SSHListen == "" {
		return
	}
	keyFile := filepath.Join(p.cfg.DataDir, "ssh_host_ed25519_key")
	key, err := cli.LoadHostKey(keyFile)
	if err != nil {
		slog.Error("portal: the SSH host key", "file", keyFile, "err", err)
		return
	}
	srv := &cli.SSHServer{Addr: p.cfg.SSHListen, HostKey: key, Login: p.cliLogin,
		Subsystems: map[string]func(context.Context, *cli.Env, io.ReadWriter) error{"netconf": netconf.Serve}}
	if err := srv.Serve(ctx); err != nil {
		slog.Error("portal: SSH", "err", err)
	}
}
