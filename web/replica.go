// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// portitor-config runs on both hosts of an HA pair, and the primary's owns
// the pair's configuration. The secondary's is a replica: it copies the
// primary's database (GET /ha/v1/database, with the pair's secret) every
// replicaEvery and whenever it changed, and is read-only, so the
// configuration survives the primary's loss and the secondary can be
// promoted (promote.go). A primary taken over by a promotion while it was
// away (its agent is stale) is a replica of the new primary in the same
// way, until it is caught up as its secondary.
//
// Which one a portitor-config is, its own agent tells it (GET
// /v1/ha/peer-config): the agent at agent_url, known in the database by
// its certificate's fingerprint; a secondary that the database has as the
// primary was promoted here. A replica takes the peer's portitor-config
// and the pair's secret from there too (fwconfig.HA.PeerConfig), from the
// document the primary deployed.

const (
	roleEvery    = 5 * time.Second
	replicaEvery = 15 * time.Second
)

// hostRole is this portitor-config's place in its pair.
type hostRole struct {
	mu sync.Mutex
	// known: the agent has answered once. Before, a portitor-config with
	// a pair in its database is read-only.
	known   bool
	replica bool
	peer    agentapi.HAPeerConfig
	// promoted: this host was promoted; its agent may still answer as the
	// secondary until the promotion's commit is applied.
	promoted bool
	// The replica's last copy.
	etag     string
	lastCopy time.Time
	copyErr  string
	// roleErr: the last error asking the agent, logged when it changes.
	roleErr string
	// fingerprint of the local agent's certificate, once read.
	fingerprint string
}

// isReplica tells whether this portitor-config is read-only: an HA
// secondary's (or a taken-over primary's), or one with a pair whose agent
// has not told it which it is yet.
func (s *Server) isReplica() bool {
	if !s.cfg.Local {
		return false
	}
	r := &s.role
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.promoted {
		return false
	}
	if !r.known {
		var n int64
		s.db.Model(&models.Firewall{}).Where("ha_primary_id IS NOT NULL").Count(&n)
		return n > 0
	}
	return r.replica
}

// agentFingerprint reads the SHA-256 of the certificate of the agent at
// url.
func agentFingerprint(ctx context.Context, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" {
		return "", fmt.Errorf("agent_url %q must be https://", rawURL)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} // read, not trusted: matched below
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("the agent presented no certificate")
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}

// localFirewall is this host's firewall: the one whose agent fingerprint
// is that of the agent at agent_url.
func (s *Server) localFirewall(ctx context.Context) (*models.Firewall, error) {
	r := &s.role
	r.mu.Lock()
	fp := r.fingerprint
	r.mu.Unlock()
	if fp == "" {
		var err error
		if fp, err = agentFingerprint(ctx, s.cfg.AgentURL); err != nil {
			return nil, fmt.Errorf("this host's agent (%s): %w", s.cfg.AgentURL, err)
		}
		r.mu.Lock()
		r.fingerprint = fp
		r.mu.Unlock()
	}
	var fw models.Firewall
	if err := s.db.Where("agent_fingerprint = ?", fp).Order("id").First(&fw).Error; err != nil {
		return nil, fmt.Errorf("no firewall here has the certificate fingerprint of this host's agent (%s)", fp)
	}
	return &fw, nil
}

// localPeerConfig asks this host's agent for its place in the pair.
func (s *Server) localPeerConfig(ctx context.Context) (*agentapi.HAPeerConfig, *models.Firewall, error) {
	fw, err := s.localFirewall(ctx)
	if err != nil {
		return nil, nil, err
	}
	c, err := agentclient.New(s.cfg.AgentURL, fw.AgentToken, fw.AgentFingerprint)
	if err != nil {
		return nil, fw, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pc, err := c.HAPeerConfig(ctx)
	return pc, fw, err
}

// checkRole asks the agent and records the role; an agent that does not
// answer leaves it as it was.
func (s *Server) checkRole(ctx context.Context) {
	pc, me, err := s.localHA(ctx)
	r := &s.role
	if err != nil {
		r.mu.Lock()
		if r.roleErr != err.Error() {
			r.roleErr = err.Error()
			slog.Warn("role: this host's agent", "err", err)
		}
		r.mu.Unlock()
		return
	}
	// A secondary whose database has it the primary of the pair was
	// promoted here, and its agent waits for the promotion's commit (one
	// that failed, before a restart). A stale agent is a primary taken
	// over: its database is the old one.
	replica := pc.Stale || (pc.Node == fwconfig.HASecondary && !s.primaryHere(me))
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roleErr = ""
	if r.promoted && pc.Node == fwconfig.HAPrimary && !pc.Stale {
		// The promotion's commit is applied.
		r.promoted = false
	}
	if !r.known || r.replica != replica {
		slog.Info("role", "replica", replica, "node", pc.Node, "stale", pc.Stale)
	}
	r.known, r.replica, r.peer = true, replica, *pc
}

// primaryHere tells whether the database has the firewall the primary of
// a pair.
func (s *Server) primaryHere(me *models.Firewall) bool {
	if me == nil || me.HAPrimaryID != nil {
		return false
	}
	var n int64
	s.db.Model(&models.Firewall{}).Where("ha_primary_id = ?", me.ID).Count(&n)
	return n > 0
}

// runRole follows the host's role, and copies the primary's database
// while it is a replica, until ctx is cancelled.
func (s *Server) runRole(ctx context.Context) {
	s.checkRole(ctx)
	t := time.NewTicker(roleEvery)
	defer t.Stop()
	var lastTry time.Time
	for {
		if s.isReplica() && time.Since(lastTry) >= replicaEvery {
			lastTry = time.Now()
			if err := s.copyPrimary(ctx); err != nil {
				slog.Warn("replica: copying the primary's configuration", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.checkRole(ctx)
	}
}

// replicaKeeps: a replica copies every table but the schema's version.
var replicaKeeps = []string{"goose_db_version"}

// copyPrimary copies the primary's database into this one, when it changed.
func (s *Server) copyPrimary(ctx context.Context) error {
	r := &s.role
	r.mu.Lock()
	peer, etag := r.peer, r.etag
	r.mu.Unlock()
	fail := func(err error) error {
		r.mu.Lock()
		r.copyErr = err.Error()
		r.mu.Unlock()
		return err
	}
	if peer.URL == "" {
		return fail(errors.New("the primary's portitor-config is not known: set its portitor-config URL and fingerprint under Firewalls, and commit"))
	}
	tlsCfg, err := agentclient.PinnedTLS("the primary's portitor-config", peer.Fingerprint)
	if err != nil {
		return fail(err)
	}
	tlsCfg.MinVersion, tlsCfg.ServerName = tls.VersionTLS12, PinnedServerName
	client := &http.Client{Timeout: time.Minute, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(peer.URL, "/")+replicaPath, nil)
	if err != nil {
		return fail(err)
	}
	req.Header.Set("Authorization", "Bearer "+peer.Secret)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	res, err := client.Do(req)
	if err != nil {
		return fail(fmt.Errorf("the primary's portitor-config: %w", err))
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusNotModified:
		r.mu.Lock()
		r.lastCopy, r.copyErr = time.Now(), ""
		r.mu.Unlock()
		return nil
	case http.StatusOK:
	default:
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fail(fmt.Errorf("the primary's portitor-config: HTTP %d %s", res.StatusCode, strings.TrimSpace(string(b))))
	}
	dir, err := s.snapshotDir()
	if err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail(err)
	}
	tmp := filepath.Join(dir, "replica.db.tmp")
	defer os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fail(err)
	}
	_, err = io.Copy(f, io.LimitReader(res.Body, backupMaxSize))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fail(err)
	}
	// Not over a promotion of this host.
	s.replMu.Lock()
	defer s.replMu.Unlock()
	if !s.isReplica() {
		return nil
	}
	if _, err := restoreDatabase(ctx, s.db, tmp, replicaKeeps); err != nil {
		return fail(fmt.Errorf("the primary's database: %w", err))
	}
	r.mu.Lock()
	if r.etag != res.Header.Get("ETag") {
		slog.Info("replica: copied the primary's configuration")
	}
	r.etag, r.lastCopy, r.copyErr = res.Header.Get("ETag"), time.Now(), ""
	r.mu.Unlock()
	return nil
}

const replicaPath = "/ha/v1/database"

// handleReplica gives the secondary's portitor-config this database, the
// pair's secret its key. Its ETag is its content's SHA-256.
func (s *Server) handleReplica(c *echo.Context) error {
	if !s.cfg.Local || s.isReplica() {
		return errJSON(c, http.StatusConflict, "this portitor-config is not the primary's")
	}
	var secrets []string
	if err := s.db.Model(&models.Firewall{}).Where("ha_primary_id IS NOT NULL AND ha_secret != ''").Pluck("ha_secret", &secrets).Error; err != nil {
		return err
	}
	got := c.Request().Header.Get("Authorization")
	ok := false
	for _, sec := range secrets {
		if subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+sec)) == 1 {
			ok = true
		}
	}
	if !ok {
		slog.Warn("replica: refused a copy of the database", "remote", c.RealIP())
		return errJSON(c, http.StatusUnauthorized, "unauthorized")
	}
	dir, err := s.snapshotDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "replica-*.db")
	if err != nil {
		return err
	}
	tmp := f.Name()
	f.Close()
	os.Remove(tmp)
	defer os.Remove(tmp)
	if err := s.db.Exec("VACUUM INTO ?", tmp).Error; err != nil {
		return err
	}
	data, err := os.ReadFile(tmp)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	h := c.Response().Header()
	h.Set("ETag", etag)
	h.Set("Cache-Control", "no-store")
	if c.Request().Header.Get("If-None-Match") == etag {
		return c.NoContent(http.StatusNotModified)
	}
	return c.Blob(http.StatusOK, "application/vnd.sqlite3", data)
}

// readOnlyAllowed are the writes a replica takes: logging in and out, the
// preview, the live tools and the host's own actions, none of which change
// the configuration, and the promotion.
var readOnlyAllowed = map[string]bool{
	"/api/login":                   true,
	"/api/logout":                  true,
	"/api/deploy/preview":          true,
	"/api/agent/capture":           true,
	"/api/agent/trace":             true,
	"/api/agent/servicelog":        true,
	"/api/agent/connections":       true,
	"/api/agent/connections/flush": true,
	"/api/agent/dhcp/renew":        true,
	"/api/system/jobs":             true,
	"/api/system/reboot":           true,
	"/api/ha/promote":              true,
}

// refuseOnReplica keeps a replica's configuration as the primary's.
func (s *Server) refuseOnReplica(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		m := c.Request().Method
		if m == http.MethodGet || m == http.MethodHead || readOnlyAllowed[c.Request().URL.Path] || !s.isReplica() {
			return next(c)
		}
		return errJSON(c, http.StatusConflict, "this is the HA secondary: its configuration is a read-only copy of the primary's; change it there, or promote this host if the primary is lost")
	}
}
