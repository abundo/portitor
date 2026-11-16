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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// portitor-config runs on both hosts of an HA pair, and the primary's owns
// the pair's configuration. The secondary's is a replica: it copies the
// primary's files (GET /ha/v2/bundle, with the pair's secret) every
// replicaEvery and whenever it changed, and is read-only, so the
// configuration survives the primary's loss and the secondary can be
// promoted (promote.go). A primary taken over by a promotion while it was
// away (its agent is stale) is a replica of the new primary in the same
// way, until it is caught up as its secondary.
//
// Which one a portitor-config is, its own agent tells it (GET
// /v1/ha/peer-config): the agent at agent_url, known in the configuration by
// its certificate's fingerprint; a secondary that the configuration has as the
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
	// a pair in its configuration is read-only.
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
	// wake: the primary said it committed (POST replicaNotifyPath); the
	// replica copies at once instead of at the next replicaEvery.
	wake chan struct{}
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
		fws, _ := s.rec.Firewalls()
		return slices.ContainsFunc(fws, func(f models.Firewall) bool { return f.HAPrimaryID != nil })
	}
	return r.replica
}

// isPrimary tells whether this portitor-config is an HA primary's (or one
// promoted here, whose agent may still answer as the secondary until the
// promotion's commit is applied).
func (s *Server) isPrimary() bool {
	if !s.cfg.Local {
		return false
	}
	r := &s.role
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.promoted {
		return true
	}
	return r.known && !r.replica && r.peer.Node == fwconfig.HAPrimary
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

// localFingerprint is the certificate fingerprint of this host's agent, the
// one at agent_url, read once.
func (s *Server) localFingerprint(ctx context.Context) (string, error) {
	r := &s.role
	r.mu.Lock()
	fp := r.fingerprint
	r.mu.Unlock()
	if fp != "" {
		return fp, nil
	}
	fp, err := agentFingerprint(ctx, s.cfg.AgentURL)
	if err != nil {
		return "", fmt.Errorf("this host's agent (%s): %w", s.cfg.AgentURL, err)
	}
	r.mu.Lock()
	r.fingerprint = fp
	r.mu.Unlock()
	return fp, nil
}

// agentURL is where this portitor-config reaches f's agent: its own
// agent at agent_url (127.0.0.1, say), every other at the firewall's agent
// URL, the address its HA peer and witness use too. The firewalls are the
// pair's, copied to the replica, so its own is told by the fingerprint.
func (s *Server) agentURL(f *models.Firewall) string {
	if !s.cfg.Local || f.AgentFingerprint == "" {
		return f.AgentURL
	}
	if fp, err := s.localFingerprint(context.Background()); err == nil && strings.EqualFold(fp, f.AgentFingerprint) {
		return s.cfg.AgentURL
	}
	return f.AgentURL
}

// localFirewall is this host's firewall: the one whose agent fingerprint
// is that of the agent at agent_url.
func (s *Server) localFirewall(ctx context.Context) (*models.Firewall, error) {
	fp, err := s.localFingerprint(ctx)
	if err != nil {
		return nil, err
	}
	fws, _ := s.rec.Firewalls()
	i := slices.IndexFunc(fws, func(f models.Firewall) bool { return f.AgentFingerprint == fp })
	if i < 0 {
		return nil, fmt.Errorf("no firewall here has the certificate fingerprint of this host's agent (%s)", fp)
	}
	return &fws[i], nil
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
	// A secondary whose configuration has it the primary of the pair was
	// promoted here, and its agent waits for the promotion's commit (one
	// that failed, before a restart). A stale agent is a primary taken
	// over: its configuration is the old one.
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

// primaryHere tells whether the configuration has the firewall the primary of
// a pair.
func (s *Server) primaryHere(me *models.Firewall) bool {
	if me == nil || me.HAPrimaryID != nil {
		return false
	}
	sec, _ := s.secondaryOf(me.ID)
	return sec != nil
}

// runRole follows the host's role, and copies the primary's files
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
		case <-s.role.wake:
			lastTry = time.Time{}
		}
		s.checkRole(ctx)
	}
}

// copyPrimary copies the primary's files into this one's, when they changed.
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
	client, err := peerClient("the primary's portitor-config", peer.Fingerprint, time.Minute)
	if err != nil {
		return fail(err)
	}
	get := func(path string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(peer.URL, "/")+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+peer.Secret)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		return client.Do(req)
	}
	// The primary's files (a primary from before 1.0.0, which kept them in a
	// database file, has no such route: update it).
	res, err := get(replicaBundlePath)
	if err == nil && res.StatusCode == http.StatusNotFound {
		res.Body.Close()
		return fail(errors.New("the primary's portitor-config is older than 1.0.0 and gives no copy this release can take: update the primary"))
	}
	if err != nil {
		return fail(fmt.Errorf("the primary's portitor-config: %w", err))
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusNotModified:
		// The same copy; running's commit may have come since.
		if err := s.replicaTree(ctx, client, peer); err != nil {
			return fail(err)
		}
		r.mu.Lock()
		r.lastCopy, r.copyErr = time.Now(), ""
		r.mu.Unlock()
		return nil
	case http.StatusOK:
	default:
		b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fail(fmt.Errorf("the primary's portitor-config: HTTP %d %s", res.StatusCode, strings.TrimSpace(string(b))))
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, backupMaxSize+1))
	if err != nil {
		return fail(err)
	}
	if len(body) > backupMaxSize {
		return fail(errors.New("the primary's copy is too large"))
	}
	// Not over a promotion of this host.
	s.replMu.Lock()
	defer s.replMu.Unlock()
	if !s.isReplica() {
		return nil
	}
	var files map[string][]byte
	if files, _, err = decodeCopy(body); err == nil {
		err = s.takeSnapshot(ctx, files, nil, false)
	}
	if err != nil {
		return fail(fmt.Errorf("the primary's copy: %w", err))
	}
	if err := s.replicaTree(ctx, client, peer); err != nil {
		return fail(err)
	}
	r.mu.Lock()
	if r.etag != res.Header.Get("ETag") {
		slog.Info("replica: copied the primary's configuration")
	}
	r.etag, r.lastCopy, r.copyErr = res.Header.Get("ETag"), time.Now(), ""
	r.mu.Unlock()
	return nil
}

// replicaBundlePath is the primary's archive of files (copybundle.go).
const replicaBundlePath = "/ha/v2/bundle"

// replicaNotifyPath is where the primary tells the replica it committed.
const replicaNotifyPath = "/ha/v2/notify"

// peerClient is an HTTPS client to the pair's other portitor-config, its
// certificate pinned.
func peerClient(what, fingerprint string, timeout time.Duration) (*http.Client, error) {
	tlsCfg, err := agentclient.PinnedTLS(what, fingerprint)
	if err != nil {
		return nil, err
	}
	tlsCfg.MinVersion, tlsCfg.ServerName = tls.VersionTLS12, PinnedServerName
	return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}}, nil
}

// notifyReplica tells the secondary's portitor-config that this primary
// committed, so it copies the files at once rather than up to replicaEvery
// later: that narrows, not closes, the window in which a lost primary takes
// its last changes with it. It doesn't wait, and a failure is only logged:
// the replica still copies at its interval.
func (s *Server) notifyReplica() {
	r := &s.role
	r.mu.Lock()
	known, replica, peer := r.known, r.replica, r.peer
	r.mu.Unlock()
	if !s.cfg.Local || !known || replica || peer.URL == "" || peer.Secret == "" {
		return
	}
	go func() {
		client, err := peerClient("the secondary's portitor-config", peer.Fingerprint, 10*time.Second)
		if err != nil {
			slog.Warn("replica: notifying the secondary", "err", err)
			return
		}
		req, err := http.NewRequest(http.MethodPost, strings.TrimRight(peer.URL, "/")+replicaNotifyPath, nil)
		if err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+peer.Secret)
		res, err := client.Do(req)
		if err != nil {
			slog.Warn("replica: notifying the secondary", "err", err)
			return
		}
		res.Body.Close()
		// A secondary before this release has no such route (404): it
		// copies at its interval.
		if res.StatusCode != http.StatusNoContent && res.StatusCode != http.StatusNotFound {
			slog.Warn("replica: notifying the secondary", "status", res.StatusCode)
		}
	}()
}

// handleReplicaNotify is the primary telling this replica it committed: the
// pair's secret (from this host's agent) its key. It only wakes the copy.
func (s *Server) handleReplicaNotify(c *echo.Context) error {
	r := &s.role
	r.mu.Lock()
	replica, secret := r.known && r.replica, r.peer.Secret
	r.mu.Unlock()
	if !s.cfg.Local || !replica || secret == "" {
		return errJSON(c, http.StatusConflict, "this portitor-config is not a replica")
	}
	if subtle.ConstantTimeCompare([]byte(c.Request().Header.Get("Authorization")), []byte("Bearer "+secret)) != 1 {
		slog.Warn("replica: refused a notification", "remote", c.RealIP())
		return errJSON(c, http.StatusUnauthorized, "unauthorized")
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return c.NoContent(http.StatusNoContent)
}

// replicaCommitPath + <commit> is a commit's configuration
// (deployed/<commit>-config.json), which the replica's running is.
const replicaCommitPath = "/ha/v1/commits/"

// pairAuthorized answers a request to the primary's portitor-config from
// its secondary's: false (answered) unless this is the primary's and the
// request has the pair's secret.
func (s *Server) pairAuthorized(c *echo.Context) (bool, error) {
	if !s.cfg.Local || s.isReplica() {
		return false, errJSON(c, http.StatusConflict, "this portitor-config is not the primary's")
	}
	fws, err := s.rec.Firewalls()
	if err != nil {
		return false, err
	}
	var secrets []string
	for _, f := range fws {
		if f.HAPrimaryID != nil && f.HASecret != "" {
			secrets = append(secrets, f.HASecret)
		}
	}
	got := c.Request().Header.Get("Authorization")
	ok := false
	for _, sec := range secrets {
		if subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+sec)) == 1 {
			ok = true
		}
	}
	if !ok {
		slog.Warn("replica: refused a request of the secondary's", "path", c.Request().URL.Path, "remote", c.RealIP())
		return false, errJSON(c, http.StatusUnauthorized, "unauthorized")
	}
	return true, nil
}

// handleReplicaCommit gives the secondary's portitor-config a commit's
// configuration, every secret in it (as the configuration has them).
func (s *Server) handleReplicaCommit(c *echo.Context) error {
	if ok, err := s.pairAuthorized(c); !ok {
		return err
	}
	commit, err := echo.PathParam[int64](c, "commit")
	if err != nil || commit <= 0 {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	dir, err := s.snapshotDir()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(configPath(dir, commit))
	if errors.Is(err, os.ErrNotExist) {
		return errJSON(c, http.StatusNotFound, fmt.Sprintf("commit %d is not kept", commit))
	} else if err != nil {
		return err
	}
	return c.Blob(http.StatusOK, "application/json", data)
}

// replicaTree brings the replica's running configuration in step with the
// copy of the primary's files (which brought its candidate): the live
// commit's configuration, fetched from the primary when this host doesn't
// have it.
func (s *Server) replicaTree(ctx context.Context, client *http.Client, peer agentapi.HAPeerConfig) error {
	commit, err := s.liveCommit()
	if err != nil || commit == 0 {
		return err
	}
	dir, err := s.snapshotDir()
	if err != nil {
		return err
	}
	path := configPath(dir, commit)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(peer.URL, "/")+replicaCommitPath+strconv.FormatInt(commit, 10), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+peer.Secret)
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("commit %d from the primary: %w", commit, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("commit %d from the primary: HTTP %d", commit, res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, backupMaxSize))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := datastore.WriteFile(path, data); err != nil {
		return err
	}
	s.forgetRunning()
	return nil
}

// handleReplicaBundle gives the secondary's portitor-config this state, the
// pair's secret its key. Its ETag is its content's SHA-256: the archive is the
// same bytes while the state is the same.
func (s *Server) handleReplicaBundle(c *echo.Context) error {
	if ok, err := s.pairAuthorized(c); !ok {
		return err
	}
	files, err := s.snapshotFiles(c.Request().Context(), true)
	if err != nil {
		return err
	}
	data, err := encodeCopy(files, "replica")
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
	return c.Blob(http.StatusOK, "application/x-tar", data)
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
