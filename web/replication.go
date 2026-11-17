// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

// A commit runs on the firewalls at once; it is safe against the loss of the
// primary's portitor-config, which alone holds the pair's configuration, only
// once the secondary's replica has copied it. The replica reports what it
// holds after each copy (POST replicaCopiedPath: the copy's ETag, or the
// error), so the primary knows, compared with the ETag of its state now,
// whether its configuration is replicated (replicationStatus). A commit waits
// a moment for the copy (awaitReplica) and warns when it doesn't come; it
// never fails for it, so a pair whose secondary is lost can still be changed.

// replicaCopiedPath is where the replica reports its copy to the primary.
const replicaCopiedPath = "/ha/v2/copied"

// replicaWait is how long a commit waits for the secondary's copy.
const replicaWait = 5 * time.Second

// copyReport is the replica's report of its copy.
type copyReport struct {
	// ETag of the copy it holds ("" when it has none yet).
	ETag  string `json:"etag"`
	Error string `json:"error,omitempty"`
}

// peerCopy is what the primary knows of its replica's copy.
type peerCopy struct {
	etag     string
	err      string
	reported time.Time
	// copied: when the replica last reported the copy it holds now.
	copied time.Time
	// changed is closed, and replaced, at each report.
	changed chan struct{}
}

// replicationStatus is whether the primary's configuration is on its
// secondary too.
type replicationStatus struct {
	// Replicated: the secondary holds the primary's configuration as it is now.
	Replicated bool `json:"replicated"`
	// Copied: when the secondary last reported the copy it holds.
	Copied *time.Time `json:"copied,omitempty"`
	// Reported: when the secondary last reported at all (none: it never
	// has, a release before this one, or it can't reach this host).
	Reported *time.Time `json:"reported,omitempty"`
	Error    string     `json:"error,omitempty"`
}

// warning is what an admin is told when the configuration is not replicated.
func (st *replicationStatus) warning() string {
	if st == nil || st.Replicated {
		return ""
	}
	msg := "the configuration runs, but the cluster secondary has not copied it yet: losing this host now loses it"
	switch {
	case st.Error != "":
		msg += " (the secondary's copy failed: " + st.Error + ")"
	case st.Reported == nil:
		msg += " (the secondary has not reported a copy: it may be unreachable or need an update)"
	case time.Since(*st.Reported) > 2*replicaEvery:
		msg += " (the secondary last reported " + st.Reported.Format(time.RFC3339) + ")"
	}
	return msg
}

// replicaCopy is this primary's state as the replica copies it, and its ETag.
func (s *Server) replicaCopy(ctx context.Context) ([]byte, string, error) {
	files, err := s.snapshotFiles(ctx, true)
	if err != nil {
		return nil, "", err
	}
	data, err := encodeCopy(files, "replica")
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return data, `"` + hex.EncodeToString(sum[:]) + `"`, nil
}

// hasSecondary tells whether this is a primary's portitor-config that has a
// secondary to copy it.
func (s *Server) hasSecondary() bool {
	if !s.isPrimary() {
		return false
	}
	r := &s.role
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.peer.URL != "" && r.peer.Secret != ""
}

// replication is whether this primary's configuration is replicated; nil when
// this is no primary with a secondary.
func (s *Server) replication(ctx context.Context) *replicationStatus {
	if !s.hasSecondary() {
		return nil
	}
	st := &replicationStatus{}
	_, etag, err := s.replicaCopy(ctx)
	if err != nil {
		st.Error = "this host's copy: " + err.Error()
		return st
	}
	pc := &s.role.copy
	s.role.mu.Lock()
	defer s.role.mu.Unlock()
	if !pc.reported.IsZero() {
		t := pc.reported
		st.Reported = &t
	}
	if !pc.copied.IsZero() {
		t := pc.copied
		st.Copied = &t
	}
	st.Error = pc.err
	st.Replicated = pc.etag != "" && pc.etag == etag
	if st.Replicated {
		st.Error = ""
	}
	return st
}

// awaitReplica waits up to d for the secondary to copy this primary's
// configuration (notifyReplica asked it to), and tells where it is; nil when
// this is no primary with a secondary.
func (s *Server) awaitReplica(ctx context.Context, d time.Duration) *replicationStatus {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	for {
		s.role.mu.Lock()
		if s.role.copy.changed == nil {
			s.role.copy.changed = make(chan struct{})
		}
		changed := s.role.copy.changed
		s.role.mu.Unlock()
		st := s.replication(ctx)
		if st == nil || st.Replicated {
			return st
		}
		select {
		case <-changed:
		case <-deadline.C:
			return st
		case <-ctx.Done():
			return st
		}
	}
}

// handleReplicaCopied takes the replica's report of its copy.
func (s *Server) handleReplicaCopied(c *echo.Context) error {
	if ok, err := s.pairAuthorized(c); !ok {
		return err
	}
	var rep copyReport
	if err := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 64<<10)).Decode(&rep); err != nil {
		return errJSON(c, http.StatusBadRequest, "a copy report is JSON")
	}
	r := &s.role
	r.mu.Lock()
	pc := &r.copy
	now := time.Now()
	if rep.Error == "" {
		pc.copied = now
	}
	pc.etag, pc.err, pc.reported = rep.ETag, rep.Error, now
	if pc.changed != nil {
		close(pc.changed)
	}
	pc.changed = make(chan struct{})
	r.mu.Unlock()
	return c.NoContent(http.StatusNoContent)
}

// reportCopy tells the primary what this replica holds after a copy, err
// its failure. A primary before this release has no such route.
func (s *Server) reportCopy(ctx context.Context, copyErr error) {
	r := &s.role
	r.mu.Lock()
	peer, rep := r.peer, copyReport{ETag: r.etag}
	r.mu.Unlock()
	if copyErr != nil {
		rep.Error = copyErr.Error()
	}
	if peer.URL == "" || peer.Secret == "" {
		return
	}
	client, err := peerClient("the primary's portitor-config", peer.Fingerprint, 10*time.Second)
	if err != nil {
		return
	}
	body, _ := json.Marshal(rep)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(peer.URL, "/")+replicaCopiedPath, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+peer.Secret)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			slog.Debug("replica: reporting the copy", "err", err)
		}
		return
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent && res.StatusCode != http.StatusNotFound {
		slog.Warn("replica: reporting the copy", "status", fmt.Sprint(res.StatusCode))
	}
}
