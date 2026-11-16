// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/datastore"
)

// A backup is a copy of the configuration's files (copybundle.go), encrypted
// with an age passphrase because it holds every secret: `age -d backup | tar x`
// opens it outside Portitor. Restore also takes the unencrypted archive.
// Restore makes the backup's configuration the candidate (and what runs of the
// users, roles and directory the backup's): a commit deploys it. A backup made
// by a release that kept the configuration in a database file is restored with
// that release, which an update then follows.

// backupMaxSize limits a restored backup; the request carries it base64
// encoded in JSON.
const backupMaxSize = 256 << 20

const restorePath = "/api/backup/restore"

// restoreKeeps are tables that belong to this installation rather than to
// the firewall configuration: restore leaves them as they are. The
// firewalls are the hosts with their agents and generations.
var restoreKeeps = []string{"users", "deployments", "firewalls", "goose_db_version"}

var sqliteMagic = []byte("SQLite format 3\x00")

func (s *Server) handleBackup(c *echo.Context) error {
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	if len(req.Passphrase) < minPasswordLen {
		return errJSON(c, http.StatusBadRequest, fmt.Sprintf("passphrase must be at least %d characters", minPasswordLen))
	}
	files, err := s.snapshotFiles(c.Request().Context(), false)
	if err != nil {
		return err
	}
	archive, err := encodeCopy(files, "backup")
	if err != nil {
		return err
	}
	var out bytes.Buffer
	if err := encryptBackup(&out, archive, req.Passphrase); err != nil {
		return err
	}
	ver := buildinfo.Version
	if ver != "dev" && !strings.HasPrefix(ver, "v") {
		ver = "v" + ver
	}
	name := "portitor-" + ver + "-" + time.Now().Format("20060102-150405") + ".tar.age"
	c.Response().Header().Set(echo.HeaderContentDisposition, `attachment; filename="`+name+`"`)
	slog.Info("backup downloaded", "user", currentUser(c).Username, "bytes", out.Len())
	return c.Stream(http.StatusOK, "application/octet-stream", &out)
}

func encryptBackup(w io.Writer, data []byte, passphrase string) error {
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}
	enc, err := age.Encrypt(w, r)
	if err != nil {
		return err
	}
	if _, err := enc.Write(data); err != nil {
		return err
	}
	return enc.Close()
}

// errOldBackup is the refusal of a backup that is a database file.
var errOldBackup = errors.New("this backup is a database file, made by a release that kept the configuration there: restore it with that release (0.9.x), then update through 1.0.0")

// isTar tells whether data starts like a tar archive.
func isTar(data []byte) bool { return len(data) > 262 && string(data[257:262]) == "ustar" }

// decryptBackup returns the archive in data: plain, or age (binary or
// armored) encrypted with passphrase.
func decryptBackup(data []byte, passphrase string) ([]byte, error) {
	if bytes.HasPrefix(data, sqliteMagic) {
		return nil, errOldBackup
	}
	if isTar(data) {
		return data, nil
	}
	var in io.Reader = bytes.NewReader(data)
	switch {
	case bytes.HasPrefix(data, []byte("age-encryption.org/")):
	case bytes.HasPrefix(bytes.TrimSpace(data), []byte(armor.Header)):
		in = armor.NewReader(bytes.NewReader(bytes.TrimSpace(data)))
	default:
		return nil, errors.New("not a Portitor backup (neither an age encrypted file nor an archive)")
	}
	id, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(in, id)
	if err != nil {
		var nm *age.NoIdentityMatchError
		if errors.As(err, &nm) {
			return nil, errors.New("wrong passphrase")
		}
		return nil, err
	}
	out, err := io.ReadAll(io.LimitReader(r, backupMaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	if len(out) > backupMaxSize {
		return nil, errors.New("backup is too large")
	}
	if bytes.HasPrefix(out, sqliteMagic) {
		return nil, errOldBackup
	}
	if !isTar(out) {
		return nil, errors.New("the decrypted backup is not an archive")
	}
	return out, nil
}

func (s *Server) handleRestore(c *echo.Context) error {
	var req struct {
		Data       []byte `json:"data"` // base64
		Passphrase string `json:"passphrase"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	data, err := decryptBackup(req.Data, req.Passphrase)
	if err != nil {
		return errJSON(c, http.StatusBadRequest, err.Error())
	}
	files, _, err := decodeCopy(data)
	if err != nil {
		return errJSON(c, http.StatusBadRequest, err.Error())
	}

	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	if deps, err := s.pendingDeployments(); err != nil {
		return err
	} else if len(deps) > 0 {
		return errJSON(c, http.StatusConflict, "a deployment is waiting for confirmation; confirm or roll it back first")
	}
	// The firewalls stay this installation's: hosts with their agents.
	if err := s.takeSnapshot(c.Request().Context(), files, s.firewallsHere, true); err != nil {
		var re restoreError
		if errors.As(err, &re) {
			return errJSON(c, http.StatusBadRequest, err.Error())
		}
		return err
	}
	slog.Info("backup restored", "user", currentUser(c).Username)
	return c.JSON(http.StatusOK, map[string]any{"restored": true})
}

// firewallsHere puts what the configuration has on a firewall this
// installation doesn't have on the first one, a default instance only
// where that one has none.
func (s *Server) firewallsHere(tree *datastore.Tree) {
	fws, err := s.firewalls()
	if err != nil || len(fws) == 0 {
		return
	}
	known := map[string]bool{}
	for _, fw := range fws {
		known[fw.Name] = true
	}
	hasDefault := false
	for _, in := range tree.Root.Lists["instance"] {
		hasDefault = hasDefault || (in.Leaf("firewall") == fws[0].Name && in.Leaf("is-default") == "true")
	}
	for _, list := range []string{"instance", "task"} {
		for _, e := range tree.Root.Lists[list] {
			if fw := e.Leaf("firewall"); fw == "" || known[fw] {
				continue
			}
			if list == "instance" && e.Leaf("is-default") == "true" {
				if hasDefault {
					continue
				}
				hasDefault = true
			}
			e.Leaves["firewall"] = fws[0].Name
		}
	}
}

// restoreError is a problem with the backup, not the server.
type restoreError string

func (e restoreError) Error() string { return string(e) }
