// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/abundo/portitor/internal/datastore"
)

// A copy of portitor-config's state for a backup and for the HA replica is a
// tar archive of its files: the candidate, what runs of the global lists, the
// entries' ids and (for the replica) the deployments, the known interfaces
// and the sessions' values (dev/design-no-database.md). A backup is that
// archive encrypted with an age passphrase (`age -d backup | tar x`).
//
// What is read is checked, not trusted: a file's name must be one of
// copyFiles (nothing is ever extracted to a path the archive names), only
// regular files, a manifest with the format first, and a size limit.

// copyFormat is the archive's format: 3 since 1.1.0, whose configuration
// has the host at the top level (an older release refuses it, as it must:
// it would misread it); 2 is 1.0.0's, which this one reads and migrates
// (datastore.Migrate), so an HA secondary updated first copies its primary.
const copyFormat = 3

// copyFormatOldest is the oldest format this release reads.
const copyFormatOldest = 2

// copyFiles are the names a copy may hold.
var copyFiles = []string{"candidate.json", "global.json", "entry-ids.json", "ids.json", "deployments.jsonl", "known-nics.json", "sessions.json"}

type copyManifest struct {
	Format int    `json:"format"`
	Kind   string `json:"kind"` // backup or replica
}

// encodeCopy makes the archive: names sorted, no times, owners or modes that
// vary, so the same state is the same bytes (the replica's ETag).
func encodeCopy(files map[string][]byte, kind string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	put := func(name string, data []byte) error {
		h := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	m, err := json.Marshal(copyManifest{Format: copyFormat, Kind: kind})
	if err != nil {
		return nil, err
	}
	if err := put("manifest.json", m); err != nil {
		return nil, err
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if !slices.Contains(copyFiles, name) {
			return nil, fmt.Errorf("%s is not a file of a copy", name)
		}
		if err := put(name, files[name]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeCopy reads an archive into memory, checking it.
func decodeCopy(data []byte) (map[string][]byte, *copyManifest, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	files := map[string][]byte{}
	var man *copyManifest
	total := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("not a readable copy: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			return nil, nil, fmt.Errorf("%s: only files are in a copy", h.Name)
		}
		if h.Name != "manifest.json" && !slices.Contains(copyFiles, h.Name) {
			return nil, nil, fmt.Errorf("%s is not a file of a copy", h.Name)
		}
		if _, dup := files[h.Name]; dup || (h.Name == "manifest.json" && man != nil) {
			return nil, nil, fmt.Errorf("%s is there twice", h.Name)
		}
		if h.Size < 0 || total+int(h.Size) > backupMaxSize {
			return nil, nil, errors.New("the copy is too large")
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size))
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", h.Name, err)
		}
		total += len(b)
		if h.Name == "manifest.json" {
			man = &copyManifest{}
			if err := json.Unmarshal(b, man); err != nil {
				return nil, nil, fmt.Errorf("manifest: %w", err)
			}
			if man.Format < copyFormatOldest || man.Format > copyFormat {
				return nil, nil, fmt.Errorf("the copy is of format %d; this version reads %d (made by a newer Portitor? update first)", man.Format, copyFormat)
			}
			continue
		}
		if man == nil {
			return nil, nil, errors.New("not a Portitor copy (no manifest first)")
		}
		files[h.Name] = b
	}
	if man == nil {
		return nil, nil, errors.New("not a Portitor copy (no manifest)")
	}
	if files["candidate.json"] == nil {
		return nil, nil, errors.New("the copy holds no configuration")
	}
	return files, man, nil
}

// snapshotFiles are the files of a copy of this installation's state.
func (s *Server) snapshotFiles(ctx context.Context, forReplica bool) (map[string][]byte, error) {
	t, err := s.tree()
	if err != nil {
		return nil, err
	}
	cand, err := t.store.Candidate(ctx)
	if err != nil {
		return nil, err
	}
	data, err := cand.JSON(datastore.JSONOptions{Secrets: true})
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{"candidate.json": data}
	if t.dir != "" {
		if ids, err := os.ReadFile(filepath.Join(t.dir, "ids.json")); err == nil {
			files["ids.json"] = ids
		}
	}
	// What runs of the global lists (globals.go).
	if path, err := s.globalsPath(); err == nil {
		if g, err := os.ReadFile(path); err == nil {
			files["global.json"] = g
		}
	}
	state, err := s.rec.ExportState(forReplica)
	if err != nil {
		return nil, err
	}
	maps.Copy(files, state)
	return files, nil
}
