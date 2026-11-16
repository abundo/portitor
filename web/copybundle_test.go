// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
)

func tarOf(t *testing.T, entries ...tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range entries {
		body := []byte(h.Linkname)
		if h.Typeflag != tar.TypeReg {
			body = nil
		}
		h.Size = int64(len(body))
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	return buf.Bytes()
}

// A copy is read as data, never as paths: only the names it may hold, plain
// files, a manifest first of the format this version reads.
func TestDecodeCopyChecksTheArchive(t *testing.T) {
	good, err := encodeCopy(map[string][]byte{"candidate.json": []byte("{}"), "global.json": []byte("{}")}, "backup")
	if err != nil {
		t.Fatal(err)
	}
	files, man, err := decodeCopy(good)
	if err != nil || len(files) != 2 || man.Kind != "backup" {
		t.Fatalf("a good copy: %v %v %+v", err, files, man)
	}
	// The same state, the same bytes (the replica's ETag).
	again, _ := encodeCopy(map[string][]byte{"global.json": []byte("{}"), "candidate.json": []byte("{}")}, "backup")
	if !bytes.Equal(good, again) {
		t.Error("the same files gave other bytes")
	}

	man1 := tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Linkname: `{"format":2,"kind":"backup"}`}
	cand := tar.Header{Name: "candidate.json", Typeflag: tar.TypeReg, Linkname: "{}"}
	for what, in := range map[string][]byte{
		"a path":           tarOf(t, man1, tar.Header{Name: "../../etc/passwd", Typeflag: tar.TypeReg, Linkname: "x"}),
		"a subdirectory":   tarOf(t, man1, tar.Header{Name: "deployed/1-config.json", Typeflag: tar.TypeReg, Linkname: "x"}),
		"a symlink":        tarOf(t, man1, tar.Header{Name: "candidate.json", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}),
		"a directory":      tarOf(t, man1, tar.Header{Name: "candidate.json", Typeflag: tar.TypeDir}),
		"twice":            tarOf(t, man1, cand, cand),
		"no manifest":      tarOf(t, cand),
		"a later format":   tarOf(t, tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Linkname: `{"format":4}`}, cand),
		"no configuration": tarOf(t, man1),
		"garbage":          []byte("not an archive at all"),
	} {
		if _, _, err := decodeCopy(in); err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
	if _, err := encodeCopy(map[string][]byte{"../x": nil}, "backup"); err == nil {
		t.Error("a name outside the list was written")
	}
}

// A backup of a release that kept the configuration in a database file says
// where to restore it.
func TestRestoreOfADatabaseFileBackupSaysWhat(t *testing.T) {
	env := newEnv(t)
	old := append([]byte(nil), sqliteMagic...)
	old = append(old, make([]byte, 100)...)
	rec := env.do("POST", "/api/backup/restore", map[string]any{"data": old})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "that release (0.9.x)") {
		t.Errorf("a database file: %d %s", rec.Code, rec.Body)
	}
}
