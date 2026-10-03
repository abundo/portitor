// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/dbmigrate"
	"github.com/abundo/portitor/models"
)

const testPassphrase = "a long enough passphrase"

func (env *testEnv) backup() []byte {
	env.t.Helper()
	rec := env.do("POST", "/api/backup", map[string]string{"passphrase": testPassphrase})
	if rec.Code != http.StatusOK {
		env.t.Fatalf("backup: %d %s", rec.Code, rec.Body)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, ".db.age") {
		env.t.Errorf("Content-Disposition %q", cd)
	}
	return rec.Body.Bytes()
}

func objectNames(t *testing.T, env *testEnv) []string {
	t.Helper()
	var names []string
	if err := env.srv.db.Model(&models.AddressObject{}).Order("name").Pluck("name", &names).Error; err != nil {
		t.Fatal(err)
	}
	return names
}

func TestBackupRestore(t *testing.T) {
	env := newEnv(t)
	env.create("/api/objects", map[string]any{"name": "nas", "addresses": []string{"192.168.1.10"}})
	env.do("PUT", "/api/settings", map[string]any{"wg_endpoint_host": "old.example.com", "agent_url": "https://10.0.0.1:8443"})
	// Role memberships come back; one of a user deleted since the backup
	// goes with that user.
	if err := CreateUser(env.srv, "stays", "another long password"); err != nil {
		t.Fatal(err)
	}
	if err := CreateUser(env.srv, "gone", "another long password"); err != nil {
		t.Fatal(err)
	}
	if err := env.srv.db.Exec("INSERT INTO roles (name) VALUES ('ops')").Error; err != nil {
		t.Fatal(err)
	}
	if err := env.srv.db.Exec("INSERT INTO role_members (role_id, user_id, level) SELECT r.id, u.id, 'viewer' FROM roles r, users u WHERE u.username IN ('stays', 'gone')"); err.Error != nil || err.RowsAffected != 2 {
		t.Fatalf("role member: %v %d", err.Error, err.RowsAffected)
	}
	data := env.backup()

	// The download is age encrypted with the passphrase.
	id, _ := age.NewScryptIdentity(testPassphrase)
	r, err := age.Decrypt(bytes.NewReader(data), id)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(r)
	if !bytes.HasPrefix(plain, sqliteMagic) {
		t.Fatal("decrypted backup is not SQLite")
	}

	// Change things after the backup.
	env.create("/api/objects", map[string]any{"name": "printer", "addresses": []string{"192.168.1.20"}})
	env.do("PUT", "/api/settings", map[string]any{"wg_endpoint_host": "new.example.com", "agent_url": "https://10.0.0.2:8443", "agent_token": "new-token"})
	env.srv.db.Model(&models.Settings{}).Where("id = 1").Update("generation", 7)
	if err := env.srv.db.Exec("DELETE FROM users WHERE username = 'gone'").Error; err != nil {
		t.Fatal(err)
	}
	if err := CreateUser(env.srv, "later", "another long password"); err != nil {
		t.Fatal(err)
	}

	for _, body := range []map[string]any{
		{"data": data, "passphrase": "wrong passphrase!"},
		{"data": []byte("garbage"), "passphrase": testPassphrase},
		{"data": append([]byte(nil), plain[:len(plain)/2]...)},
	} {
		if rec := env.do("POST", "/api/backup/restore", body); rec.Code != http.StatusBadRequest {
			t.Errorf("restore %.20q: %d %s", body["data"], rec.Code, rec.Body)
		}
	}
	if got := objectNames(t, env); strings.Join(got, ",") != "nas,printer" {
		t.Fatalf("a failed restore changed the database: %v", got)
	}

	if rec := env.do("POST", "/api/backup/restore", map[string]any{"data": data, "passphrase": testPassphrase}); rec.Code != http.StatusOK {
		t.Fatalf("restore: %d %s", rec.Code, rec.Body)
	}
	if got := objectNames(t, env); strings.Join(got, ",") != "nas" {
		t.Errorf("objects after restore: %v", got)
	}
	st, _ := env.srv.settings()
	if st.WgEndpointHost != "old.example.com" {
		t.Errorf("settings not restored: %q", st.WgEndpointHost)
	}
	// This installation's agent connection, generation and users stay.
	if st.AgentURL != "https://10.0.0.2:8443" || st.AgentToken != "new-token" || st.Generation != 7 {
		t.Errorf("agent settings: %q %q %d", st.AgentURL, st.AgentToken, st.Generation)
	}
	var n int64
	env.srv.db.Model(&models.User{}).Where("username = ?", "later").Count(&n)
	if n != 1 {
		t.Error("restore replaced the users")
	}
	var members []string
	env.srv.db.Raw("SELECT u.username FROM role_members m JOIN users u ON u.id = m.user_id").Scan(&members)
	if strings.Join(members, ",") != "stays" {
		t.Errorf("role members after restore: %v", members)
	}
	if rec := env.do("GET", "/api/me", nil); rec.Code != http.StatusOK {
		t.Errorf("session after restore: %d", rec.Code)
	}
	// A new row does not reuse the id of a row the restore removed.
	var printerID, next uint
	env.srv.db.Raw("SELECT seq FROM sqlite_sequence WHERE name = 'address_objects'").Scan(&printerID)
	next = env.create("/api/objects", map[string]any{"name": "scanner", "addresses": []string{"192.168.1.30"}})
	if next <= printerID {
		t.Errorf("id %d reused (sequence was %d)", next, printerID)
	}

	// An unencrypted database file restores too.
	if rec := env.do("POST", "/api/backup/restore", map[string]any{"data": plain}); rec.Code != http.StatusOK {
		t.Fatalf("plain restore: %d %s", rec.Code, rec.Body)
	}
	if got := objectNames(t, env); strings.Join(got, ",") != "nas" {
		t.Errorf("objects after plain restore: %v", got)
	}
}

func TestBackupPassphrase(t *testing.T) {
	env := newEnv(t)
	if rec := env.do("POST", "/api/backup", map[string]string{"passphrase": "short"}); rec.Code != http.StatusBadRequest {
		t.Errorf("short passphrase: %d", rec.Code)
	}
}

func TestRestoreRefusesNewerSchema(t *testing.T) {
	env := newEnv(t)
	path := filepath.Join(t.TempDir(), "snap.db")
	if err := env.srv.db.Exec("VACUUM INTO ?", path).Error; err != nil {
		t.Fatal(err)
	}
	// Pretend the backup comes from a later version.
	bk, err := dbmigrate.Open(path, &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	bk.Exec("INSERT INTO goose_db_version (version_id, is_applied) VALUES (99999, 1)")
	sqlDB, _ := bk.DB()
	sqlDB.Close()
	_, err = restoreDatabase(t.Context(), env.srv.db, path)
	if err == nil || !strings.Contains(err.Error(), "newer Portitor") {
		t.Errorf("newer schema: %v", err)
	}
}
