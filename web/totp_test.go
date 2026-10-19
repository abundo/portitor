// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/abundo/portitor/models"
)

func TestTOTPCode(t *testing.T) {
	// RFC 6238 appendix B, SHA-1, the last 6 of its 8 digits.
	key := []byte("12345678901234567890")
	for _, tc := range []struct {
		unix int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		if got := totpCode(key, tc.unix/totpPeriod); got != tc.want {
			t.Errorf("%d: %s, want %s", tc.unix, got, tc.want)
		}
	}
	secret := b32.EncodeToString(key)
	now := time.Unix(1111111109, 0)
	if totpMatch(secret, "081804", now) == 0 || totpMatch(secret, "081804", now.Add(totpPeriod*time.Second)) == 0 {
		t.Error("code of now (or the step before) refused")
	}
	if totpMatch(secret, "081804", now.Add(3*totpPeriod*time.Second)) != 0 {
		t.Error("old code accepted")
	}
}

func TestTOTPLogin(t *testing.T) {
	env := newEnv(t)
	const pw = "correct horse battery"
	if rec := env.do("POST", "/api/me/totp/setup", map[string]string{"password": "wrong"}); rec.Code != http.StatusForbidden {
		t.Errorf("setup with a wrong password: %d", rec.Code)
	}
	rec := env.do("POST", "/api/me/totp/setup", map[string]string{"password": pw})
	var setup struct{ Secret, URI string }
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &setup) != nil || setup.Secret == "" {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
	// Pending: the login doesn't ask for a code yet.
	env.login("admin", pw)
	if rec := env.do("POST", "/api/me/totp/enable", map[string]string{"code": "000000"}); rec.Code != http.StatusBadRequest {
		t.Errorf("enable with a wrong code: %d", rec.Code)
	}
	key, _ := b32.DecodeString(setup.Secret)
	code := totpCode(key, time.Now().Unix()/totpPeriod)
	rec = env.do("POST", "/api/me/totp/enable", map[string]string{"code": code})
	var enabled struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &enabled) != nil || len(enabled.RecoveryCodes) != recoveryCount {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("GET", "/api/me", nil); !strings.Contains(rec.Body.String(), `"totp_enabled":true`) {
		t.Errorf("me: %s", rec.Body)
	}

	login := func(code string) int {
		env.cookie = nil
		rec := env.do("POST", "/api/login", map[string]string{"username": "admin", "password": pw, "code": code})
		for _, c := range rec.Result().Cookies() {
			if c.Name == cookieName {
				env.cookie = c
			}
		}
		return rec.Code
	}
	if got := login(""); got != http.StatusUnauthorized {
		t.Errorf("login without a code: %d", got)
	}
	// The code enable took is used up.
	if got := login(code); got != http.StatusUnauthorized {
		t.Errorf("login with a used code: %d", got)
	}
	env.srv.db.Model(&models.User{}).Where("username = ?", "admin").Update("totp_last_step", 0)
	if got := login(code); got != http.StatusOK {
		t.Errorf("login with a code: %d", got)
	}
	rc := enabled.RecoveryCodes[0]
	if got := login(" " + rc + " "); got != http.StatusOK {
		t.Errorf("login with a recovery code: %d", got)
	}
	if got := login(rc); got != http.StatusUnauthorized {
		t.Errorf("login with a used recovery code: %d", got)
	}
	if got := login(enabled.RecoveryCodes[1]); got != http.StatusOK {
		t.Fatalf("login with another recovery code: %d", got)
	}

	// Another admin resets it; the user logs in with the password alone.
	if err := CreateUser(env.srv, "other", pw); err != nil {
		t.Fatal(err)
	}
	var admin models.User
	env.srv.db.Where("username = ?", "admin").First(&admin)
	env.login("other", pw)
	if rec := env.do("DELETE", "/api/users/"+itoa(admin.ID)+"/totp", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	if got := login(""); got != http.StatusOK {
		t.Errorf("login after reset: %d", got)
	}
}

func TestTOTPRequired(t *testing.T) {
	env := newEnv(t)
	const pw = "correct horse battery"
	if rec := env.do("PUT", "/api/settings", map[string]any{"totp_default": true}); rec.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	id := env.create("/api/users", map[string]any{"username": "bob", "password": pw, "role": "admin"})
	var bob models.User
	env.srv.db.First(&bob, id)
	if !bob.TOTPRequired {
		t.Fatal("the default under Settings was not copied")
	}
	off := env.create("/api/users", map[string]any{"username": "carol", "password": pw, "role": "viewer", "totp_required": false})
	var carol models.User
	env.srv.db.First(&carol, off)
	if carol.TOTPRequired {
		t.Error("totp_required false not kept")
	}

	// Until bob sets it up, he may do that and nothing else.
	env.login("bob", pw)
	if rec := env.do("GET", "/api/users", nil); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "totp_setup_required") {
		t.Errorf("before setup: %d %s", rec.Code, rec.Body)
	}
	rec := env.do("POST", "/api/me/totp/setup", map[string]string{"password": pw})
	var setup struct{ Secret string }
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &setup) != nil {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
	key, _ := b32.DecodeString(setup.Secret)
	if rec := env.do("POST", "/api/me/totp/enable", map[string]string{"code": totpCode(key, time.Now().Unix()/totpPeriod)}); rec.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("GET", "/api/users", nil); rec.Code != http.StatusOK {
		t.Errorf("after setup: %d %s", rec.Code, rec.Body)
	}

	// An admin turns the requirement on.
	if rec := env.do("PUT", "/api/users/"+itoa(off), map[string]any{"role": "viewer", "totp_required": true}); rec.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}
	env.srv.db.First(&carol, off)
	if !carol.TOTPRequired {
		t.Error("totp_required not set")
	}
}
