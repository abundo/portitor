// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/records"
	"github.com/abundo/portitor/internal/totp"
	"github.com/abundo/portitor/models"
)

// Two-factor login with TOTP (RFC 6238: HMAC-SHA1, 30 s steps, 6 digits,
// what every authenticator app does). A secret is set up pending and on
// only once a code from it was checked; then the login asks for a code, or
// one of the recovery codes, each good once.

const (
	// recoveryCount codes are made at a time.
	recoveryCount = 10
	totpIssuer    = "Portitor"
)

var b32 = totp.Encoding

func newTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

func totpURI(username, secret string) string {
	v := url.Values{"secret": {secret}, "issuer": {totpIssuer}, "algorithm": {"SHA1"},
		"digits": {fmt.Sprint(totp.Digits)}, "period": {fmt.Sprint(totp.Period)}}
	return "otpauth://totp/" + url.PathEscape(totpIssuer+":"+username) + "?" + v.Encode()
}

// normalizeCode drops spaces and dashes, as a code is often typed with them.
func normalizeCode(code string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(code))
}

func hashRecovery(code string) string {
	sum := sha256.Sum256([]byte(normalizeCode(code)))
	return hex.EncodeToString(sum[:])
}

// newRecoveryCodes returns the codes to show (xxxxx-xxxxx, 50 bits each)
// and the JSON of their hashes to store.
func newRecoveryCodes() ([]string, string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
	codes := make([]string, recoveryCount)
	hashes := make([]string, recoveryCount)
	for i := range codes {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, "", err
		}
		for j := range b {
			b[j] = alphabet[int(b[j])%len(alphabet)]
		}
		codes[i] = string(b[:5]) + "-" + string(b[5:])
		hashes[i] = hashRecovery(codes[i])
	}
	j, err := json.Marshal(hashes)
	return codes, string(j), err
}

// checkSecondFactor checks a TOTP code or a recovery code of a user with
// two-factor login on, and uses it up: a TOTP step is good once, a
// recovery code is removed. The updates are conditional, so two requests
// can't both use one code.
func checkSecondFactor(rec records.Store, u *models.User, code string) (bool, error) {
	code = normalizeCode(code)
	if step := totp.Match(u.TOTPSecret, code, time.Now()); step != 0 {
		return rec.UseTOTPStep(u.ID, step)
	}
	if code == "" || u.RecoveryCodes == "" {
		return false, nil
	}
	var hashes []string
	if err := json.Unmarshal([]byte(u.RecoveryCodes), &hashes); err != nil {
		return false, err
	}
	h := hashRecovery(code)
	for i, stored := range hashes {
		if subtle.ConstantTimeCompare([]byte(stored), []byte(h)) == 1 {
			rest, err := json.Marshal(append(hashes[:i:i], hashes[i+1:]...))
			if err != nil {
				return false, err
			}
			ok, err := rec.UseRecoveryCode(u.ID, u.RecoveryCodes, string(rest))
			if ok {
				slog.Info("recovery code used", "user", u.Username, "left", len(hashes)-1)
			}
			return ok, err
		}
	}
	return false, nil
}

// recoveryLeft counts a user's unused recovery codes.
func recoveryLeft(u *models.User) int {
	var hashes []string
	_ = json.Unmarshal([]byte(u.RecoveryCodes), &hashes)
	return len(hashes)
}

// ownTOTP checks that the caller may change their own two-factor login,
// with their password when the request has one.
func (s *Server) ownTOTP(c *echo.Context, password *string) (*models.User, error) {
	u := currentUser(c)
	if password != nil && !checkPassword(c.Request().Context(), s, u, *password) {
		return nil, errJSON(c, http.StatusForbidden, "password is wrong")
	}
	return u, nil
}

// handleTOTPStatus tells whether the caller has two-factor login on and
// how many recovery codes are left.
func (s *Server) handleTOTPStatus(c *echo.Context) error {
	u := currentUser(c)
	return c.JSON(http.StatusOK, map[string]any{"enabled": u.TOTPSecret != "", "recovery_left": recoveryLeft(u)})
}

// handleTOTPSetup makes a new pending secret for the caller, after their
// password. Two-factor login stays as it was until enable checks a code.
func (s *Server) handleTOTPSetup(c *echo.Context) error {
	var req struct {
		Password string `json:"password"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	u, err := s.ownTOTP(c, &req.Password)
	if u == nil {
		return err
	}
	secret, err := newTOTPSecret()
	if err != nil {
		return err
	}
	if err := s.rec.BeginTOTP(u, secret); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]string{"secret": secret, "uri": totpURI(u.Username, secret)})
}

// handleTOTPEnable turns on the pending secret once code is one of its
// codes, and answers with new recovery codes, shown this once.
func (s *Server) handleTOTPEnable(c *echo.Context) error {
	var req struct {
		Code string `json:"code"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	u, err := s.ownTOTP(c, nil)
	if u == nil {
		return err
	}
	if u.TOTPPending == "" {
		return errJSON(c, http.StatusBadRequest, "set up two-factor login first")
	}
	step := totp.Match(u.TOTPPending, normalizeCode(req.Code), time.Now())
	if step == 0 {
		return errJSON(c, http.StatusBadRequest, "the code is wrong; check the time on your phone")
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return err
	}
	if err = s.rec.EnableTOTP(u, step, hashes); err != nil {
		return err
	}
	slog.Info("two-factor login enabled", "user", u.Username)
	return c.JSON(http.StatusOK, map[string]any{"recovery_codes": codes})
}

// handleTOTPDisable turns off the caller's two-factor login, after their
// password.
func (s *Server) handleTOTPDisable(c *echo.Context) error {
	var req struct {
		Password string `json:"password"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	u, err := s.ownTOTP(c, &req.Password)
	if u == nil {
		return err
	}
	if u.TOTPRequired {
		return errJSON(c, http.StatusForbidden, "an admin requires two-factor login of your user")
	}
	if err := s.rec.ClearTOTP(u); err != nil {
		return err
	}
	slog.Info("two-factor login disabled", "user", u.Username)
	return c.NoContent(http.StatusNoContent)
}

// handleRecoveryCodes replaces the caller's recovery codes, after their
// password, and answers with the new ones.
func (s *Server) handleRecoveryCodes(c *echo.Context) error {
	var req struct {
		Password string `json:"password"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	u, err := s.ownTOTP(c, &req.Password)
	if u == nil {
		return err
	}
	if u.TOTPSecret == "" {
		return errJSON(c, http.StatusBadRequest, "two-factor login is off")
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return err
	}
	if err := s.rec.SetRecoveryCodes(u, hashes); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"recovery_codes": codes})
}

// handleResetUserTOTP turns off another user's two-factor login (a lost
// phone). They log in with their password alone and may set it up again.
func (s *Server) handleResetUserTOTP(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	if id == currentUser(c).ID {
		return errJSON(c, http.StatusBadRequest, "turn off your own two-factor login under My settings")
	}
	u, err := s.rec.User(id)
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	// A managed user's too: their manager's next commit brings it back.
	if err := s.rec.ClearTOTP(u); err != nil {
		return err
	}
	slog.Info("two-factor login reset", "user", u.Username, "by", currentUser(c).Username)
	return c.NoContent(http.StatusNoContent)
}

// ResetTOTP turns off a user's two-factor login (portitor-config reset-2fa),
// for a user locked out, a managed one included.
func ResetTOTP(s *Server, username string) error {
	u, err := s.rec.UserNamed(username)
	if err != nil {
		return fmt.Errorf("user %s: %w", username, err)
	}
	if err := s.rec.ClearTOTP(u); err != nil {
		return err
	}
	slog.Info("two-factor login reset on the console", "user", u.Username)
	return nil
}
