// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agentclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A wrong token or a certificate other than the pinned one is a refusal,
// said as such; an agent that isn't there is unreachable.
func TestRefused(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"wrong token"}`))
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)
	fp := hex.EncodeToString(sum[:])

	c, _ := New(srv.URL, "bad", fp)
	_, err := c.Status(context.Background())
	if !Refused(err) || !strings.Contains(err.Error(), "refused the token") {
		t.Errorf("wrong token: %v", err)
	}
	c, _ = New(srv.URL, "x", strings.Repeat("ab", 32))
	_, err = c.Status(context.Background())
	if !Refused(err) || !strings.Contains(err.Error(), "fingerprint mismatch") || strings.Contains(err.Error(), "unreachable") {
		t.Errorf("wrong fingerprint: %v", err)
	}
	url := srv.URL
	srv.Close()
	c, _ = New(url, "x", fp)
	if _, err = c.Status(context.Background()); Refused(err) || !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("gone: %v", err)
	}
}
