// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package totp

import (
	"testing"
	"time"
)

func TestCode(t *testing.T) {
	// RFC 6238 appendix B, SHA-1, the last 6 of its 8 digits.
	key := []byte("12345678901234567890")
	for _, tc := range []struct {
		unix int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		if got := Code(key, tc.unix/Period); got != tc.want {
			t.Errorf("%d: %s, want %s", tc.unix, got, tc.want)
		}
	}
	secret := Encoding.EncodeToString(key)
	if !ValidSecret(secret) || ValidSecret("not base32!") || ValidSecret("") {
		t.Error("ValidSecret")
	}
	now := time.Unix(1111111109, 0)
	if Match(secret, "081804", now) == 0 || Match(secret, "081804", now.Add(Period*time.Second)) == 0 {
		t.Error("code of now (or the step before) refused")
	}
	if Match(secret, "081804", now.Add(3*Period*time.Second)) != 0 {
		t.Error("old code accepted")
	}
}
