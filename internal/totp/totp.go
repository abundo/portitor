// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package totp is TOTP (RFC 6238: HMAC-SHA1, 30 s steps, 6 digits, what
// every authenticator app does), shared by portitor-config's two-factor
// login and the agent's OpenVPN logins.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	Period = 30
	Digits = 6
	// Skew steps before and after now are accepted too (clock drift).
	Skew = 1
)

// Encoding is a secret's: base32 without padding.
var Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// ValidSecret tells whether s is a secret Match can use.
func ValidSecret(s string) bool {
	key, err := Encoding.DecodeString(s)
	return err == nil && len(key) >= 10
}

// Code is the code of a step (RFC 4226 dynamic truncation).
func Code(key []byte, step int64) string {
	m := hmac.New(sha1.New, key)
	_ = binary.Write(m, binary.BigEndian, uint64(step))
	sum := m.Sum(nil)
	o := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", Digits, v%1000000)
}

// Match returns the step of now's window whose code is code, or 0.
func Match(secret, code string, now time.Time) int64 {
	key, err := Encoding.DecodeString(secret)
	if err != nil || len(code) != Digits {
		return 0
	}
	cur := now.Unix() / Period
	for step := cur - Skew; step <= cur+Skew; step++ {
		if subtle.ConstantTimeCompare([]byte(Code(key, step)), []byte(code)) == 1 {
			return step
		}
	}
	return 0
}
