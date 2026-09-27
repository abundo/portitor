// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wgkeys generates WireGuard (Curve25519) keys in wg(8)'s base64
// format.
package wgkeys

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// Generate returns a new private key and its public key.
func Generate() (priv, pub string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()),
		base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// Public derives the public key of a private key.
func Public(priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid WireGuard private key")
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// PresharedKey returns 32 random bytes, base64.
func PresharedKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}
