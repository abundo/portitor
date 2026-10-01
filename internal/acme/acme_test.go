// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// SelfSigned is a certificate for domains, valid from notBefore for 90
// days, PEM encoded, as an ACME CA would answer.
func selfSigned(t *testing.T, notBefore time.Time, domains ...string) *Result {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domains[0]}, Issuer: pkix.Name{CommonName: "test CA"},
		DNSNames: domains, NotBefore: notBefore, NotAfter: notBefore.Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return &Result{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}),
	}
}

func TestSaveLoad(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "www")
	if Load(dir) != nil {
		t.Fatal("Load of nothing")
	}
	req := Request{Directory: "https://ca.example/dir", KeyType: "ec256", Domains: []string{"www.example.com", "example.com"}}
	start := time.Now().Truncate(time.Second).UTC()
	if _, err := Save(dir, req, selfSigned(t, start, "www.example.com", "example.com")); err != nil {
		t.Fatal(err)
	}
	st := Load(dir)
	if st == nil || !st.Matches(req) || !st.NotBefore.Equal(start) {
		t.Fatalf("got %+v", st)
	}
	if want := start.Add(60 * 24 * time.Hour); !st.RenewAt().Equal(want) {
		t.Errorf("renew at %v, want %v", st.RenewAt(), want)
	}
	for _, other := range []Request{
		{Directory: req.Directory, KeyType: "rsa2048", Domains: req.Domains},
		{Directory: "https://other.example/dir", KeyType: "ec256", Domains: req.Domains},
		{Directory: req.Directory, KeyType: "ec256", Domains: []string{"www.example.com"}},
	} {
		if st.Matches(other) {
			t.Errorf("matches %+v", other)
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, PrivKeyFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v %v", fi, err)
	}
}

func TestAccount(t *testing.T) {
	dir := t.TempDir()
	a, err := loadAccount(dir, "https://ca.example/dir", "admin@example.com")
	if err != nil || a.key == nil || a.Registration != nil {
		t.Fatalf("new account: %+v %v", a, err)
	}
	b, err := loadAccount(dir, "https://ca.example/dir", "admin@example.com")
	if err != nil || !b.key.(*ecdsa.PrivateKey).Equal(a.key) {
		t.Fatalf("reload: %v", err)
	}
	c, err := loadAccount(dir, "https://ca.example/dir", "")
	if err != nil || c.key.(*ecdsa.PrivateKey).Equal(a.key) {
		t.Fatalf("other email shares the key: %v", err)
	}
}
