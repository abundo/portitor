// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/models"
)

type certFakeAgent struct {
	agentAPI
	files *agentapi.CertificateFiles
	asked string
}

func (f *certFakeAgent) Certificate(_ context.Context, instance, name string) (*agentapi.CertificateFiles, error) {
	f.asked = instance + "/" + name
	if f.files == nil {
		return nil, errors.New("no certificate")
	}
	return f.files, nil
}

func testCertFiles(t *testing.T, cn string) *agentapi.CertificateFiles {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{cn},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return &agentapi.CertificateFiles{
		FullChain: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		PrivKey:   string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})),
	}
}

func TestTLSCertificate(t *testing.T) {
	env := newEnv(t)
	fake := &certFakeAgent{}
	env.srv.newAgent = func(*models.Settings) (agentAPI, error) { return fake, nil }
	env.srv.cfg.TLSCertificate = "main/web"
	env.srv.cfg.DB.Path = t.TempDir() + "/portitor.db"

	tc, err := env.srv.newTLSCert()
	if err != nil {
		t.Fatal(err)
	}
	dns := func() string {
		c, _ := tc.get(nil)
		x, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil || len(x.DNSNames) == 0 {
			return ""
		}
		return x.DNSNames[0]
	}
	// None yet: the self-signed fallback.
	if err := tc.fetch(context.Background()); err == nil || dns() != "" {
		t.Fatalf("no certificate: %v %q", err, dns())
	}
	fake.files = testCertFiles(t, "a.example.com")
	if err := tc.fetch(context.Background()); err != nil || dns() != "a.example.com" || fake.asked != "main/web" {
		t.Fatalf("fetch: %v %q %q", err, dns(), fake.asked)
	}
	// Renewed: swapped in without a restart.
	fake.files = testCertFiles(t, "b.example.com")
	if err := tc.fetch(context.Background()); err != nil || dns() != "b.example.com" {
		t.Fatalf("renewed: %v %q", err, dns())
	}
	if fi, err := os.Stat(tc.cache); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache: %v", err)
	}
	// A restart with the agent down uses the cached one.
	fake.files = nil
	tc, err = env.srv.newTLSCert()
	if err != nil || dns() != "b.example.com" {
		t.Fatalf("cached: %v %q", err, dns())
	}
}

func TestTLSCertificateConfig(t *testing.T) {
	for s, ok := range map[string]bool{"main/web": true, "main": false, "Main/web": false, "main/../x": false} {
		c := &Config{JWTSecret: "0123456789abcdef0123456789abcdef", TLSCertificate: s}
		if err := c.validateForServe(); (err == nil) != ok {
			t.Errorf("%q: %v", s, err)
		}
	}
	c := &Config{JWTSecret: "0123456789abcdef0123456789abcdef", TLSCertificate: "main/web", TLSCert: "a", TLSKey: "b"}
	if c.validateForServe() == nil {
		t.Error("tls_certificate with tls_cert accepted")
	}
}
