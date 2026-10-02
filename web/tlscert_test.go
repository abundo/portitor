// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
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

func TestWebCertificate(t *testing.T) {
	env := newEnv(t)
	fake := &certFakeAgent{}
	env.srv.newAgent = func(*models.Settings) (agentAPI, error) { return fake, nil }
	env.srv.cfg.DB.Path = t.TempDir() + "/portitor.db"
	fb := testCertFiles(t, "fallback.example.com")
	fallback, err := tls.X509KeyPair([]byte(fb.FullChain), []byte(fb.PrivKey))
	if err != nil {
		t.Fatal(err)
	}
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	wan := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "wan", "ipv4_mode": "dhcp", "enabled": true})
	id := env.create("/api/certificates", map[string]any{"instance_id": inst, "name": "web", "enabled": true,
		"interface_id": wan, "domains": []string{"a.example.com"}})

	tc := env.srv.newTLSCert(&fallback)
	env.srv.webCert = tc
	dns := func() string {
		c, _ := tc.get(nil)
		x, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil || len(x.DNSNames) == 0 {
			return ""
		}
		return x.DNSNames[0]
	}
	// None chosen: tls_cert.
	if chosen, err := tc.fetch(context.Background()); chosen || err != nil || dns() != "fallback.example.com" {
		t.Fatalf("none chosen: %v %v %q", chosen, err, dns())
	}
	if rec := env.do("PUT", "/api/settings", map[string]any{"web_certificate_id": 9999}); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown certificate accepted: %d", rec.Code)
	}
	if rec := env.do("PUT", "/api/settings", map[string]any{"web_certificate_id": id}); rec.Code != http.StatusOK {
		t.Fatalf("choose: %d %s", rec.Code, rec.Body)
	}
	// Chosen but not issued yet: still tls_cert.
	if chosen, err := tc.fetch(context.Background()); !chosen || err == nil || dns() != "fallback.example.com" {
		t.Fatalf("not issued: %v %v %q", chosen, err, dns())
	}
	fake.files = testCertFiles(t, "a.example.com")
	if _, err := tc.fetch(context.Background()); err != nil || dns() != "a.example.com" || fake.asked != "main/web" {
		t.Fatalf("fetch: %v %q %q", err, dns(), fake.asked)
	}
	// Renewed: swapped in without a restart.
	fake.files = testCertFiles(t, "b.example.com")
	if _, err := tc.fetch(context.Background()); err != nil || dns() != "b.example.com" {
		t.Fatalf("renewed: %v %q", err, dns())
	}
	if fi, err := os.Stat(tc.cache); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache: %v", err)
	}
	// A restart with the agent down uses the cached one.
	fake.files = nil
	tc = env.srv.newTLSCert(&fallback)
	if dns() != "b.example.com" {
		t.Fatalf("cached: %q", dns())
	}
	// Cleared: back to tls_cert at once, cache gone.
	env.srv.webCert = tc
	if rec := env.do("PUT", "/api/settings", map[string]any{"web_certificate_id": 0}); rec.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", rec.Code, rec.Body)
	}
	if _, err := os.Stat(tc.cache); dns() != "fallback.example.com" || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleared: %q %v", dns(), err)
	}
	// Deleting the chosen certificate clears the choice.
	env.do("PUT", "/api/settings", map[string]any{"web_certificate_id": id})
	if rec := env.do("DELETE", fmt.Sprintf("/api/certificates/%v", id), nil); rec.Code >= 300 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if st, _ := env.srv.settings(); st.WebCertificateID != nil {
		t.Fatalf("choice kept: %v", *st.WebCertificateID)
	}
}
