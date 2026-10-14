// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package acmeserver

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type user struct {
	key *ecdsa.PrivateKey
	reg *registration.Resource
}

func (u *user) GetEmail() string                        { return "" }
func (u *user) GetRegistration() *registration.Resource { return u.reg }
func (u *user) GetPrivateKey() crypto.PrivateKey        { return u.key }

// tokens is lego's HTTP-01 provider: what the client would serve.
type tokens struct {
	mu sync.Mutex
	m  map[string]string
}

func (t *tokens) Present(_, token, keyAuth string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.m[token] = keyAuth
	return nil
}

func (t *tokens) CleanUp(_, token, _ string) error { return nil }

// testCA signs CSRs as the upstream CA would.
func testCA(t *testing.T) func(context.Context, *x509.CertificateRequest, []string, netip.Addr) ([]byte, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return func(_ context.Context, csr *x509.CertificateRequest, names []string, _ netip.Addr) ([]byte, error) {
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: names, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
		d, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, key)
		if err != nil {
			return nil, err
		}
		return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...), nil
	}
}

func setup(t *testing.T, hooks Hooks) (*lego.Client, *tokens, *Server) {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "accounts.json"), hooks)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(s)
	t.Cleanup(func() { srv.Close(); s.Close() })
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u := &user{key: key}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = srv.URL + "/directory"
	cfg.HTTPClient = srv.Client()
	// lego waits for a failed order until its timeout.
	cfg.Certificate.Timeout = 3 * time.Second
	client, err := lego.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tok := &tokens{m: map[string]string{}}
	if err := client.Challenge.SetHTTP01Provider(tok); err != nil {
		t.Fatal(err)
	}
	if u.reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true}); err != nil {
		t.Fatal(err)
	}
	return client, tok, s
}

func TestObtain(t *testing.T) {
	var tok *tokens
	var validated []string
	var mu sync.Mutex
	hooks := Hooks{
		Authorize: func(name string, client netip.Addr) error {
			if !strings.HasSuffix(name, ".lan.example") {
				return errors.New("not allowed")
			}
			if !client.IsLoopback() {
				t.Errorf("client %s", client)
			}
			return nil
		},
		Validate: func(_ context.Context, name, token, keyAuth string, _ netip.Addr) error {
			tok.mu.Lock()
			defer tok.mu.Unlock()
			if tok.m[token] != keyAuth {
				return errors.New("wrong key authorization")
			}
			mu.Lock()
			validated = append(validated, name)
			mu.Unlock()
			return nil
		},
		Issue: testCA(t),
	}
	var ordered []string
	hooks.Ordered = func(names []string, _ netip.Addr) { ordered = append(ordered, names...) }
	client, tk, _ := setup(t, hooks)
	tok = tk
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{"www.lan.example", "a.lan.example"}, Bundle: true})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(res.Certificate)
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(leaf.DNSNames, ","); got != "a.lan.example,www.lan.example" {
		t.Errorf("names %s", got)
	}
	if len(validated) != 2 {
		t.Errorf("validated %v", validated)
	}
	if got := strings.Join(ordered, ","); got != "a.lan.example,www.lan.example" {
		t.Errorf("ordered %s", got)
	}

	// A name no policy allows is refused at the order.
	_, err = client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{"www.example.com"}})
	if err == nil || !strings.Contains(err.Error(), "rejectedIdentifier") {
		t.Errorf("want rejectedIdentifier, got %v", err)
	}
	// So is a wildcard.
	_, err = client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{"*.lan.example"}})
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Errorf("want a wildcard refusal, got %v", err)
	}
}

func TestValidationFails(t *testing.T) {
	issued := false
	hooks := Hooks{
		Authorize: func(string, netip.Addr) error { return nil },
		Validate: func(context.Context, string, string, string, netip.Addr) error {
			return errors.New("connection refused")
		},
		Issue: func(context.Context, *x509.CertificateRequest, []string, netip.Addr) ([]byte, error) {
			issued = true
			return nil, errors.New("no")
		},
	}
	client, _, _ := setup(t, hooks)
	_, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{"www.lan.example"}})
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("want the validation's error, got %v", err)
	}
	if issued {
		t.Error("issued without validation")
	}
}

func TestIssueFails(t *testing.T) {
	hooks := Hooks{
		Authorize: func(string, netip.Addr) error { return nil },
		Validate:  func(context.Context, string, string, string, netip.Addr) error { return nil },
		Issue: func(context.Context, *x509.CertificateRequest, []string, netip.Addr) ([]byte, error) {
			return nil, errors.New("upstream said no")
		},
	}
	client, _, _ := setup(t, hooks)
	_, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{"www.lan.example"}})
	if err == nil || !strings.Contains(err.Error(), "upstream said no") {
		t.Errorf("want the upstream's error, got %v", err)
	}
}

// Accounts survive a restart.
func TestAccountsKept(t *testing.T) {
	file := filepath.Join(t.TempDir(), "accounts.json")
	s, err := New(file, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(s)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u := &user{key: key}
	cfg := lego.NewConfig(u)
	cfg.CADirURL, cfg.HTTPClient = srv.URL+"/directory", srv.Client()
	client, _ := lego.NewClient(cfg)
	if _, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true}); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	s.Close()

	s2, err := New(file, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	srv2 := httptest.NewTLSServer(s2)
	defer srv2.Close()
	cfg.CADirURL, cfg.HTTPClient = srv2.URL+"/directory", srv2.Client()
	client2, _ := lego.NewClient(cfg)
	if _, err := client2.Registration.ResolveAccountByKey(); err != nil {
		t.Errorf("account lost: %v", err)
	}
}
