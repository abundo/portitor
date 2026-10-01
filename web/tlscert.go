// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
)

// certAgent is the part of the agent client tls_certificate uses.
type certAgent interface {
	Certificate(ctx context.Context, instance, name string) (*agentapi.CertificateFiles, error)
}

// tlsCert serves tls_certificate: a certificate from the Certificates page,
// fetched from the agent. The last one fetched is kept next to the database
// (0600), so a restart while the agent is unreachable still has it; until
// there is one, a self-signed certificate keeps the GUI reachable.
type tlsCert struct {
	s              *Server
	instance, name string
	cache          string

	mu       sync.Mutex
	cur      *tls.Certificate
	pem      []byte // chain + key of cur, as cached
	fallback *tls.Certificate
}

const (
	tlsCertRefresh = time.Hour
	tlsCertRetry   = time.Minute
)

func (s *Server) newTLSCert() (*tlsCert, error) {
	inst, name, err := splitTLSCertificate(s.cfg.TLSCertificate)
	if err != nil {
		return nil, err
	}
	t := &tlsCert{s: s, instance: inst, name: name,
		cache: filepath.Join(filepath.Dir(s.cfg.DB.Path), "tls-certificate.pem")}
	if data, err := os.ReadFile(t.cache); err == nil {
		if err := t.set(data); err != nil {
			slog.Warn("tls_certificate: ignoring the cached certificate", "file", t.cache, "err", err)
		}
	}
	if t.fallback, err = selfSigned(); err != nil {
		return nil, err
	}
	return t, nil
}

// set parses chain + key (PEM, one after the other) and makes them current.
func (t *tlsCert) set(data []byte) error {
	c, err := tls.X509KeyPair(data, data)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.cur, t.pem = &c, data
	t.mu.Unlock()
	return nil
}

func (t *tlsCert) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cur != nil {
		return t.cur, nil
	}
	return t.fallback, nil
}

// run fetches the certificate now and then every tlsCertRefresh, every
// tlsCertRetry while there is none.
func (t *tlsCert) run(ctx context.Context) {
	for {
		err := t.fetch(ctx)
		if err != nil {
			slog.Warn("tls_certificate: fetching from the agent", "certificate", t.instance+"/"+t.name, "err", err)
		}
		t.mu.Lock()
		wait := tlsCertRefresh
		if t.cur == nil {
			wait = tlsCertRetry
		}
		t.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (t *tlsCert) fetch(ctx context.Context) error {
	a, _, err := t.s.agent()
	if err != nil {
		return err
	}
	ca, ok := a.(certAgent)
	if !ok {
		return errors.New("agent client cannot fetch certificates")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	f, err := ca.Certificate(ctx, t.instance, t.name)
	if err != nil {
		return err
	}
	data := []byte(f.FullChain + f.PrivKey)
	t.mu.Lock()
	same := bytes.Equal(data, t.pem)
	t.mu.Unlock()
	if same {
		return nil
	}
	if err := t.set(data); err != nil {
		return fmt.Errorf("agent's certificate: %w", err)
	}
	slog.Info("tls_certificate: loaded", "certificate", t.instance+"/"+t.name)
	tmp := t.cache + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, t.cache)
}

// selfSigned makes a throwaway certificate for while there is none.
func selfSigned() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "portitor-web"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
