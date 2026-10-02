// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/models"
)

// certAgent is the part of the agent client the web certificate uses.
type certAgent interface {
	Certificate(ctx context.Context, instance, name string) (*agentapi.CertificateFiles, error)
}

// tlsCert serves HTTPS for portitor-web: the certificate chosen under
// Settings (Portitor web, settings.web_certificate_id), fetched from the
// agent, or tls_cert while none is chosen or fetched yet. The last one
// fetched is kept next to the database (0600), so a restart while the agent
// is unreachable still has it.
type tlsCert struct {
	s     *Server
	cache string
	kick  chan struct{}

	mu       sync.Mutex
	cur      *tls.Certificate
	pem      []byte // chain + key of cur, as cached
	fallback *tls.Certificate
}

const (
	tlsCertRefresh = time.Hour
	tlsCertRetry   = time.Minute
)

func (s *Server) newTLSCert(fallback *tls.Certificate) *tlsCert {
	t := &tlsCert{s: s, fallback: fallback, kick: make(chan struct{}, 1),
		cache: filepath.Join(filepath.Dir(s.cfg.DB.Path), "tls-certificate.pem")}
	if st, err := s.settings(); err == nil && st.WebCertificateID != nil {
		if data, err := os.ReadFile(t.cache); err == nil {
			if err := t.set(data); err != nil {
				slog.Warn("web certificate: ignoring the cached certificate", "file", t.cache, "err", err)
			}
		}
	}
	return t
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

// reset drops the current certificate and its cache, and fetches the one
// now chosen: the choice changed.
func (t *tlsCert) reset() {
	t.mu.Lock()
	t.cur, t.pem = nil, nil
	t.mu.Unlock()
	if err := os.Remove(t.cache); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("web certificate: removing the cache", "err", err)
	}
	select {
	case t.kick <- struct{}{}:
	default:
	}
}

func (t *tlsCert) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cur != nil {
		return t.cur, nil
	}
	return t.fallback, nil
}

// run fetches the certificate now, then every tlsCertRefresh (every
// tlsCertRetry while a chosen one is missing) and when the choice changes.
func (t *tlsCert) run(ctx context.Context) {
	for {
		chosen, err := t.fetch(ctx)
		if err != nil {
			slog.Warn("web certificate: fetching from the agent", "err", err)
		}
		t.mu.Lock()
		wait := tlsCertRefresh
		if chosen && t.cur == nil {
			wait = tlsCertRetry
		}
		t.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-t.kick:
		case <-time.After(wait):
		}
	}
}

// fetch gets the chosen certificate from the agent; chosen says whether
// one is chosen.
func (t *tlsCert) fetch(ctx context.Context) (chosen bool, err error) {
	st, err := t.s.settings()
	if err != nil {
		return false, err
	}
	if st.WebCertificateID == nil {
		return false, nil
	}
	var cert models.Certificate
	if err := t.s.db.First(&cert, *st.WebCertificateID).Error; err != nil {
		return true, err
	}
	var inst models.Instance
	if err := t.s.db.First(&inst, cert.InstanceID).Error; err != nil {
		return true, err
	}
	a, _, err := t.s.agent()
	if err != nil {
		return true, err
	}
	ca, ok := a.(certAgent)
	if !ok {
		return true, errors.New("agent client cannot fetch certificates")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	f, err := ca.Certificate(ctx, inst.Name, cert.Name)
	if err != nil {
		return true, fmt.Errorf("%s/%s: %w", inst.Name, cert.Name, err)
	}
	data := []byte(f.FullChain + f.PrivKey)
	t.mu.Lock()
	same := bytes.Equal(data, t.pem)
	t.mu.Unlock()
	if same {
		return true, nil
	}
	if err := t.set(data); err != nil {
		return true, fmt.Errorf("agent's certificate %s/%s: %w", inst.Name, cert.Name, err)
	}
	slog.Info("web certificate: loaded", "certificate", inst.Name+"/"+cert.Name)
	tmp := t.cache + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return true, err
	}
	return true, os.Rename(tmp, t.cache)
}
