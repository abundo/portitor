// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/http01"

	"github.com/abundo/portitor/internal/acme"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

type certKey struct{ instance, name string }

// certItem is a certificate as the applied document declares it.
type certItem struct {
	instance, netns string
	cfg             fwconfig.Certificate
}

// Waits between attempts after a failed order, doubling up to the last.
// Let's Encrypt allows few failed validations an hour.
const (
	certRetryMin = 10 * time.Minute
	certRetryMax = 12 * time.Hour
	// certCheck is the longest sleep: the stored certificate is looked at
	// again at least this often.
	certCheck = 12 * time.Hour
)

// certManager gets and renews each certificate of the applied document
// from its ACME CA. Orders run one at a time; the CA's HTTP-01 requests
// are answered by a server in the instance's namespace, on port 80, which
// the instance's ruleset opens only while it runs (render.ACMEHTTPSet).
type certManager struct {
	dryRun bool
	paths  render.Paths
	// run opens and closes port 80 (nft), outside an apply's log.
	run Runner
	// obtain gets a certificate (acme.Obtain; a fake in tests).
	obtain func(accountsDir string, req acme.Request) (*acme.Result, error)

	mu    sync.Mutex
	certs map[certKey]*certRun
	// open counts the challenge servers running per namespace: an apply
	// reloads the ruleset, which empties the set, so it is filled again.
	open map[string]int
	wg   sync.WaitGroup

	order chan struct{} // one order at a time
}

type certRun struct {
	item   certItem
	cancel context.CancelFunc
	// Under certManager.mu:
	state, err  string
	stored      *acme.Stored
	lastAttempt time.Time
	next        time.Time
}

func newCertManager(dryRun bool, paths render.Paths, run Runner) *certManager {
	return &certManager{
		dryRun: dryRun, paths: paths, run: run, obtain: acme.Obtain,
		certs: map[certKey]*certRun{}, open: map[string]int{}, order: make(chan struct{}, 1),
	}
}

// Reconcile starts a loop for each new certificate, restarts changed ones
// and stops removed ones (their files stay). It runs after an apply has
// loaded the rulesets, so it opens port 80 again where a challenge is
// being answered.
func (m *certManager) Reconcile(ctx context.Context, want []certItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := map[certKey]bool{}
	for _, it := range want {
		k := certKey{it.instance, it.cfg.Name}
		keep[k] = true
		if r, ok := m.certs[k]; ok {
			if reflect.DeepEqual(r.item, it) {
				continue
			}
			r.cancel()
		}
		m.certs[k] = m.start(it)
	}
	for k, r := range m.certs {
		if !keep[k] {
			r.cancel()
			delete(m.certs, k)
		}
	}
	for ns, n := range m.open {
		if n > 0 {
			m.setPort(ctx, ns, true)
		}
	}
}

func (m *certManager) Stop() {
	m.Reconcile(context.Background(), nil)
	m.wg.Wait()
}

func (m *certManager) start(it certItem) *certRun {
	ctx, cancel := context.WithCancel(context.Background())
	r := &certRun{item: it, cancel: cancel, stored: acme.Load(m.dir(it))}
	if m.dryRun {
		r.state = "dry-run"
		return r
	}
	r.state = "pending"
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.loop(ctx, r)
	}()
	return r
}

func (m *certManager) dir(it certItem) string {
	return m.paths.CertificateDir(it.instance, it.cfg.Name)
}

func certRequest(c fwconfig.Certificate) (acme.Request, error) {
	dir, err := fwconfig.ACMEDirectory(c.CA)
	return acme.Request{Directory: dir, Email: c.Email, KeyType: c.KeyType, Domains: c.Domains}, err
}

// loop gets the certificate when there is none for the current settings
// and renews it when due, until ctx is done.
func (m *certManager) loop(ctx context.Context, r *certRun) {
	log := slog.With("instance", r.item.instance, "certificate", r.item.cfg.Name)
	req, err := certRequest(r.item.cfg)
	if err != nil {
		m.update(r, func() { r.state, r.err = "error", err.Error() })
		return
	}
	retry := certRetryMin
	for {
		st := acme.Load(m.dir(r.item))
		var wait time.Duration
		if st != nil && st.Matches(req) && time.Now().Before(st.RenewAt()) {
			m.update(r, func() { r.stored, r.state, r.err = st, "ok", "" })
			wait = min(time.Until(st.RenewAt()), certCheck)
		} else {
			m.update(r, func() { r.state, r.lastAttempt, r.next = "issuing", time.Now(), time.Time{} })
			log.Info("ordering certificate", "domains", req.Domains, "ca", req.Directory)
			st, err := m.order1(ctx, r.item, req)
			if ctx.Err() != nil {
				return
			}
			if err == nil {
				log.Info("certificate saved", "not_after", st.NotAfter)
				retry = certRetryMin
				continue
			}
			log.Error("certificate order failed", "err", err, "retry_in", retry)
			m.update(r, func() { r.state, r.err = "error", err.Error() })
			wait = retry
			retry = min(retry*2, certRetryMax)
		}
		m.update(r, func() { r.next = time.Now().Add(wait) })
		if !sleepCtx(ctx, wait) {
			return
		}
	}
}

func (m *certManager) update(r *certRun, fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn()
}

// order1 runs one order, after any other's. lego takes no context: when
// ctx ends the order runs on, and is saved, but order1 returns.
func (m *certManager) order1(ctx context.Context, it certItem, req acme.Request) (*acme.Stored, error) {
	select {
	case m.order <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	type result struct {
		st  *acme.Stored
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-m.order }()
		p := &http01Server{m: m, netns: it.netns, tokens: map[string]string{}}
		req.HTTP01 = p
		res, err := m.obtain(m.paths.ACMEAccountsDir(), req)
		p.close()
		var st *acme.Stored
		if err == nil {
			st, err = acme.Save(m.dir(it), req, res)
		}
		done <- result{st, err}
	}()
	select {
	case r := <-done:
		return r.st, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// setPort opens or closes port 80 in a namespace's ruleset. Called with
// m.mu held.
func (m *certManager) setPort(ctx context.Context, ns string, open bool) {
	script := render.ACMEHTTPClose
	if open {
		script = render.ACMEHTTPOpen
	}
	if _, err := m.run.RunInput(ctx, ns, []byte(script), "nft", "-f", "-"); err != nil {
		slog.Error("acme: port 80", "netns", ns, "open", open, "err", err)
	}
}

// http01Server answers the HTTP-01 challenges of one order: a server on
// port 80 in the instance's namespace, started at the first challenge and
// closed when the order is done.
type http01Server struct {
	m     *certManager
	netns string

	mu     sync.Mutex
	tokens map[string]string // token -> key authorization
	srv    *http.Server
}

func (p *http01Server) Present(_, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokens[token] = keyAuth
	if p.srv != nil {
		return nil
	}
	var ln net.Listener
	err := withNetns(p.netns, func() error {
		var e error
		ln, e = net.Listen("tcp", ":80")
		return e
	})
	if err != nil {
		return fmt.Errorf("HTTP-01 server on port 80: %w", err)
	}
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := p.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("acme: HTTP-01 server", "netns", p.netns, "err", err)
		}
	}()
	p.m.mu.Lock()
	if p.m.open[p.netns]++; p.m.open[p.netns] == 1 {
		p.m.setPort(context.Background(), p.netns, true)
	}
	p.m.mu.Unlock()
	return nil
}

func (p *http01Server) CleanUp(_, token, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.tokens, token)
	return nil
}

func (p *http01Server) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.srv == nil {
		return
	}
	p.srv.Close()
	p.srv = nil
	p.m.mu.Lock()
	if p.m.open[p.netns]--; p.m.open[p.netns] <= 0 {
		delete(p.m.open, p.netns)
		p.m.setPort(context.Background(), p.netns, false)
	}
	p.m.mu.Unlock()
}

func (p *http01Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.URL.Path, http01.ChallengePath(""))
	p.mu.Lock()
	keyAuth, found := p.tokens[token]
	p.mu.Unlock()
	if !ok || !found || r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(keyAuth))
}

// Status returns every certificate's state, by instance and name.
func (m *certManager) Status() []CertificateStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]CertificateStatus, 0, len(m.certs))
	for k, r := range m.certs {
		s := CertificateStatus{
			Instance: k.instance, Name: k.name, Domains: r.item.cfg.Domains,
			State: r.state, LastError: r.err, Dir: m.dir(r.item),
			LastAttempt: timePtr(r.lastAttempt), NextAttempt: timePtr(r.next),
		}
		if st := r.stored; st != nil {
			s.NotBefore, s.NotAfter, s.Issuer = timePtr(st.NotBefore), timePtr(st.NotAfter), st.Issuer
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b CertificateStatus) int {
		if c := strings.Compare(a.Instance, b.Instance); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
