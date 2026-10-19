// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/http01"

	"github.com/abundo/portitor/internal/acme"
	"github.com/abundo/portitor/internal/acmeserver"
	"github.com/abundo/portitor/internal/dyndns"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

// acmeProxyItem is an instance's ACME proxy as the applied document
// declares it.
type acmeProxyItem struct {
	instance, netns string
	cfg             fwconfig.ACMEProxy
	// addrs are the proxy's interfaces' static addresses, the self-signed
	// certificate's SANs.
	addrs []string
}

// issueLogSize is how many issued certificates an instance's log keeps.
const issueLogSize = 50

// preauthKeep is how long a successful upstream authorization of a set
// of names is taken as done, so a client ordering it again doesn't start
// another one.
const preauthKeep = time.Hour

// acmeProxyManager runs each instance's ACME proxy (fwconfig.ACMEProxy):
// an acmeserver.Server on its port in the instance's namespace. A name a
// client orders is authorized upstream at once (preauthorize), as its
// policy says: by DNS-01 through the policy's DNS update client, or by
// HTTP-01 answered on port 80 of the instance (certManager's
// http01Server), while the client answers its own HTTP-01 challenge,
// which the agent checks from the instance; finalizing
// then orders the certificate for the client's CSR, reusing those
// authorizations. Upstream orders run one at a time with the
// certificates' (certManager.order).
type acmeProxyManager struct {
	dryRun bool
	paths  render.Paths
	certs  *certManager
	// The upstream calls (acme.Authorize, acme.ObtainForCSR; fakes in
	// tests) and the HTTP-01 check.
	authorize func(accountsDir string, req acme.Request) error
	obtain    func(accountsDir string, req acme.Request, csr *x509.CertificateRequest) ([]byte, error)
	validate  func(ctx context.Context, it acmeProxyItem, name, token, keyAuth string, client netip.Addr) error

	mu   sync.Mutex
	runs map[string]*proxyRun
}

type proxyRun struct {
	item acmeProxyItem
	srv  *http.Server
	acme *acmeserver.Server
	dir  string
	// Under acmeProxyManager.mu:
	state, err string
	selfSigned []byte
	issued     []ACMEProxyIssue
	preauth    map[string]*preauth // by the names, joined with ","
}

type preauth struct {
	done chan struct{}
	err  error
	at   time.Time
}

func newACMEProxyManager(dryRun bool, paths render.Paths, certs *certManager) *acmeProxyManager {
	return &acmeProxyManager{
		dryRun: dryRun, paths: paths, certs: certs,
		authorize: acme.Authorize, obtain: acme.ObtainForCSR, validate: validateHTTP01,
		runs: map[string]*proxyRun{},
	}
}

// Reconcile starts the proxies of want, restarts the changed ones and
// stops the rest.
func (m *acmeProxyManager) Reconcile(want []acmeProxyItem) {
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := map[string]bool{}
	for _, it := range want {
		keep[it.instance] = true
		if r, ok := m.runs[it.instance]; ok {
			if reflect.DeepEqual(r.item, it) {
				continue
			}
			m.stop(r)
		}
		m.runs[it.instance] = m.start(it)
	}
	for name, r := range m.runs {
		if !keep[name] {
			m.stop(r)
			delete(m.runs, name)
		}
	}
}

func (m *acmeProxyManager) Stop() { m.Reconcile(nil) }

// stop closes a proxy's listener and waits for its validations and
// orders; called with m.mu held, which they don't take until they end.
func (m *acmeProxyManager) stop(r *proxyRun) {
	if r.srv != nil {
		r.srv.Close()
	}
	if r.acme != nil {
		// Its hooks take m.mu: wait without it.
		m.mu.Unlock()
		r.acme.Close()
		m.mu.Lock()
	}
}

func (m *acmeProxyManager) start(it acmeProxyItem) *proxyRun {
	r := &proxyRun{item: it, dir: m.paths.ACMEProxyDir(it.instance), preauth: map[string]*preauth{}}
	r.issued = loadIssued(r.dir)
	if m.dryRun {
		r.state = "dry-run"
		return r
	}
	fail := func(err error) *proxyRun {
		r.state, r.err = "error", err.Error()
		slog.Error("acme proxy", "instance", it.instance, "err", err)
		return r
	}
	self, err := selfSigned(r.dir, it.instance, it.addrs)
	if err != nil {
		return fail(fmt.Errorf("self-signed certificate: %w", err))
	}
	r.selfSigned = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: self.Certificate[0]})
	s, err := acmeserver.New(filepath.Join(r.dir, "accounts.json"), acmeserver.Hooks{
		Authorize: func(name string, client netip.Addr) error {
			if it.cfg.Policy(name, client) == nil {
				return fmt.Errorf("no policy allows it from %s", client)
			}
			return nil
		},
		Validate: func(ctx context.Context, name, token, keyAuth string, client netip.Addr) error {
			return m.validate(ctx, it, name, token, keyAuth, client)
		},
		Ordered: func(names []string, client netip.Addr) { m.preauthorize(r, names, client) },
		Issue: func(ctx context.Context, csr *x509.CertificateRequest, names []string, client netip.Addr) ([]byte, error) {
			return m.issue(ctx, r, csr, names, client)
		},
	})
	if err != nil {
		return fail(err)
	}
	var ln net.Listener
	err = withNetns(it.netns, func() error {
		var e error
		ln, e = net.Listen("tcp", ":"+strconv.Itoa(it.cfg.Port))
		return e
	})
	if err != nil {
		s.Close()
		return fail(fmt.Errorf("port %d: %w", it.cfg.Port, err))
	}
	tc := &tlsCert{dir: "", self: self}
	if it.cfg.Certificate != "" {
		tc.dir = m.paths.CertificateDir(it.instance, it.cfg.Certificate)
	}
	r.acme = s
	r.srv = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: tc.get},
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
	}
	go func() {
		if err := r.srv.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			m.mu.Lock()
			r.state, r.err = "error", err.Error()
			m.mu.Unlock()
		}
	}()
	r.state = "running"
	slog.Info("acme proxy listening", "instance", it.instance, "port", it.cfg.Port)
	return r
}

// upstream is the request of an upstream order of names for client: the
// proxy's CA, and the challenge of the names' policies. With DNS-01 each
// name's TXT record is written through its own policy's DNS update
// client; with HTTP-01 the agent answers on port 80 of the instance until
// done is called. lego picks one challenge for all the names of an order,
// so their policies must agree.
func (m *acmeProxyManager) upstream(it acmeProxyItem, names []string, client netip.Addr) (req acme.Request, done func(), err error) {
	dir, err := fwconfig.ACMEDirectory(it.cfg.CA)
	if err != nil {
		return acme.Request{}, nil, err
	}
	req = acme.Request{Directory: dir, Email: it.cfg.Email, Domains: names}
	p := &multiDNS01{by: map[string]challenge.ProviderTimeout{}}
	clients := map[string]challenge.ProviderTimeout{}
	http01 := false
	for i, n := range names {
		pol := it.cfg.Policy(n, client)
		if pol == nil {
			return acme.Request{}, nil, fmt.Errorf("%s: no policy allows it from %s", n, client)
		}
		if i > 0 && pol.HTTP01() != http01 {
			return acme.Request{}, nil, fmt.Errorf("%s and %s are validated upstream by different challenges: order them separately", names[0], n)
		}
		http01 = pol.HTTP01()
		if http01 {
			continue
		}
		d := pol.DNS01
		if d == nil {
			return acme.Request{}, nil, fmt.Errorf("%s: policy %s has no DNS update client", n, pol.Name)
		}
		if clients[d.Client] == nil {
			u, err := dyndns.NewTXTUpdater(*d, instanceDNSEnv(it.netns))
			if err != nil {
				return acme.Request{}, nil, fmt.Errorf("DNS update %s: %w", d.Client, err)
			}
			clients[d.Client] = acme.NewDNS01(u)
		}
		p.by[n] = clients[d.Client]
	}
	if http01 {
		s := &http01Server{m: m.certs, netns: it.netns, tokens: map[string]string{}}
		req.HTTP01 = s
		return req, s.close, nil
	}
	req.DNS01 = p
	return req, func() {}, nil
}

// preauthorize starts the upstream authorization of an order's names,
// unless one is running or recently done.
func (m *acmeProxyManager) preauthorize(r *proxyRun, names []string, client netip.Addr) {
	key := strings.Join(names, ",")
	m.mu.Lock()
	if p := r.preauth[key]; p != nil {
		select {
		case <-p.done:
			if p.err == nil && time.Since(p.at) < preauthKeep {
				m.mu.Unlock()
				return
			}
		default:
			m.mu.Unlock()
			return
		}
	}
	for k, p := range r.preauth {
		select {
		case <-p.done:
			if time.Since(p.at) >= preauthKeep {
				delete(r.preauth, k)
			}
		default:
		}
	}
	p := &preauth{done: make(chan struct{})}
	r.preauth[key] = p
	m.mu.Unlock()
	go func() {
		err := m.upstreamCall(func() error {
			req, done, err := m.upstream(r.item, names, client)
			if err != nil {
				return err
			}
			defer done()
			return m.authorize(m.paths.ACMEAccountsDir(), req)
		})
		if err != nil {
			slog.Warn("acme proxy: upstream authorization", "instance", r.item.instance, "names", names, "err", err)
		}
		m.mu.Lock()
		p.err, p.at = err, time.Now()
		m.mu.Unlock()
		close(p.done)
	}()
}

// upstreamCall runs fn after any other upstream order (certManager's
// too).
func (m *acmeProxyManager) upstreamCall(fn func() error) error {
	m.certs.order <- struct{}{}
	defer func() { <-m.certs.order }()
	return fn()
}

// issue gets the certificate of a client's CSR upstream, after the
// names' authorization (whose failure the order then reports itself).
func (m *acmeProxyManager) issue(ctx context.Context, r *proxyRun, csr *x509.CertificateRequest, names []string, client netip.Addr) ([]byte, error) {
	m.mu.Lock()
	p := r.preauth[strings.Join(names, ",")]
	m.mu.Unlock()
	if p != nil {
		select {
		case <-p.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	type result struct {
		chain []byte
		err   error
	}
	done := make(chan result, 1)
	// lego takes no context: the order runs on when ctx ends.
	go func() {
		var chain []byte
		err := m.upstreamCall(func() error {
			req, done, err := m.upstream(r.item, names, client)
			if err != nil {
				return err
			}
			defer done()
			chain, err = m.obtain(m.paths.ACMEAccountsDir(), req, csr)
			return err
		})
		done <- result{chain, err}
	}()
	var res result
	select {
	case res = <-done:
	case <-ctx.Done():
		res.err = ctx.Err()
	}
	m.logIssue(r, names, client, res.chain, res.err)
	return res.chain, res.err
}

func (m *acmeProxyManager) logIssue(r *proxyRun, names []string, client netip.Addr, chain []byte, err error) {
	e := ACMEProxyIssue{Time: time.Now().UTC(), Client: client.String(), Names: names}
	if err != nil {
		e.Error = err.Error()
	} else if b, _ := pem.Decode(chain); b != nil {
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			e.NotAfter, e.Issuer = timePtr(c.NotAfter), c.Issuer.String()
		}
		slog.Info("acme proxy: certificate issued", "instance", r.item.instance, "names", names, "client", client)
	}
	m.mu.Lock()
	r.issued = slices.Insert(r.issued, 0, e)
	if len(r.issued) > issueLogSize {
		r.issued = r.issued[:issueLogSize]
	}
	data, _ := json.MarshalIndent(r.issued, "", "  ")
	m.mu.Unlock()
	if err := writeState(filepath.Join(r.dir, "issued.json"), data); err != nil {
		slog.Error("acme proxy: issue log", "err", err)
	}
}

func loadIssued(dir string) []ACMEProxyIssue {
	var out []ACMEProxyIssue
	if data, err := os.ReadFile(filepath.Join(dir, "issued.json")); err == nil {
		_ = json.Unmarshal(data, &out)
	}
	return out
}

func writeState(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Status returns each proxy's state.
func (m *acmeProxyManager) Status() []ACMEProxyStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []ACMEProxyStatus{}
	for _, r := range m.runs {
		s := ACMEProxyStatus{
			Instance: r.item.instance, Port: r.item.cfg.Port, State: r.state, LastError: r.err,
			Issued: slices.Clone(r.issued),
		}
		if s.Issued == nil {
			s.Issued = []ACMEProxyIssue{}
		}
		if r.item.cfg.Certificate == "" {
			s.SelfSigned = string(r.selfSigned)
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b ACMEProxyStatus) int { return strings.Compare(a.Instance, b.Instance) })
	return out
}

// multiDNS01 answers each domain's DNS-01 challenge through its own
// provider: the names of one order may be allowed by different policies.
type multiDNS01 struct {
	by map[string]challenge.ProviderTimeout
}

func (p *multiDNS01) provider(domain string) (challenge.ProviderTimeout, error) {
	if q := p.by[domain]; q != nil {
		return q, nil
	}
	return nil, fmt.Errorf("%s: no DNS update client", domain)
}

func (p *multiDNS01) Present(domain, token, keyAuth string) error {
	q, err := p.provider(domain)
	if err != nil {
		return err
	}
	return q.Present(domain, token, keyAuth)
}

func (p *multiDNS01) CleanUp(domain, token, keyAuth string) error {
	q, err := p.provider(domain)
	if err != nil {
		return err
	}
	return q.CleanUp(domain, token, keyAuth)
}

func (p *multiDNS01) Timeout() (time.Duration, time.Duration) {
	var timeout, interval time.Duration
	for _, q := range p.by {
		t, i := q.Timeout()
		timeout, interval = max(timeout, t), max(interval, i)
	}
	return timeout, interval
}

// validateHTTP01 checks a client's HTTP-01 challenge from the instance:
// the name, resolved there, must only have addresses in the policy's
// sources, and one of them must answer the key authorization on port 80.
// Redirects are not followed.
func validateHTTP01(ctx context.Context, it acmeProxyItem, name, token, keyAuth string, client netip.Addr) error {
	pol := it.cfg.Policy(name, client)
	if pol == nil {
		return fmt.Errorf("no policy allows it from %s", client)
	}
	addrs, err := resolveAddrs(ctx, it.netns, name, "")
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if !pol.AllowsSource(a) {
			return fmt.Errorf("%s resolves to %s, outside policy %s's sources", name, a, pol.Name)
		}
	}
	var errs []error
	for _, a := range addrs {
		err := fetchToken(ctx, it.netns, a, name, token, keyAuth)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func fetchToken(ctx context.Context, netns string, addr netip.Addr, name, token, keyAuth string) error {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			var c net.Conn
			err := withNetns(netns, func() error {
				var e error
				c, e = (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
				return e
			})
			return c, err
		},
		DisableKeepAlives: true,
	}
	hc := &http.Client{
		Transport:     tr,
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	u := "http://" + netip.AddrPortFrom(addr, 80).String() + http01.ChallengePath(token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Host = name
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", addr, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: http://%s%s answered %s", addr, name, http01.ChallengePath(token), resp.Status)
	}
	if strings.TrimSpace(string(body)) != keyAuth {
		return fmt.Errorf("%s: http://%s%s answered the wrong key authorization", addr, name, http01.ChallengePath(token))
	}
	return nil
}

// tlsCert is the certificate the proxy presents: the instance's chosen
// certificate (dir), read again when its files change, or the
// self-signed one until it exists.
type tlsCert struct {
	dir  string
	self *tls.Certificate

	mu    sync.Mutex
	mtime time.Time
	cert  *tls.Certificate
}

func (c *tlsCert) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c.dir == "" {
		return c.self, nil
	}
	chain := filepath.Join(c.dir, acme.FullChainFile)
	fi, err := os.Stat(chain)
	if err != nil {
		return c.self, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert == nil || !fi.ModTime().Equal(c.mtime) {
		pair, err := tls.LoadX509KeyPair(chain, filepath.Join(c.dir, acme.PrivKeyFile))
		if err != nil {
			slog.Error("acme proxy: certificate", "dir", c.dir, "err", err)
			if c.cert == nil {
				return c.self, nil
			}
			return c.cert, nil
		}
		c.cert, c.mtime = &pair, fi.ModTime()
	}
	return c.cert, nil
}

// selfSigned returns the proxy's self-signed certificate, made when there
// is none or its addresses changed. It is kept, so clients that trust it
// go on doing so.
func selfSigned(dir, instance string, addrs []string) (*tls.Certificate, error) {
	certFile, keyFile := filepath.Join(dir, "selfsigned.crt"), filepath.Join(dir, "selfsigned.key")
	var ips []net.IP
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a); err == nil {
			ips = append(ips, p.Addr().AsSlice())
		}
	}
	if pair, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
		if c, err := x509.ParseCertificate(pair.Certificate[0]); err == nil && time.Now().Before(c.NotAfter.Add(-30*24*time.Hour)) &&
			slices.EqualFunc(c.IPAddresses, ips, func(a, b net.IP) bool { return a.Equal(b) }) {
			return &pair, nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Portitor ACME proxy " + instance},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true, BasicConstraintsValid: true,
		IPAddresses: ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	if err := writeState(keyFile, keyPEM); err != nil {
		return nil, err
	}
	if err := writeState(certFile, certPEM); err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	return &pair, err
}
