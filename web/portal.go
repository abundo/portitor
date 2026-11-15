// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
)

// portitor-web is a portal with a configuration of its own, a tree of
// portitor-portal.yang (PortalStore): the firewalls whose GUIs it serves, the
// witness strings of the HA pairs it is the witness of, and its users. It
// serves each firewall at /fw/<name>/, passing the GUI, the API, the console
// and the streams through to that firewall's portitor-config, whose login,
// roles and checks apply as they do there, and shows them as tabs (portal.html).
// The session cookie of each is kept to its path (both hosts' paths for an HA
// pair). A firewall is added by reading its fingerprints over SSH
// (portalssh.go). What it needs to start is web.yaml.

// PortalConfig is /etc/portitor/web.yaml: what portitor-web needs to start.
// The firewalls and the witness strings are the configuration's, in the data
// directory; those listed here are taken in once, when it has none yet.
type PortalConfig struct {
	Bind string `yaml:"bind"`
	// Dev drops the HTTPS requirement of the firewalls' URLs on loopback
	// only; the cookies' Secure flag is portitor-config's.
	Dev bool `yaml:"dev"`
	// TLSCert/TLSKey serve HTTPS directly; otherwise put a reverse proxy
	// in front.
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// DataDir holds portal.json (the configuration) and the session key.
	DataDir string `yaml:"data_dir"`
	// SSHListen serves the configuration's CLI and NETCONF over SSH to the
	// portal's users (empty: not).
	SSHListen string `yaml:"ssh_listen"`
	// Firewalls and Witness of an older web.yaml: taken into the
	// configuration at the first start.
	Firewalls []PortalFirewall `yaml:"firewalls"`
	Witness   []string         `yaml:"witness"`
}

// DefaultPortalDataDir is where portitor-web keeps its files.
const DefaultPortalDataDir = "/var/lib/portitor-web"

// PortalFirewall is one firewall's portitor-config: its URL, and the
// SHA-256 fingerprint of its tls_cert (portitor-config fingerprint).
// portitor-web asks for that certificate by PinnedServerName, so a
// certificate chosen there under Settings changes nothing here.
type PortalFirewall struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description" json:"description,omitempty"`
	URL         string `yaml:"url" json:"url"`
	Fingerprint string `yaml:"fingerprint" json:"fingerprint,omitempty"`
	SSHHostKey  string `yaml:"ssh_host_key" json:"ssh_host_key,omitempty"`
}

func LoadPortalConfig(path string) (*PortalConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &PortalConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Bind == "" {
		cfg.Bind = "127.0.0.1:8080"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = DefaultPortalDataDir
	}
	if err := cfg.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (c *PortalConfig) check() error {
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("tls_cert and tls_key go together")
	}
	seen := map[string]bool{}
	for i := range c.Firewalls {
		if err := CheckPortalFirewall(&c.Firewalls[i]); err != nil {
			return fmt.Errorf("firewalls: %w", err)
		}
		if seen[c.Firewalls[i].Name] {
			return fmt.Errorf("firewalls: %s twice", c.Firewalls[i].Name)
		}
		seen[c.Firewalls[i].Name] = true
	}
	for _, w := range c.Witness {
		if _, err := ParseWitness(w); err != nil {
			return fmt.Errorf("witness: %w", err)
		}
	}
	return nil
}

// CheckPortalFirewall checks a firewall and normalizes its URL and
// fingerprint.
func CheckPortalFirewall(f *PortalFirewall) error {
	// A firewall's own name (fwconfig.ValidDefaultInstanceName).
	if !fwconfig.ValidDefaultInstanceName(f.Name) {
		return fmt.Errorf("name %q: letters, digits, '-', '_' and '.', starting with a letter or digit, at most 63 characters", f.Name)
	}
	f.URL = strings.TrimRight(f.URL, "/")
	u, err := url.Parse(f.URL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("%s: url must be https://<host>:<port> of its portitor-config", f.Name)
	}
	switch {
	case u.Scheme == "https":
		f.Fingerprint = normalizeFingerprint(f.Fingerprint)
		if len(f.Fingerprint) != 64 {
			return fmt.Errorf("%s: fingerprint: the SHA-256 of its tls_cert (portitor-config fingerprint there)", f.Name)
		}
	case u.Scheme == "http" && isLoopback(u.Hostname()):
		// portitor-config on this host, without TLS.
		f.Fingerprint = ""
	default:
		return fmt.Errorf("%s: url must be https:// (http:// only to this host)", f.Name)
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Portal is portitor-web's server.
type Portal struct {
	cfg   *PortalConfig
	store *PortalStore
	key   []byte
	page  *template.Template

	mu      sync.RWMutex
	fws     []PortalFirewall
	proxies map[string]*httputil.ReverseProxy
	clients map[string]*http.Client

	witnessMu     sync.Mutex
	witnessCancel context.CancelFunc
	witnessStrs   []string
	ctx           context.Context

	limits loginLimits
}

//go:embed portal.html portal.js
var portalFS embed.FS

// NewPortal opens the configuration in cfg.DataDir (taking in web.yaml's
// firewalls and witness strings the first time) and makes the proxies.
func NewPortal(cfg *PortalConfig) (*Portal, error) {
	store, err := OpenPortalConfigStore(cfg)
	if err != nil {
		return nil, err
	}
	return NewPortalWith(cfg, store)
}

// OpenPortalConfigStore opens the configuration, taking in web.yaml's
// firewalls and witness strings the first time.
func OpenPortalConfigStore(cfg *PortalConfig) (*PortalStore, error) {
	store, err := OpenPortalStore(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if !store.Exists() {
		if err := importPortalConfig(store, cfg); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// NewPortalWith is NewPortal on a store already open.
func NewPortalWith(cfg *PortalConfig, store *PortalStore) (*Portal, error) {
	p := &Portal{cfg: cfg, store: store, limits: loginLimits{fails: map[string][]time.Time{}}}
	var err error
	if p.page, err = template.ParseFS(portalFS, "portal.html"); err != nil {
		return nil, err
	}
	if p.key, err = loadSessionKey(cfg.DataDir); err != nil {
		return nil, err
	}
	if err := p.reload(); err != nil {
		return nil, err
	}
	store.OnChange(func() {
		if err := p.reload(); err != nil {
			slog.Warn("portal: reload", "err", err)
		}
		p.restartWitness()
	})
	return p, nil
}

// importPortalConfig makes the configuration of an older web.yaml's lists.
func importPortalConfig(store *PortalStore, cfg *PortalConfig) error {
	return store.Edit(func(t *datastore.Tree) error {
		for _, f := range cfg.Firewalls {
			leaves := map[string]string{"name": f.Name, "url": f.URL}
			if f.Fingerprint != "" {
				leaves["fingerprint"] = f.Fingerprint
			}
			if f.Description != "" {
				leaves["description"] = f.Description
			}
			t.Root.AddEntry(t.Root.S.Child("firewall"), leaves)
		}
		for _, str := range cfg.Witness {
			w, _ := ParseWitness(str)
			t.Root.AddEntry(t.Root.S.Child("witness"), map[string]string{"pair": w.Pair, "string": w.String()})
		}
		return nil
	})
}

// reload makes the proxies of the configuration's firewalls.
func (p *Portal) reload() error {
	fws := p.store.Firewalls()
	proxies := map[string]*httputil.ReverseProxy{}
	clients := map[string]*http.Client{}
	for i := range fws {
		f := &fws[i]
		if err := CheckPortalFirewall(f); err != nil {
			slog.Warn("portal: firewall left out", "firewall", f.Name, "err", err)
			continue
		}
		target, _ := url.Parse(f.URL)
		tr := &http.Transport{
			Proxy:                 nil,
			ForceAttemptHTTP2:     false,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute,
		}
		if target.Scheme == "https" {
			tlsCfg, err := agentclient.PinnedTLS("portitor-config "+f.Name, f.Fingerprint)
			if err != nil {
				return err
			}
			tlsCfg.MinVersion = tls.VersionTLS12
			tlsCfg.ServerName = PinnedServerName
			tr.TLSClientConfig = tlsCfg
		}
		proxies[f.Name] = p.proxy(f.Name, target, tr)
		clients[f.Name] = &http.Client{Transport: tr, Timeout: 3 * time.Second}
	}
	p.mu.Lock()
	p.fws, p.proxies, p.clients = fws, proxies, clients
	p.mu.Unlock()
	return nil
}

func (p *Portal) firewalls() []PortalFirewall {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return slices.Clone(p.fws)
}

func (p *Portal) proxyFor(name string) (*httputil.ReverseProxy, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	rp, ok := p.proxies[name]
	return rp, ok
}

// prefix is where a firewall is served.
func portalPrefix(name string) string { return "/fw/" + name }

// proxy passes /fw/<name>/... to the firewall's portitor-config as /...,
// with the prefix in X-Forwarded-Prefix (its index.html takes it as the
// base) and the client's address in X-Forwarded-For (trusted_proxies
// there). The Host header is the browser's, so the console's WebSocket
// passes its origin check, and responses are flushed as they come
// (captures, traces, logs).
func (p *Portal) proxy(name string, target *url.URL, tr http.RoundTripper) *httputil.ReverseProxy {
	prefix := portalPrefix(name)
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Path = strings.TrimPrefix(r.In.URL.Path, prefix)
			// Keep the escaped form: a key with a slash in it
			// (192.168.1.0%2F24) must not become two path steps.
			r.Out.URL.RawPath = strings.TrimPrefix(r.In.URL.EscapedPath(), prefix)
			if r.Out.URL.RawPath == r.Out.URL.Path {
				r.Out.URL.RawPath = ""
			}
			r.SetURL(target)
			r.SetXForwarded()
			r.Out.Host = r.In.Host
			r.Out.Header.Set("X-Forwarded-Prefix", prefix)
			stripPortalCookie(r.Out)
		},
		Transport:     tr,
		FlushInterval: -1,
		ModifyResponse: func(res *http.Response) error {
			paths := []string{prefix}
			if fps := res.Header.Get(PairHeader); fps != "" {
				res.Header.Del(PairHeader)
				paths = p.pairPrefixes(name, strings.Split(fps, ","))
			}
			portalCookies(res.Header, paths)
			if loc := res.Header.Get("Location"); strings.HasPrefix(loc, "/") && !strings.HasPrefix(loc, "//") {
				res.Header.Set("Location", prefix+loc)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("portal: portitor-config unreachable", "firewall", name, "err", err)
			msg := fmt.Sprintf("firewall %s: portitor-config does not answer", name)
			if strings.HasPrefix(strings.TrimPrefix(r.URL.Path, prefix), "/api/") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
				return
			}
			http.Error(w, msg, http.StatusBadGateway)
		},
	}
}

// pairPrefixes are the paths of the firewalls of an HA pair, by the
// fingerprints its portitor-config names (PairHeader): name's, and those of
// the others it pins by one of them, if name is one of them.
func (p *Portal) pairPrefixes(name string, fps []string) []string {
	out := []string{portalPrefix(name)}
	var own string
	fws := p.firewalls()
	for _, f := range fws {
		if f.Name == name {
			own = f.Fingerprint
		}
	}
	if own == "" || !slices.Contains(fps, own) {
		return out
	}
	for _, f := range fws {
		if f.Name != name && f.Fingerprint != "" && slices.Contains(fps, f.Fingerprint) {
			out = append(out, portalPrefix(f.Name))
		}
	}
	return out
}

// portalCookies keeps each firewall's cookies to its path, so the
// sessions of several firewalls live side by side; an HA pair's session is
// set on the paths of both its hosts (pairPrefixes), one login for the two.
func portalCookies(h http.Header, prefixes []string) {
	vals := h.Values("Set-Cookie")
	if len(vals) == 0 {
		return
	}
	h.Del("Set-Cookie")
	for _, v := range vals {
		c, err := http.ParseSetCookie(v)
		if err != nil {
			continue
		}
		path := "/" + strings.TrimPrefix(c.Path, "/")
		for _, prefix := range prefixes {
			c.Path = prefix + path
			h.Add("Set-Cookie", c.String())
		}
	}
}

// Handler serves the portal: its shell and API (behind its own login), and
// each firewall at /fw/<name>/ (behind it too).
func (p *Portal) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", p.handlePage)
	mux.HandleFunc("GET /portal/{$}", p.handlePage)
	mux.HandleFunc("GET /portal/portal.js", p.handleScript)
	mux.HandleFunc("POST /portal/v1/login", p.handleLogin)
	mux.HandleFunc("POST /portal/v1/logout", p.handleLogout)
	mux.HandleFunc("GET /portal/v1/session", p.authed(p.handleSession))
	mux.HandleFunc("GET /portal/v1/firewalls", p.authed(p.handleFirewalls))
	mux.HandleFunc("POST /portal/v1/firewalls", p.authed(p.handlePutFirewall))
	mux.HandleFunc("PUT /portal/v1/firewalls/{name}", p.authed(p.handlePutFirewall))
	mux.HandleFunc("DELETE /portal/v1/firewalls/{name}", p.authed(p.handleDeleteFirewall))
	mux.HandleFunc("POST /portal/v1/probe", p.authed(p.handleProbe))
	mux.HandleFunc("POST /portal/v1/pair", p.authed(p.handlePair))
	mux.HandleFunc("GET /portal/v1/witness", p.authed(p.handleWitnesses))
	mux.HandleFunc("POST /portal/v1/witness", p.authed(p.handlePutWitness))
	mux.HandleFunc("DELETE /portal/v1/witness/{pair}", p.authed(p.handleDeleteWitness))
	mux.HandleFunc("GET /portal/v1/config", p.authed(p.handleConfig))
	mux.HandleFunc("/fw/{name}", p.authed(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := p.proxyFor(r.PathValue("name")); !ok {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, portalPrefix(r.PathValue("name"))+"/", http.StatusFound)
	}))
	mux.HandleFunc("/fw/{name}/", p.authed(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		rp, ok := p.proxyFor(name)
		if !ok {
			http.NotFound(w, r)
			return
		}
		rp.ServeHTTP(w, r)
	}))
	return mux
}

// portalHeaders are the portal's own pages': what the shell frames is its
// own origin (the firewalls at /fw/).
func portalHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
}

// portalStatus is a firewall in the portal's list.
type portalStatus struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
	Path        string `json:"path"`
	Version     string `json:"version,omitempty"`
	Error       string `json:"error,omitempty"`
}

// statuses asks every portitor-config for its version, at once.
func (p *Portal) statuses(ctx context.Context) []portalStatus {
	fws := p.firewalls()
	out := make([]portalStatus, len(fws))
	var wg sync.WaitGroup
	for i, f := range fws {
		out[i] = portalStatus{Name: f.Name, Description: f.Description, URL: f.URL, Path: portalPrefix(f.Name) + "/"}
		p.mu.RLock()
		client := p.clients[f.Name]
		p.mu.RUnlock()
		wg.Go(func() {
			if client == nil {
				out[i].Error = "not valid"
				return
			}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.URL+"/api/version", nil)
			res, err := client.Do(req)
			if err != nil {
				out[i].Error = "does not answer"
				return
			}
			defer res.Body.Close()
			var v buildinfo.Info
			if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&v) != nil {
				out[i].Error = fmt.Sprintf("answers HTTP %d", res.StatusCode)
				return
			}
			out[i].Version = v.Version
		})
	}
	wg.Wait()
	return out
}

// Check asks every firewall's portitor-config for its version.
func (p *Portal) Check(ctx context.Context) []portalStatus { return p.statuses(ctx) }

// Store is the portal's configuration.
func (p *Portal) Store() *PortalStore { return p.store }

// handlePage is the shell: the login, the tabs, the firewalls' list.
func (p *Portal) handlePage(w http.ResponseWriter, r *http.Request) {
	portalHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := p.page.Execute(w, struct{ Version string }{buildinfo.Version}); err != nil {
		slog.Warn("portal page", "err", err)
	}
}

func (p *Portal) handleScript(w http.ResponseWriter, r *http.Request) {
	portalHeaders(w)
	data, _ := portalFS.ReadFile("portal.js")
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = w.Write(data)
}

// restartWitness runs the witness of the configuration's strings, again
// when they changed.
func (p *Portal) restartWitness() {
	p.witnessMu.Lock()
	defer p.witnessMu.Unlock()
	if p.ctx == nil {
		return
	}
	// A restart loses the vote's state: only when the strings changed.
	if cur := p.store.Witnesses(); p.witnessCancel != nil && slices.Equal(cur, p.witnessStrs) {
		return
	}
	if p.witnessCancel != nil {
		p.witnessCancel()
		p.witnessCancel = nil
	}
	strs := p.store.Witnesses()
	if len(strs) == 0 {
		p.witnessStrs = nil
		return
	}
	w, err := NewWitness(strs)
	if err != nil {
		slog.Warn("portal: witness", "err", err)
		return
	}
	ctx, cancel := context.WithCancel(p.ctx)
	p.witnessCancel = cancel
	p.witnessStrs = strs
	go w.Run(ctx)
}

// warnWebYAML says when web.yaml lists firewalls or witness strings the
// configuration lacks: they are taken in once, at the first start, and
// never again.
func (p *Portal) warnWebYAML() {
	have := map[string]bool{}
	for _, f := range p.firewalls() {
		have[f.Name] = true
	}
	for _, f := range p.cfg.Firewalls {
		if !have[f.Name] {
			slog.Warn("web.yaml lists a firewall the portal's configuration does not have; it is ignored (add it in the portal, or portitor-web add-firewall)", "firewall", f.Name)
		}
	}
	if len(p.cfg.Witness) > 0 && len(p.store.Witnesses()) == 0 {
		slog.Warn("web.yaml lists witness strings the portal's configuration does not have; they are ignored (portitor-web add-witness)")
	}
}

// Serve runs until ctx is cancelled: the portal, and the witness of the
// pairs it is given.
func (p *Portal) Serve(ctx context.Context) error {
	srv := &http.Server{Addr: p.cfg.Bind, Handler: p.Handler(), ReadHeaderTimeout: 30 * time.Second}
	p.witnessMu.Lock()
	p.ctx = ctx
	p.witnessMu.Unlock()
	p.restartWitness()
	go p.store.Watch(ctx)
	go p.runSSH(ctx)
	p.warnWebYAML()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	slog.Info("portitor-web listening", "addr", p.cfg.Bind, "firewalls", len(p.firewalls()), "witness", len(p.store.Witnesses()), "tls", p.cfg.TLSCert != "")
	var err error
	if p.cfg.TLSCert != "" {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		err = srv.ListenAndServeTLS(p.cfg.TLSCert, p.cfg.TLSKey)
	} else {
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// stripPortalCookie takes the portal's own session cookie out of a request
// for a firewall: the firewall's GUI has no use for it.
func stripPortalCookie(r *http.Request) {
	cs := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cs {
		if c.Name != portalCookie {
			r.AddCookie(c)
		}
	}
}
