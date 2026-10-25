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
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/buildinfo"
)

// portitor-web is a portal: it has no database and no configuration of
// its own. Each firewall keeps its configuration in its own
// portitor-config; portitor-web serves the firewalls it lists (web.yaml)
// at /fw/<name>/, passing the GUI, the API, the console and the streams
// through to that portitor-config, whose login, roles and checks apply as
// they do there. The session cookie of each is kept to its path (both
// hosts' paths for an HA pair). It is also the witness of the HA pairs it
// is given (witness:, portalwitness.go).

// PortalConfig is /etc/portitor/web.yaml.
type PortalConfig struct {
	Bind string `yaml:"bind"`
	// Dev drops the HTTPS requirement of the firewalls' URLs on loopback
	// only; the cookies' Secure flag is portitor-config's.
	Dev bool `yaml:"dev"`
	// TLSCert/TLSKey serve HTTPS directly; otherwise put a reverse proxy
	// in front.
	TLSCert   string           `yaml:"tls_cert"`
	TLSKey    string           `yaml:"tls_key"`
	Firewalls []PortalFirewall `yaml:"firewalls"`
	// Witness are witness strings (portitor-config witness-string on an
	// HA primary): the pairs this portitor-web is the third vote of.
	Witness []string `yaml:"witness"`
}

// PortalFirewall is one firewall's portitor-config: its URL, and the
// SHA-256 fingerprint of its tls_cert (portitor-config fingerprint).
// portitor-web asks for that certificate by PinnedServerName, so a
// certificate chosen there under Settings changes nothing here.
type PortalFirewall struct {
	Name        string `yaml:"name" json:"name"`
	URL         string `yaml:"url" json:"-"`
	Fingerprint string `yaml:"fingerprint" json:"-"`
}

var portalNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

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
		f := &c.Firewalls[i]
		if !portalNameRe.MatchString(f.Name) {
			return fmt.Errorf("firewalls: name %q: lowercase letters, digits and -, starting with a letter, at most 32", f.Name)
		}
		if seen[f.Name] {
			return fmt.Errorf("firewalls: %s twice", f.Name)
		}
		seen[f.Name] = true
		f.URL = strings.TrimRight(f.URL, "/")
		u, err := url.Parse(f.URL)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || (u.Path != "" && u.Path != "/") {
			return fmt.Errorf("firewalls: %s: url must be https://<host>:<port> of its portitor-config", f.Name)
		}
		switch {
		case u.Scheme == "https":
			f.Fingerprint = normalizeFingerprint(f.Fingerprint)
			if len(f.Fingerprint) != 64 {
				return fmt.Errorf("firewalls: %s: fingerprint: the SHA-256 of its tls_cert (portitor-config fingerprint there)", f.Name)
			}
		case u.Scheme == "http" && isLoopback(u.Hostname()):
			// portitor-config on this host, without TLS.
		default:
			return fmt.Errorf("firewalls: %s: url must be https:// (http:// only to this host)", f.Name)
		}
	}
	for _, w := range c.Witness {
		if _, err := ParseWitness(w); err != nil {
			return fmt.Errorf("witness: %w", err)
		}
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
	cfg     *PortalConfig
	proxies map[string]*httputil.ReverseProxy
	clients map[string]*http.Client
	page    *template.Template
}

//go:embed portal.html
var portalFS embed.FS

func NewPortal(cfg *PortalConfig) (*Portal, error) {
	p := &Portal{cfg: cfg, proxies: map[string]*httputil.ReverseProxy{}, clients: map[string]*http.Client{}}
	var err error
	if p.page, err = template.ParseFS(portalFS, "portal.html"); err != nil {
		return nil, err
	}
	for _, f := range cfg.Firewalls {
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
				return nil, err
			}
			tlsCfg.MinVersion = tls.VersionTLS12
			tlsCfg.ServerName = PinnedServerName
			tr.TLSClientConfig = tlsCfg
		}
		p.proxies[f.Name] = p.proxy(f.Name, target, tr)
		p.clients[f.Name] = &http.Client{Transport: tr, Timeout: 3 * time.Second}
	}
	return p, nil
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
			r.Out.URL.RawPath = ""
			r.SetURL(target)
			r.SetXForwarded()
			r.Out.Host = r.In.Host
			r.Out.Header.Set("X-Forwarded-Prefix", prefix)
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
	for _, f := range p.cfg.Firewalls {
		if f.Name == name {
			own = f.Fingerprint
		}
	}
	if own == "" || !slices.Contains(fps, own) {
		return out
	}
	for _, f := range p.cfg.Firewalls {
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

// Handler serves the portal.
func (p *Portal) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", p.handleRoot)
	mux.HandleFunc("GET /portal/{$}", p.handlePage)
	mux.HandleFunc("GET /portal/v1/firewalls", p.handleFirewalls)
	mux.HandleFunc("/fw/{name}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := p.proxies[r.PathValue("name")]; !ok {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, portalPrefix(r.PathValue("name"))+"/", http.StatusFound)
	})
	mux.HandleFunc("/fw/{name}/", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		rp, ok := p.proxies[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, portalPrefix(name))
		if r.Method == http.MethodGet && !strings.HasPrefix(rest, "/api/") && !strings.HasPrefix(rest, "/assets/") {
			// The GUI's page: the firewall / opens next time.
			http.SetCookie(w, &http.Cookie{Name: lastFirewallCookie, Value: name, Path: "/", MaxAge: 365 * 24 * 3600,
				HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
		}
		rp.ServeHTTP(w, r)
	})
	return mux
}

// portalHeaders are the portal's own pages' (the proxied ones bring
// portitor-config's).
func portalHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
}

// portalStatus is a firewall on the portal's page.
type portalStatus struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
}

// statuses asks every portitor-config for its version, at once.
func (p *Portal) statuses(ctx context.Context) []portalStatus {
	out := make([]portalStatus, len(p.cfg.Firewalls))
	var wg sync.WaitGroup
	for i, f := range p.cfg.Firewalls {
		out[i] = portalStatus{Name: f.Name, Path: portalPrefix(f.Name) + "/"}
		wg.Go(func() {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.URL+"/api/version", nil)
			res, err := p.clients[f.Name].Do(req)
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

// lastFirewallCookie names the firewall whose GUI the browser opened last.
const lastFirewallCookie = "portitor_firewall"

// handleRoot opens a firewall's GUI, whose switcher picks the others: the
// one opened last, else the first. Without firewalls, the list says so.
func (p *Portal) handleRoot(w http.ResponseWriter, r *http.Request) {
	if len(p.cfg.Firewalls) == 0 {
		p.handlePage(w, r)
		return
	}
	name := p.cfg.Firewalls[0].Name
	if c, err := r.Cookie(lastFirewallCookie); err == nil {
		if _, ok := p.proxies[c.Value]; ok {
			name = c.Value
		}
	}
	http.Redirect(w, r, portalPrefix(name)+"/", http.StatusFound)
}

// handlePage lists the firewalls, with their versions or why they don't
// answer (/portal/).
func (p *Portal) handlePage(w http.ResponseWriter, r *http.Request) {
	portalHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		Firewalls []portalStatus
		Version   string
	}{p.statuses(r.Context()), buildinfo.Version}
	if err := p.page.Execute(w, data); err != nil {
		slog.Warn("portal page", "err", err)
	}
}

// handleFirewalls lists the firewalls for the GUI's firewall switcher.
func (p *Portal) handleFirewalls(w http.ResponseWriter, r *http.Request) {
	portalHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p.statuses(r.Context()))
}

// Serve runs until ctx is cancelled: the portal, and the witness of the
// pairs it is given.
func (p *Portal) Serve(ctx context.Context) error {
	srv := &http.Server{Addr: p.cfg.Bind, Handler: p.Handler(), ReadHeaderTimeout: 30 * time.Second}
	if len(p.cfg.Witness) > 0 {
		w, err := NewWitness(p.cfg.Witness)
		if err != nil {
			return err
		}
		go w.Run(ctx)
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	slog.Info("portitor-web listening", "addr", p.cfg.Bind, "firewalls", len(p.cfg.Firewalls), "witness", len(p.cfg.Witness), "tls", p.cfg.TLSCert != "")
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
