// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/datastore"
)

// The portal's own login: its users are in the configuration
// (portitor-portal.yang), a session is a signed cookie. The firewalls keep
// their own logins behind it.

const portalCookie = "portitor_portal"

// portalLoginHeader marks a 401 as the portal's.
const portalLoginHeader = "X-Portitor-Portal"

const portalSessionTTL = 12 * time.Hour

// loadSessionKey reads the key that signs sessions from the data directory,
// making it the first time. It is not configuration: a new key only logs
// everyone out.
func loadSessionKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, "session.key")
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		return b, nil
	}
	b := make([]byte, 48)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

// loginLimits counts the failed logins of an address: five a minute.
type loginLimits struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

func (l *loginLimits) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := time.Now().Add(-time.Minute)
	var keep []time.Time
	for _, t := range l.fails[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.fails, ip)
	} else {
		l.fails[ip] = keep
	}
	return len(keep) >= 5
}

func (l *loginLimits) fail(ip string) {
	l.mu.Lock()
	l.fails[ip] = append(l.fails[ip], time.Now())
	l.mu.Unlock()
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (p *Portal) sessionUser(r *http.Request) string {
	c, err := r.Cookie(portalCookie)
	if err != nil {
		return ""
	}
	var claims jwt.RegisteredClaims
	tok, err := jwt.ParseWithClaims(c.Value, &claims, func(*jwt.Token) (any, error) { return p.key, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	if err != nil || !tok.Valid {
		return ""
	}
	if _, ok := p.store.PasswordHash(claims.Subject); !ok {
		return ""
	}
	return claims.Subject
}

// authed passes a request from a logged-in user; a write must be JSON (a
// form from another site can't send it).
func (p *Portal) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := p.sessionUser(r)
		if user == "" {
			portalError(w, r, http.StatusUnauthorized, "log in to portitor-manager")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && strings.HasPrefix(r.URL.Path, "/portal/v1/") &&
			r.Method != http.MethodDelete && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			portalError(w, r, http.StatusUnsupportedMediaType, "JSON expected")
			return
		}
		next(w, r)
	}
}

func portalError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if strings.HasPrefix(r.URL.Path, "/portal/v1/") || strings.HasPrefix(r.URL.Path, "/fw/") {
		if status == http.StatusUnauthorized && strings.HasPrefix(r.URL.Path, "/fw/") {
			// The portal's login, not the firewall's: a framed GUI hands
			// it to the portal's page.
			w.Header().Set(portalLoginHeader, "login")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
		return
	}
	http.Error(w, msg, status)
}

func portalJSON(w http.ResponseWriter, v any) {
	portalHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func readBody(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	return json.NewDecoder(r.Body).Decode(v)
}

func (p *Portal) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if p.limits.blocked(ip) {
		portalError(w, r, http.StatusTooManyRequests, "too many failed logins; wait a minute")
		return
	}
	var req struct{ User, Password string }
	if err := readBody(r, &req); err != nil {
		portalError(w, r, http.StatusBadRequest, "bad request")
		return
	}
	hash, ok := p.store.PasswordHash(req.User)
	h := []byte(hash)
	if !ok {
		h = dummyHash
	}
	if bcrypt.CompareHashAndPassword(h, []byte(req.Password)) != nil || !ok {
		p.limits.fail(ip)
		portalError(w, r, http.StatusUnauthorized, "wrong user or password")
		return
	}
	now := time.Now()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject: req.User, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(portalSessionTTL)),
	}).SignedString(p.key)
	if err != nil {
		portalError(w, r, http.StatusInternalServerError, "no session")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: portalCookie, Value: tok, Path: "/", MaxAge: int(portalSessionTTL.Seconds()),
		HttpOnly: true, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", SameSite: http.SameSiteStrictMode})
	portalJSON(w, map[string]string{"user": req.User})
}

func (p *Portal) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: portalCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	portalJSON(w, map[string]string{})
}

func (p *Portal) handleSession(w http.ResponseWriter, r *http.Request) {
	portalJSON(w, map[string]string{"user": p.sessionUser(r)})
}

// handleVersion is the portal's build, before any login (the login page
// shows it).
func (p *Portal) handleVersion(w http.ResponseWriter, r *http.Request) {
	portalJSON(w, buildinfo.Get())
}

func (p *Portal) handleFirewalls(w http.ResponseWriter, r *http.Request) {
	portalJSON(w, p.statuses(r.Context()))
}

func (p *Portal) handlePutFirewall(w http.ResponseWriter, r *http.Request) {
	var f PortalFirewall
	if err := readBody(r, &f); err != nil {
		portalError(w, r, http.StatusBadRequest, "bad request")
		return
	}
	if name := r.PathValue("name"); name != "" {
		f.Name = name
	}
	if err := CheckPortalFirewall(&f); err != nil {
		portalError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if r.Method == http.MethodPost && p.nameTaken(f.Name) {
		portalError(w, r, http.StatusConflict, "there is a firewall "+f.Name+" already")
		return
	}
	if err := p.store.PutFirewall(f); err != nil {
		portalError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	portalJSON(w, f)
}

func (p *Portal) handleDeleteFirewall(w http.ResponseWriter, r *http.Request) {
	if err := p.store.DeleteFirewall(r.PathValue("name")); err != nil {
		portalError(w, r, http.StatusNotFound, err.Error())
		return
	}
	portalJSON(w, map[string]string{})
}

// handleProbe reads a firewall's fingerprints over SSH.
func (p *Portal) handleProbe(w http.ResponseWriter, r *http.Request) {
	var req SSHProbe
	if err := readBody(r, &req); err != nil {
		portalError(w, r, http.StatusBadRequest, "bad request")
		return
	}
	res, err := RunSSHProbe(r.Context(), req)
	if err != nil {
		slog.Info("portal: ssh probe failed", "host", req.Host, "err", err)
		portalError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	portalJSON(w, res)
}

// handlePutHA adds an HA firewall (POST) or changes its description and
// witness flag (PUT).
func (p *Portal) handlePutHA(w http.ResponseWriter, r *http.Request) {
	var ha PortalHA
	ha.Witness = true
	if err := readBody(r, &ha); err != nil {
		portalError(w, r, http.StatusBadRequest, "bad request")
		return
	}
	if name := r.PathValue("name"); name != "" {
		ha.Name = name
		if _, ok := p.store.HAFirewall(name); !ok {
			portalError(w, r, http.StatusNotFound, "there is no cluster firewall "+name)
			return
		}
	} else if p.nameTaken(ha.Name) {
		portalError(w, r, http.StatusConflict, "there is a firewall "+ha.Name+" already")
		return
	}
	ha.Primary, ha.Secondary = nil, nil
	if err := CheckPortalHA(&ha); err != nil {
		portalError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	if err := p.store.PutHA(ha); err != nil {
		portalError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	portalJSON(w, ha)
}

// nameTaken tells whether a firewall or HA firewall has the name.
func (p *Portal) nameTaken(name string) bool {
	t := p.store.Tree()
	return t.Root.Entry("firewall", []string{name}) != nil || t.Root.Entry("cluster", []string{name}) != nil
}

func (p *Portal) handleDeleteHA(w http.ResponseWriter, r *http.Request) {
	if err := p.store.DeleteHA(r.PathValue("name")); err != nil {
		portalError(w, r, http.StatusNotFound, err.Error())
		return
	}
	portalJSON(w, map[string]string{})
}

// handleHAHost adds a host to an HA firewall, pairing the two when it is
// the second.
func (p *Portal) handleHAHost(w http.ResponseWriter, r *http.Request) {
	var req HAHostRequest
	if err := readBody(r, &req); err != nil {
		portalError(w, r, http.StatusBadRequest, "bad request")
		return
	}
	req.Firewall, req.Role = r.PathValue("name"), r.PathValue("role")
	res, err := p.AddHAHost(r.Context(), req)
	if err != nil {
		slog.Info("portal: adding a cluster host failed", "firewall", req.Firewall, "role", req.Role, "host", req.SSH.Host, "err", err)
		status := http.StatusBadGateway
		if errors.Is(err, errNeedLogin) {
			status = http.StatusConflict
		}
		portalError(w, r, status, err.Error())
		return
	}
	portalJSON(w, res)
}

// handleRemoveHAHost takes a host out of an HA firewall (the pair is not
// changed).
func (p *Portal) handleRemoveHAHost(w http.ResponseWriter, r *http.Request) {
	if err := p.store.SetHAHost(r.PathValue("name"), r.PathValue("role"), nil); err != nil {
		portalError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	portalJSON(w, map[string]string{})
}

func (p *Portal) handleWitnesses(w http.ResponseWriter, r *http.Request) {
	type pair struct {
		Pair  string   `json:"pair"`
		Hosts []string `json:"hosts"`
	}
	out := []pair{}
	for _, s := range p.store.Witnesses() {
		if wp, err := ParseWitness(s); err == nil {
			e := pair{Pair: wp.Pair}
			for _, h := range wp.Hosts {
				e.Hosts = append(e.Hosts, h.Name+" "+h.URL)
			}
			out = append(out, e)
		}
	}
	portalJSON(w, out)
}

func (p *Portal) handlePutWitness(w http.ResponseWriter, r *http.Request) {
	var req struct {
		String string `json:"string"`
	}
	if err := readBody(r, &req); err != nil {
		portalError(w, r, http.StatusBadRequest, "bad request")
		return
	}
	if err := p.store.PutWitness(req.String); err != nil {
		portalError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	portalJSON(w, map[string]string{})
}

func (p *Portal) handleDeleteWitness(w http.ResponseWriter, r *http.Request) {
	if err := p.store.DeleteWitness(r.PathValue("pair")); err != nil {
		portalError(w, r, http.StatusNotFound, err.Error())
		return
	}
	portalJSON(w, map[string]string{})
}

// handleConfig is the configuration tree as RFC 7951 JSON, secrets left out.
func (p *Portal) handleConfig(w http.ResponseWriter, r *http.Request) {
	data, err := p.store.Tree().JSON(datastore.JSONOptions{SecretsSet: true, Indent: true})
	if err != nil {
		portalError(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	portalHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

// CreatePortalUser makes a user, or changes their password.
func CreatePortalUser(store *PortalStore, user, password string) error {
	if len(password) < 8 {
		return errors.New("the password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return store.SetPassword(user, string(hash))
}
