// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"net/http"
	"net/mail"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/abundo/portitor/models"
)

const (
	cookieName     = "fw_session"
	sessionTTL     = 12 * time.Hour
	rememberTTL    = 30 * 24 * time.Hour
	ctxUser        = "user"
	ctxRemember    = "remember"
	ctxClaims      = "claims"
	minPasswordLen = 10
	// loginMaxTracked addresses with failed logins make loginLimiter
	// prune expired ones.
	loginMaxTracked = 10000
)

type sessionClaims struct {
	UserID       uint `json:"uid"`
	TokenVersion int  `json:"tv"`
	Remember     bool `json:"rm,omitempty"`
	jwt.RegisteredClaims
}

// issueSession sets the session cookie. Without remember it is a browser
// session cookie (gone when the browser closes) and expires after
// sessionTTL; with remember it persists for rememberTTL.
func (s *Server) issueSession(c *echo.Context, u *models.User, remember bool) error {
	ttl := sessionTTL
	if remember {
		ttl = rememberTTL
	}
	claims := sessionClaims{
		UserID:       u.ID,
		TokenVersion: u.TokenVersion,
		Remember:     remember,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtKey)
	if err != nil {
		return err
	}
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.cfg.Dev,
		SameSite: http.SameSiteStrictMode,
	}
	if remember {
		cookie.MaxAge = int(ttl.Seconds())
	}
	c.SetCookie(cookie)
	return nil
}

func (s *Server) clearSession(c *echo.Context) {
	c.SetCookie(&http.Cookie{Name: cookieName, Value: "", Path: "/", HttpOnly: true, Secure: !s.cfg.Dev,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// requireAuth resolves the session cookie to a user.
func (s *Server) requireAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		cookie, err := c.Cookie(cookieName)
		if err != nil {
			return errJSON(c, http.StatusUnauthorized, "not logged in")
		}
		var claims sessionClaims
		_, err = jwt.ParseWithClaims(cookie.Value, &claims, func(t *jwt.Token) (any, error) {
			return s.jwtKey, nil
		}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired())
		if err != nil {
			return errJSON(c, http.StatusUnauthorized, "session expired")
		}
		var u models.User
		if err := s.db.First(&u, claims.UserID).Error; err != nil || u.TokenVersion != claims.TokenVersion {
			return errJSON(c, http.StatusUnauthorized, "session revoked")
		}
		c.Set(ctxUser, &u)
		c.Set(ctxRemember, claims.Remember)
		c.Set(ctxClaims, &claims)
		return next(c)
	}
}

// sessionValid tells whether a session requireAuth accepted still would:
// it has not expired, and its user still exists with the same token
// version. For connections that outlive the request (the console).
func (s *Server) sessionValid(claims *sessionClaims) bool {
	if claims == nil || claims.ExpiresAt == nil || !time.Now().Before(claims.ExpiresAt.Time) {
		return false
	}
	var u models.User
	return s.db.First(&u, claims.UserID).Error == nil && u.TokenVersion == claims.TokenVersion
}

// viewerDenied are the GET routes only a global admin may use: they hand
// out a root shell, or the user and role lists. (A WireGuard client
// config, with its private key, takes an admin of the peer's instance.)
var viewerDenied = map[string]bool{
	"/api/users":         true,
	"/api/roles":         true,
	"/api/agent/console": true,
}

// tenantDenied are the GET routes a user without a global role (RoleNone)
// may not use either: they show the whole firewall, not one instance.
var tenantDenied = map[string]bool{
	"/api/settings":   true,
	"/api/system":     true,
	"/api/agent/logs": true,
}

// viewerWrites are the requests other than GET a viewer may make: their own
// profile and password, and the deploy preview, which changes nothing.
var viewerWrites = map[string]bool{
	"PUT /api/me":              true,
	"POST /api/me/password":    true,
	"POST /api/deploy/preview": true,
}

// requireRole lets a global admin through, limits everyone else to reading,
// and lets the requests in tenantWrites through to an instance admin, whose
// handlers check the instance. It runs after requireAuth and matches the
// route pattern, so it cannot be dodged with another spelling of the path.
func (s *Server) requireRole(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		u := currentUser(c)
		if u == nil {
			return errJSON(c, http.StatusUnauthorized, "not logged in")
		}
		a, err := accessOf(s.db, u)
		if err != nil {
			return err
		}
		c.Set(ctxAccess, a)
		if a.isAdmin() {
			return next(c)
		}
		method, path := c.Request().Method, c.Path()
		allowed := viewerWrites[method+" "+path] || s.tenantWrites[method+" "+path] && a.writesAny()
		if method == http.MethodGet || method == http.MethodHead {
			allowed = !viewerDenied[path] && (a.readsAll() || !tenantDenied[path])
		}
		if !allowed {
			return errJSON(c, http.StatusForbidden, "your user can't do this")
		}
		return next(c)
	}
}

// requireJSON rejects state-changing requests that aren't JSON. Browsers
// can't send application/json cross-site without a CORS preflight (which
// is never granted), so together with SameSite=Strict this blocks CSRF.
// DELETE is exempt: it has no body (axios drops the Content-Type then), and
// a cross-site DELETE needs a preflight whatever its content type.
func requireJSON(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		switch c.Request().Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodDelete:
		default:
			ct := c.Request().Header.Get("Content-Type")
			if !strings.HasPrefix(ct, "application/json") {
				return errJSON(c, http.StatusUnsupportedMediaType, "content type must be application/json")
			}
		}
		return next(c)
	}
}

// noStore keeps API answers out of caches: some hold secrets (a backup,
// a WireGuard client config with its private key).
func noStore(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")
		return next(c)
	}
}

func currentUser(c *echo.Context) *models.User {
	u, _ := c.Get(ctxUser).(*models.User)
	return u
}

// loginLimiter slows down password guessing per client address.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

const (
	loginWindow      = 15 * time.Minute
	loginMaxFailures = 10
)

func (l *loginLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(ip)
	return len(l.failures[ip]) >= loginMaxFailures
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failures == nil {
		l.failures = map[string][]time.Time{}
	}
	// Addresses are pruned when they try again; guessing from many
	// addresses would grow the map without bound, so prune them all now
	// and then.
	if len(l.failures) >= loginMaxTracked {
		for other := range l.failures {
			l.prune(other)
		}
	}
	l.failures[ip] = append(l.failures[ip], time.Now())
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, ip)
}

func (l *loginLimiter) prune(ip string) {
	cut := time.Now().Add(-loginWindow)
	list := l.failures[ip]
	i := 0
	for i < len(list) && list[i].Before(cut) {
		i++
	}
	if i == len(list) {
		delete(l.failures, ip)
	} else {
		l.failures[ip] = list[i:]
	}
}

// dummyHash keeps login timing the same for unknown users.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("timing-equaliser"), bcrypt.DefaultCost)

func (s *Server) handleLogin(c *echo.Context) error {
	ip := c.RealIP()
	if s.limiter.blocked(ip) {
		return errJSON(c, http.StatusTooManyRequests, "too many failed logins; try again later")
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Remember bool   `json:"remember"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	var u models.User
	found := s.db.Where("username = ?", req.Username).First(&u).Error == nil
	hash := dummyHash
	if found {
		hash = []byte(u.PasswordHash)
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(req.Password)) != nil || !found {
		s.limiter.fail(ip)
		return errJSON(c, http.StatusUnauthorized, "wrong username or password")
	}
	s.limiter.reset(ip)
	if err := s.issueSession(c, &u, req.Remember); err != nil {
		return err
	}
	return s.me(c, &u)
}

func (s *Server) handleLogout(c *echo.Context) error {
	s.clearSession(c)
	return c.NoContent(http.StatusNoContent)
}

func (s *Server) handleMe(c *echo.Context) error {
	return s.me(c, currentUser(c))
}

// me answers with the user and their level per instance id (admin or
// viewer; an instance missing has none), for the GUI to show what they
// may change.
func (s *Server) me(c *echo.Context, u *models.User) error {
	a, err := accessOf(s.db, u)
	if err != nil {
		return err
	}
	st, err := s.settings()
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, struct {
		*models.User
		Access           map[uint]string `json:"access"`
		VirtualFirewalls bool            `json:"virtual_firewalls"`
	}{u, a.levels, st.VirtualFirewalls})
}

// handleUpdateMe changes the caller's own full name, email and date format
// (kept when left out). The username cannot be changed here.
func (s *Server) handleUpdateMe(c *echo.Context) error {
	var req struct {
		FullName   string  `json:"full_name"`
		Email      string  `json:"email"`
		DateFormat *string `json:"date_format"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	req.FullName = strings.TrimSpace(req.FullName)
	req.Email = strings.TrimSpace(req.Email)
	if strings.ContainsFunc(req.FullName, unicode.IsControl) {
		return errJSON(c, http.StatusBadRequest, "control characters are not allowed")
	}
	if req.Email != "" {
		if a, err := mail.ParseAddress(req.Email); err != nil || a.Address != req.Email {
			return errJSON(c, http.StatusBadRequest, "invalid email address")
		}
	}
	fields := map[string]any{"full_name": req.FullName, "email": req.Email}
	if req.DateFormat != nil {
		if !slices.Contains(models.DateFormats, *req.DateFormat) {
			return errJSON(c, http.StatusBadRequest, "invalid date format")
		}
		fields["date_format"] = *req.DateFormat
	}
	u := currentUser(c)
	err := s.db.Model(u).Updates(fields).Error
	if err != nil {
		return dbError(c, err)
	}
	if err := s.db.First(u, u.ID).Error; err != nil {
		return err
	}
	return s.me(c, u)
}

// handleChangePassword changes the caller's password and revokes their
// other sessions.
func (s *Server) handleChangePassword(c *echo.Context) error {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	u := currentUser(c)
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Current)) != nil {
		return errJSON(c, http.StatusForbidden, "current password is wrong")
	}
	if err := setPassword(u, req.New); err != nil {
		return errJSON(c, http.StatusBadRequest, err.Error())
	}
	u.TokenVersion++
	if err := s.db.Save(u).Error; err != nil {
		return err
	}
	remember, _ := c.Get(ctxRemember).(bool)
	if err := s.issueSession(c, u, remember); err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

func setPassword(u *models.User, password string) error {
	if len(password) < minPasswordLen {
		return errors.New("password must be at least 10 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hash)
	return nil
}

// CreateUser adds or resets an admin (portitor-web createadmin).
func CreateUser(s *Server, username, password string) error {
	var u models.User
	s.db.Where("username = ?", username).First(&u)
	u.Username = username
	u.Role = models.RoleAdmin
	if err := setPassword(&u, password); err != nil {
		return err
	}
	u.TokenVersion++
	return s.db.Save(&u).Error
}
