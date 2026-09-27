// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/abundo/portitor/models"
)

const (
	cookieName     = "fw_session"
	sessionTTL     = 12 * time.Hour
	ctxUser        = "user"
	minPasswordLen = 10
)

type sessionClaims struct {
	UserID       uint `json:"uid"`
	TokenVersion int  `json:"tv"`
	jwt.RegisteredClaims
}

func (s *Server) issueSession(c *echo.Context, u *models.User) error {
	claims := sessionClaims{
		UserID:       u.ID,
		TokenVersion: u.TokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(sessionTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtKey)
	if err != nil {
		return err
	}
	c.SetCookie(&http.Cookie{
		Name:     cookieName,
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.cfg.Dev,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
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
		return next(c)
	}
}

// requireJSON rejects state-changing requests that aren't JSON. Browsers
// can't send application/json cross-site without a CORS preflight (which
// is never granted), so together with SameSite=Strict this blocks CSRF.
func requireJSON(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		switch c.Request().Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			ct := c.Request().Header.Get("Content-Type")
			if !strings.HasPrefix(ct, "application/json") {
				return errJSON(c, http.StatusUnsupportedMediaType, "content type must be application/json")
			}
		}
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
	if err := s.issueSession(c, &u); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, u)
}

func (s *Server) handleLogout(c *echo.Context) error {
	s.clearSession(c)
	return c.NoContent(http.StatusNoContent)
}

func (s *Server) handleMe(c *echo.Context) error {
	return c.JSON(http.StatusOK, currentUser(c))
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
	if err := s.issueSession(c, u); err != nil {
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

// CreateUser adds or resets a user (portitor-web createadmin).
func CreateUser(s *Server, username, password string) error {
	var u models.User
	s.db.Where("username = ?", username).First(&u)
	u.Username = username
	if err := setPassword(&u, password); err != nil {
		return err
	}
	u.TokenVersion++
	return s.db.Save(&u).Error
}
