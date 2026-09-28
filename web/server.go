// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package web is portitor-web: the REST API behind the Vue GUI, and the
// place configuration is built and pushed to portitor-agent.
package web

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// agentAPI is what the server needs from the agent (agentclient.Client;
// a fake in tests).
type agentAPI interface {
	Status(ctx context.Context) (*agentapi.Status, error)
	Leases(ctx context.Context) (*agentapi.LeasesResponse, error)
	Render(ctx context.Context, doc fwconfig.Document) (*agentapi.RenderResult, error)
	Apply(ctx context.Context, doc fwconfig.Document, confirmTimeout int) (*agentapi.ApplyResult, error)
	Confirm(ctx context.Context, generation int64) error
	Rollback(ctx context.Context) (*agentapi.ApplyResult, error)
}

type Server struct {
	cfg      *Config
	db       *gorm.DB
	jwtKey   []byte
	limiter  loginLimiter
	deployMu sync.Mutex
	// nicMu serializes syncNICs (every open browser polls the status).
	nicMu sync.Mutex
	// newAgent builds a client from the current settings.
	newAgent func(s *models.Settings) (agentAPI, error)
	static   fs.FS
}

func NewServer(cfg *Config, db *gorm.DB) *Server {
	return &Server{
		cfg:    cfg,
		db:     db,
		jwtKey: []byte(cfg.JWTSecret),
		newAgent: func(s *models.Settings) (agentAPI, error) {
			return agentclient.New(s.AgentURL, s.AgentToken, s.AgentFingerprint)
		},
		static: staticFS(),
	}
}

// Echo builds the HTTP handler.
func (s *Server) Echo() *echo.Echo {
	e := echo.New()
	e.HTTPErrorHandler = func(c *echo.Context, err error) {
		var he *echo.HTTPError
		if errors.As(err, &he) {
			_ = c.JSON(he.Code, map[string]any{"error": http.StatusText(he.Code)})
			return
		}
		slog.Error("request failed", "path", c.Request().URL.Path, "err", err)
		_ = c.JSON(http.StatusInternalServerError, map[string]any{"error": err.Error()})
	}
	e.Use(middleware.Recover())
	e.Use(middleware.BodyLimit(4 << 20))
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "0",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "DENY",
		ReferrerPolicy:        "same-origin",
		ContentSecurityPolicy: "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
	}))

	api := e.Group("/api", requireJSON)
	api.POST("/login", s.handleLogin)
	api.POST("/logout", s.handleLogout)
	api.GET("/version", func(c *echo.Context) error { return c.JSON(http.StatusOK, buildinfo.Get()) })

	g := api.Group("", s.requireAuth)
	g.GET("/me", s.handleMe)
	g.POST("/me/password", s.handleChangePassword)

	(&resource[models.Instance, *models.Instance]{db: s.db, order: "is_default desc, name", prepare: prepareInstance}).register(g, "/instances")
	(&resource[models.InterfaceZone, *models.InterfaceZone]{db: s.db, filters: []string{"instance_id"}, order: "name", prepare: prepareInterfaceZone, beforeDelete: deleteInterfaceZone}).register(g, "/interface-zones")
	(&resource[models.Interface, *models.Interface]{db: s.db, filters: []string{"instance_id"}, order: "name", prepare: prepareInterface, beforeDelete: deleteInterface}).register(g, "/interfaces")
	(&resource[models.WgPeer, *models.WgPeer]{db: s.db, filters: []string{"interface_id"}, order: "name", prepare: prepareWgPeer, present: presentWgPeer}).register(g, "/wg/peers")
	(&resource[models.Link, *models.Link]{db: s.db, order: "name", prepare: prepareLink, beforeDelete: deleteLink}).register(g, "/links")
	(&resource[models.Route, *models.Route]{db: s.db, filters: []string{"instance_id"}, order: "destination", prepare: prepareRoute}).register(g, "/routes")
	(&resource[models.Rule, *models.Rule]{db: s.db, filters: []string{"instance_id"}, order: "position, id", prepare: prepareRule}).register(g, "/rules")
	(&resource[models.NatRule, *models.NatRule]{db: s.db, filters: []string{"instance_id"}, order: "position, id", prepare: prepareNat}).register(g, "/nat")
	(&resource[models.IpamPrefix, *models.IpamPrefix]{db: s.db, filters: []string{"instance_id"}, order: "prefix", prepare: prepareIpamPrefix}).register(g, "/ipam/prefixes")
	(&resource[models.IpamAddress, *models.IpamAddress]{db: s.db, filters: []string{"instance_id", "interface_id"}, order: "address", prepare: prepareIpamAddress}).register(g, "/ipam/addresses")
	(&resource[models.DnsZone, *models.DnsZone]{db: s.db, filters: []string{"instance_id"}, order: "name", prepare: prepareDnsZone}).register(g, "/dns/zones")
	(&resource[models.DnsRecord, *models.DnsRecord]{db: s.db, filters: []string{"zone_id"}, order: "rank, id", prepare: prepareDnsRecord}).register(g, "/dns/records")
	(&resource[models.DnsSoaTemplate, *models.DnsSoaTemplate]{db: s.db, order: "name", prepare: prepareDnsSoaTemplate, beforeDelete: deleteDnsSoaTemplate}).register(g, "/dns/soa-templates")
	(&resource[models.DnsDnssecPolicy, *models.DnsDnssecPolicy]{db: s.db, order: "name", prepare: prepareDnsDnssecPolicy, beforeDelete: deleteDnsDnssecPolicy}).register(g, "/dns/dnssec-policies")
	(&resource[models.DnsTemplate, *models.DnsTemplate]{db: s.db, order: "name", prepare: prepareDnsTemplate, beforeDelete: deleteDnsTemplate}).register(g, "/dns/templates")
	(&resource[models.AddressObject, *models.AddressObject]{db: s.db, order: "name", prepare: prepareAddressObject, beforeDelete: deleteAddressObject}).register(g, "/objects")

	g.PUT("/dns/zones/:id/records", s.handleZoneRecords)
	g.GET("/ipam/tree", s.handleIpamTree)
	g.GET("/ipam/prefixes/:id/next-free", s.handleNextFree)
	g.POST("/rules/reorder", s.handleReorder("rules"))
	g.POST("/nat/reorder", s.handleReorder("nat_rules"))
	g.GET("/wg/peers/:id/config", s.handleWgClientConfig)
	g.POST("/interfaces/:id/wg-rekey", s.handleWgRekey)

	g.GET("/settings", s.handleGetSettings)
	g.PUT("/settings", s.handlePutSettings)
	g.GET("/users", s.handleListUsers)
	g.POST("/users", s.handleCreateUser)
	g.DELETE("/users/:id", s.handleDeleteUser)

	g.GET("/deploy/check", s.handleDeployCheck)
	g.POST("/deploy/preview", s.handleDeployPreview)
	g.POST("/deploy/apply", s.handleDeployApply)
	g.POST("/deploy/confirm", s.handleDeployConfirm)
	g.POST("/deploy/rollback", s.handleDeployRollback)
	g.GET("/deployments", s.handleDeployments)
	g.GET("/agent/status", s.handleAgentStatus)
	g.GET("/agent/leases", s.handleAgentLeases)

	api.Any("/*", func(c *echo.Context) error { return errJSON(c, http.StatusNotFound, "no such API endpoint") })

	// The Vue SPA owns every other path; unknown paths fall back to
	// index.html so client-side routes survive a reload.
	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		Filesystem: s.static,
		Root:       ".",
		HTML5:      true,
		Skipper: func(c *echo.Context) bool {
			return strings.HasPrefix(c.Request().URL.Path, "/api/")
		},
	}))
	return e
}

// Serve runs until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	if err := s.cfg.validateForServe(); err != nil {
		return err
	}
	if err := s.ensureDefaultInstance(); err != nil {
		return err
	}
	e := s.Echo()
	sc := echo.StartConfig{Address: s.cfg.Bind, HideBanner: true}
	slog.Info("portitor-web listening", "addr", s.cfg.Bind, "dev", s.cfg.Dev, "tls", s.cfg.TLSCert != "")
	var err error
	if s.cfg.TLSCert != "" {
		err = sc.StartTLS(ctx, e, s.cfg.TLSCert, s.cfg.TLSKey)
	} else {
		err = sc.Start(ctx, e)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// DefaultInstanceName is the instance created on start when there is none.
const DefaultInstanceName = "main"

// ensureDefaultInstance creates the default instance if there are no
// instances, since everything else belongs to one.
func (s *Server) ensureDefaultInstance() error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var n int64
		if err := tx.Model(&models.Instance{}).Count(&n).Error; err != nil || n > 0 {
			return err
		}
		in := models.Instance{Name: DefaultInstanceName, IsDefault: true}
		if err := prepareInstance(tx, &in, nil); err != nil {
			return err
		}
		if err := tx.Create(&in).Error; err != nil {
			return err
		}
		slog.Info("created default instance", "name", in.Name)
		return nil
	})
}

func (s *Server) settings() (*models.Settings, error) {
	var st models.Settings
	if err := s.db.FirstOrCreate(&st, models.Settings{ID: 1}).Error; err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *Server) agent() (agentAPI, *models.Settings, error) {
	st, err := s.settings()
	if err != nil {
		return nil, nil, err
	}
	a, err := s.newAgent(st)
	if err != nil {
		return nil, st, bad(err.Error())
	}
	return a, st, nil
}
