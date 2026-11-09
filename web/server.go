// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package web is portitor-web: the REST API behind the Vue GUI, and the
// place configuration is built and pushed to portitor-agent.
package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/coder/websocket"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/netobj"
	"github.com/abundo/portitor/models"
)

// agentAPI is what the server needs from the agent (agentclient.Client;
// a fake in tests).
type agentAPI interface {
	Status(ctx context.Context) (*agentapi.Status, error)
	Leases(ctx context.Context) (*agentapi.LeasesResponse, error)
	Neighbours(ctx context.Context) (*agentapi.NeighboursResponse, error)
	RoutingTable(ctx context.Context) (*agentapi.RoutingTableResponse, error)
	BGP(ctx context.Context) (*agentapi.BGPResponse, error)
	BGPNeighborRoutes(ctx context.Context, instance, vrf, neighbor string) (*agentapi.BGPNeighborRoutes, error)
	BGPNeighborDetail(ctx context.Context, instance, vrf, neighbor string) (*agentapi.BGPNeighborDetail, error)
	OSPF(ctx context.Context) (*agentapi.OSPFResponse, error)
	ISIS(ctx context.Context) (*agentapi.ISISResponse, error)
	VRRP(ctx context.Context) (*agentapi.VRRPResponse, error)
	BFD(ctx context.Context) (*agentapi.BFDResponse, error)
	NTP(ctx context.Context) (*agentapi.NTPResponse, error)
	Syslog(ctx context.Context) (*agentapi.SyslogStatus, error)
	NAT64(ctx context.Context) (*agentapi.NAT64Response, error)
	OpenVPN(ctx context.Context) (*agentapi.OpenVPNResponse, error)
	OpenVPNCA(ctx context.Context, instance string) (*agentapi.OpenVPNCA, error)
	DirectoryLogins(ctx context.Context, after int64) (*agentapi.DirectoryLoginsResponse, error)
	RuleCounters(ctx context.Context) (*agentapi.RuleCountersResponse, error)
	RateLimits(ctx context.Context) (*agentapi.RateLimitsResponse, error)
	Logs(ctx context.Context, after int64) (*agentapi.LogsResponse, error)
	PacketLog(ctx context.Context, after int64) (*agentapi.PacketLogResponse, error)
	DNSQueryLog(ctx context.Context, after int64) (*agentapi.DNSQueryLogResponse, error)
	Render(ctx context.Context, doc fwconfig.Document) (*agentapi.RenderResult, error)
	ParseNftables(ctx context.Context, text string) (*agentapi.ParseNftablesResult, error)
	Apply(ctx context.Context, doc fwconfig.Document, confirmTimeout int) (*agentapi.ApplyResult, error)
	Confirm(ctx context.Context, generation int64) error
	Rollback(ctx context.Context) (*agentapi.ApplyResult, error)
	RunTask(ctx context.Context, name string) error
	RefreshIPList(ctx context.Context, name string) error
	RefreshDNSBlocklist(ctx context.Context, instance, name string) error
	RenewCertificate(ctx context.Context, instance, name string) error
	Console(ctx context.Context, instance string) (*websocket.Conn, error)
	Capture(ctx context.Context, req agentapi.CaptureRequest) (io.ReadCloser, error)
	Trace(ctx context.Context, req agentapi.TraceRequest) (io.ReadCloser, error)
	Iperf(ctx context.Context, req agentapi.IperfRequest) (io.ReadCloser, error)
	Probe(ctx context.Context, req agentapi.ProbeRequest) (io.ReadCloser, error)
	ServiceLog(ctx context.Context, req agentapi.ServiceLogRequest) (io.ReadCloser, error)
	Journal(ctx context.Context, req agentapi.JournalRequest) (io.ReadCloser, error)
	Connections(ctx context.Context, req agentapi.ConnectionsRequest) (io.ReadCloser, error)
	FlushConnections(ctx context.Context, instance string) error
	RenewDHCP(ctx context.Context, req agentapi.DHCPRenewRequest) error
	System(ctx context.Context) (*agentapi.SystemStatus, error)
	StartSystemJob(ctx context.Context, req agentapi.SystemJobRequest) error
	Reboot(ctx context.Context) error
	HA(ctx context.Context) (*agentapi.HAStatus, error)
	HASwitchover(ctx context.Context) error
	HAVote(ctx context.Context, seconds int) (*agentapi.HAStatus, error)
}

type Server struct {
	cfg      *Config
	db       *gorm.DB
	jwtKey   []byte
	limiter  loginLimiter
	deployMu sync.Mutex
	// nicMu serializes syncNICs (every open browser polls the status).
	nicMu sync.Mutex
	// tenantWrites are the routes ("POST /api/rules") an instance admin
	// may use besides reading; their handlers check the instance.
	tenantWrites map[string]bool
	// newAgent builds a client for a firewall's agent (at agentURL).
	newAgent func(f *models.Firewall) (agentAPI, error)
	static   fs.FS
	// webCert serves HTTPS when portitor-web does (tls_cert); nil otherwise.
	webCert *tlsCert
	// witness is the HA pairs' third vote (witness.go).
	witness *witness
	// role is the host's place in its HA pair, and replMu keeps a copy of
	// the primary's database and a promotion apart (replica.go).
	role   hostRole
	replMu sync.Mutex
	// localHA asks this host's agent for its place in the pair
	// (localPeerConfig; a fake in tests).
	localHA func(ctx context.Context) (*agentapi.HAPeerConfig, *models.Firewall, error)
	// treeState is the configuration tree and its candidate (datastore.go).
	treeState treeState
	viewCache viewCache // the candidate as rows (confview.go)
}

func NewServer(cfg *Config, db *gorm.DB) *Server {
	s := &Server{
		cfg:    cfg,
		db:     db,
		jwtKey: []byte(cfg.JWTSecret),
		static: staticFS(),
	}
	s.newAgent = func(f *models.Firewall) (agentAPI, error) {
		return agentclient.New(s.agentURL(f), f.AgentToken, f.AgentFingerprint)
	}
	s.localHA = s.localPeerConfig
	return s
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
	e.Use(middleware.BodyLimitWithConfig(middleware.BodyLimitConfig{
		LimitBytes: 4 << 20,
		Skipper:    func(c *echo.Context) bool { return c.Request().URL.Path == restorePath },
	}))
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "0",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "DENY",
		ReferrerPolicy:        "same-origin",
		ContentSecurityPolicy: "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
	}))
	e.Use(captureWorkerCSP)
	if nets, _ := s.cfg.trustedProxies(); len(nets) > 0 {
		opts := []echo.TrustOption{echo.TrustLoopback(false), echo.TrustLinkLocal(false), echo.TrustPrivateNet(false)}
		for _, n := range nets {
			opts = append(opts, echo.TrustIPRange(n))
		}
		e.IPExtractor = echo.ExtractIPFromXFFHeader(opts...)
	}
	e.GET(replicaPath, s.handleReplica, noStore)
	e.GET(replicaCommitPath+":commit", s.handleReplicaCommit, noStore)

	api := e.Group("/api", requireJSON, noStore, s.refuseOnReplica)
	api.POST("/login", s.handleLogin)
	api.POST("/logout", s.handleLogout)
	api.GET("/version", func(c *echo.Context) error { return c.JSON(http.StatusOK, buildinfo.Get()) })

	s.tenantWrites = map[string]bool{}
	g := api.Group("", s.requireAuth, s.requireRole)
	g.GET("/me", s.handleMe)
	g.PUT("/me", s.handleUpdateMe)
	g.POST("/me/password", s.handleChangePassword)
	g.GET("/me/totp", s.handleTOTPStatus)
	g.POST("/me/totp/setup", s.handleTOTPSetup)
	g.POST("/me/totp/enable", s.handleTOTPEnable)
	g.POST("/me/totp/disable", s.handleTOTPDisable)
	g.POST("/me/totp/recovery-codes", s.handleRecoveryCodes)

	(&resource[models.Firewall, *models.Firewall]{db: s.db, order: "id", prepare: s.prepareFirewallHere, present: presentFirewall, afterSave: s.firewallSaved, preDelete: s.deleteFirewall}).register(s, g, "/firewalls")
	s.registerViewReads(g)

	// Instance admins use these too; the handlers check the instance.
	for _, r := range []string{"POST /api/wg/import", "POST /api/agent/capture", "POST /api/agent/trace", "POST /api/agent/iperf", "POST /api/agent/probe", "POST /api/agent/servicelog", "POST /api/agent/connections", "POST /api/agent/connections/flush", "POST /api/agent/dhcp/renew",
		"POST /api/deploy/apply", "POST /api/deploy/confirm", "POST /api/deploy/rollback",
		"PUT /api/config/*", "PATCH /api/config/*", "POST /api/config/*", "DELETE /api/config/*"} {
		s.tenantWrites[r] = true
	}
	// The routes of the GUI besides the configuration API: imports, reads
	// and operations.
	g.GET("/ipam/tree", s.handleIpamTree)
	g.GET("/rules/auto", s.handleAutoRules)
	g.GET("/services", func(c *echo.Context) error { return c.JSON(http.StatusOK, fwconfig.Services) })
	g.GET("/certificates/cas", func(c *echo.Context) error { return c.JSON(http.StatusOK, fwconfig.ACMECAs) })
	g.GET("/dyndns/providers", func(c *echo.Context) error { return c.JSON(http.StatusOK, fwconfig.DNSProviders) })
	g.GET("/predefined-services", func(c *echo.Context) error { return c.JSON(http.StatusOK, netobj.Predefined) })
	g.GET("/icmp-types", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string][]fwconfig.ICMPType{"icmp": fwconfig.ICMPTypes, "icmpv6": fwconfig.ICMPv6Types})
	})
	g.POST("/wg/import", s.handleWgImport)
	g.GET("/schedule/preview", s.handleSchedulePreview)

	g.GET("/settings", s.handleGetSettings)
	g.PUT("/settings", s.handlePutSettings)
	g.POST("/backup", s.handleBackup)
	g.POST(strings.TrimPrefix(restorePath, "/api"), s.handleRestore, middleware.BodyLimit(backupMaxSize/3*4+1<<20))
	g.GET("/users", s.handleListUsers)
	g.POST("/users", s.handleCreateUser)
	g.PUT("/users/:id", s.handleUpdateUser)
	g.POST("/users/:id/password", s.handleSetUserPassword)
	g.DELETE("/users/:id/totp", s.handleResetUserTOTP)
	g.DELETE("/users/:id", s.handleDeleteUser)
	g.GET("/roles", s.handleListRoles)
	g.POST("/roles", s.handleCreateRole)
	g.PUT("/roles/:id", s.handleUpdateRole)
	g.DELETE("/roles/:id", s.handleDeleteRole)

	// Bundles hold a virtual firewall's secrets: global admins only
	// (no tenant or viewer write rule, and the GET in viewerDenied).
	g.POST("/instances/import", s.handleImportBundle)
	g.GET("/firewalls/:id/witness", s.handleWitnessString)
	g.POST("/firewalls/:id/switchover", s.handleSwitchover)
	g.GET("/ha", s.handleHAStatus)
	g.POST("/ha/promote", s.handlePromote)
	// The configuration on the datastore (configapi.go).
	g.GET("/schema", s.handleSchema)
	g.GET("/config/changes", s.handleConfigChanges)
	g.POST("/config/discard", s.handleConfigDiscard)
	g.GET("/config/*", s.handleConfigGet)
	for _, m := range []string{http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete} {
		g.Add(m, "/config/*", s.handleConfigEdit)
	}
	g.GET("/deploy/check", s.handleDeployCheck)
	g.GET("/deploy/changes", s.handleDeployChanges)
	g.POST("/deploy/preview", s.handleDeployPreview)
	g.GET("/deploy/nftables", s.handleExportNftables)
	g.POST("/import/nftables", s.handleImportNftables)
	g.POST("/deploy/apply", s.handleDeployApply)
	g.POST("/deploy/confirm", s.handleDeployConfirm)
	g.POST("/deploy/rollback", s.handleDeployRollback)
	g.POST("/deploy/revert", s.handleDeployRevert)
	g.GET("/deployments", s.handleDeployments)
	g.GET("/agent/status", s.handleAgentStatus)
	g.GET("/agent/leases", s.handleAgentLeases)
	g.GET("/agent/neighbours", s.handleAgentNeighbours)
	g.GET("/agent/routing-table", s.handleAgentRoutingTable)
	g.GET("/agent/bgp", s.handleAgentBGP)
	g.GET("/agent/bgp/routes", s.handleAgentBGPRoutes)
	g.GET("/agent/bgp/neighbor", s.handleAgentBGPNeighbor)
	g.GET("/agent/ospf", s.handleAgentOSPF)
	g.GET("/agent/isis", s.handleAgentISIS)
	g.GET("/agent/vrrp", s.handleAgentVRRP)
	g.GET("/agent/bfd", s.handleAgentBFD)
	g.GET("/agent/ntp", s.handleAgentNTP)
	g.GET("/agent/syslog", s.handleAgentSyslog)
	g.GET("/agent/nat64", s.handleAgentNAT64)
	g.GET("/agent/openvpn", s.handleAgentOpenVPN)
	(&resource[models.LdapServer, *models.LdapServer]{db: s.db, order: "position, id", prepare: prepareLdapServer, present: presentLdapServer}).register(s, g, "/directory/servers")
	(&resource[models.LdapRoleMapping, *models.LdapRoleMapping]{db: s.db, order: "group_dn, role_id", prepare: prepareLdapRoleMapping}).register(s, g, "/directory/mappings")
	g.POST("/directory/servers/reorder", s.handleReorderLdapServers)
	g.POST("/directory/servers/test", s.handleTestLdapServer)
	g.GET("/directory/servers/:id/browse", s.handleBrowseLdapServer)
	g.GET("/agent/rule-counters", s.handleAgentRuleCounters)
	g.GET("/agent/rate-limits", s.handleAgentRateLimits)
	g.GET("/agent/logs", s.handleAgentLogs)
	g.GET("/agent/packet-log", s.handleAgentPacketLog)
	g.GET("/agent/dns-query-log", s.handleAgentDNSQueryLog)
	g.GET("/agent/console", s.handleAgentConsole)
	g.POST("/agent/capture", s.handleAgentCapture)
	g.POST("/agent/trace", s.handleAgentTrace)
	g.POST("/agent/iperf", s.handleAgentIperf)
	g.POST("/agent/probe", s.handleAgentProbe)
	g.POST("/agent/servicelog", s.handleAgentServiceLog)
	g.POST("/agent/journal", s.handleAgentJournal)
	g.POST("/agent/connections", s.handleAgentConnections)
	g.POST("/agent/connections/flush", s.handleAgentConnectionsFlush)
	g.POST("/agent/dhcp/renew", s.handleAgentDHCPRenew)
	g.GET("/system", s.handleSystem)
	g.POST("/system/jobs", s.handleSystemJob)
	g.POST("/system/reboot", s.handleSystemReboot)

	api.Any("/*", func(c *echo.Context) error { return errJSON(c, http.StatusNotFound, "no such API endpoint") })

	// The Vue SPA owns every other path: its files, and index.html for
	// the rest, so client-side routes survive a reload.
	e.Use(s.serveIndex)
	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		Filesystem: s.static,
		Root:       ".",
		Skipper: func(c *echo.Context) bool {
			p := c.Request().URL.Path
			return strings.HasPrefix(p, "/api/")
		},
	}))
	return e
}

// isPortalPrefix: a path portitor-web serves a firewall at (portalPrefix).
func isPortalPrefix(p string) bool {
	name, ok := strings.CutPrefix(p, "/fw/")
	return ok && fwconfig.ValidDefaultInstanceName(name)
}

// serveIndex answers the SPA's routes, and every path that is not one of
// its files, with index.html, its <base> the path portitor-web serves this
// firewall at (X-Forwarded-Prefix), or / without one.
func (s *Server) serveIndex(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		r := c.Request()
		p := strings.TrimPrefix(r.URL.Path, "/")
		if (r.Method != http.MethodGet && r.Method != http.MethodHead) || strings.HasPrefix(p, "api/") || strings.HasPrefix(p, "ha/") {
			return next(c)
		}
		if p != "" && p != "index.html" {
			if fi, err := fs.Stat(s.static, p); err == nil && !fi.IsDir() {
				return next(c)
			}
		}
		page, err := fs.ReadFile(s.static, "index.html")
		if err != nil {
			return errJSON(c, http.StatusNotFound, "the GUI is not built (web/static)")
		}
		base := "/"
		if pre := r.Header.Get("X-Forwarded-Prefix"); isPortalPrefix(pre) {
			base = pre + "/"
		}
		page = bytes.Replace(page, []byte("<head>"), []byte(`<head><base href="`+base+`">`), 1)
		// The browser's tab names the firewall it is on.
		if host, err := os.Hostname(); err == nil && s.cfg.Local {
			page = bytes.Replace(page, []byte("<title>Portitor</title>"),
				[]byte("<title>Portitor · "+html.EscapeString(host)+"</title>"), 1)
		}
		c.Response().Header().Set("Cache-Control", "no-cache")
		return c.HTMLBlob(http.StatusOK, page)
	}
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
	if s.cfg.Local {
		go s.runRole(ctx)
	}
	go s.runWitness(ctx)
	go s.runDirectorySync(ctx)
	go s.runSSH(ctx)
	go s.runSNMP(ctx)
	sc := echo.StartConfig{Address: s.cfg.Bind, HideBanner: true}
	slog.Info("portitor-config listening", "addr", s.cfg.Bind, "dev", s.cfg.Dev, "tls", s.cfg.TLSCert != "")
	var err error
	if s.cfg.TLSCert != "" {
		cert, key, rerr := readFiles(s.cfg.TLSCert, s.cfg.TLSKey)
		if rerr != nil {
			return rerr
		}
		fallback, rerr := tls.X509KeyPair(cert, key)
		if rerr != nil {
			return fmt.Errorf("tls_cert: %w", rerr)
		}
		s.webCert = s.newTLSCert(&fallback)
		go s.webCert.run(ctx)
		sc.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: s.webCert.get}
		err = sc.Start(ctx, e)
	} else {
		err = sc.Start(ctx, e)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func readFiles(a, b string) ([]byte, []byte, error) {
	da, err := os.ReadFile(a)
	if err != nil {
		return nil, nil, err
	}
	db, err := os.ReadFile(b)
	return da, db, err
}

// DefaultInstanceName is the instance created on start when there is none.
const DefaultInstanceName = "main"

// ensureDefaultInstance creates the first firewall and its default
// instance if there are no instances, since everything else belongs to one.
func (s *Server) ensureDefaultInstance() error {
	if err := s.ensureFirewall(); err != nil {
		return err
	}
	ctx := context.Background()
	v, err := s.view(ctx)
	if err != nil || len(v.Instances) > 0 {
		return err
	}
	var fw models.Firewall
	if err := s.db.Order("id").First(&fw).Error; err != nil {
		return err
	}
	if err := s.addDefaultInstance(ctx, fw.Name, DefaultInstanceName); err != nil {
		return err
	}
	slog.Info("created default instance", "name", DefaultInstanceName)
	return nil
}

// settings are the Settings: the configuration's (the tree's settings),
// with the commit counter and the GUI's certificate, which are
// portitor-config's own (the table settings, row 1).
func (s *Server) settings() (*models.Settings, error) {
	own, err := s.ownSettings()
	if err != nil {
		return nil, err
	}
	v, err := s.view(context.Background())
	if err != nil {
		return nil, err
	}
	st := v.Settings
	st.ID, st.LastCommit, st.WebCertificateID = 1, own.LastCommit, own.WebCertificateID
	return &st, nil
}

// settingsOf is settings with the configuration's of tree.
func (s *Server) settingsOf(tree *datastore.Tree) (*models.Settings, error) {
	own, err := s.ownSettings()
	if err != nil {
		return nil, err
	}
	v, err := s.viewOf(tree)
	if err != nil {
		return nil, err
	}
	st := v.Settings
	st.ID, st.LastCommit, st.WebCertificateID = 1, own.LastCommit, own.WebCertificateID
	return &st, nil
}

// ownSettings is the row of the settings that are not configuration.
type ownSettings struct {
	LastCommit       int64
	WebCertificateID *uint
}

func (s *Server) ownSettings() (*ownSettings, error) {
	if err := s.db.Exec("INSERT OR IGNORE INTO settings (id) VALUES (1)").Error; err != nil {
		return nil, err
	}
	var own ownSettings
	if err := s.db.Table("settings").Select("last_commit, web_certificate_id").Where("id = 1").Take(&own).Error; err != nil {
		return nil, err
	}
	return &own, nil
}
