// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package web is portitor-web: the REST API behind the Vue GUI, and the
// place configuration is built and pushed to portitor-agent.
package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
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
	BGPNeighborRoutes(ctx context.Context, instance, neighbor string) (*agentapi.BGPNeighborRoutes, error)
	BGPNeighborDetail(ctx context.Context, instance, neighbor string) (*agentapi.BGPNeighborDetail, error)
	OSPF(ctx context.Context) (*agentapi.OSPFResponse, error)
	VRRP(ctx context.Context) (*agentapi.VRRPResponse, error)
	BFD(ctx context.Context) (*agentapi.BFDResponse, error)
	NTP(ctx context.Context) (*agentapi.NTPResponse, error)
	RuleCounters(ctx context.Context) (*agentapi.RuleCountersResponse, error)
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
	Console(ctx context.Context, instance string) (*websocket.Conn, error)
	Capture(ctx context.Context, req agentapi.CaptureRequest) (io.ReadCloser, error)
	Trace(ctx context.Context, req agentapi.TraceRequest) (io.ReadCloser, error)
	ServiceLog(ctx context.Context, req agentapi.ServiceLogRequest) (io.ReadCloser, error)
	Connections(ctx context.Context, req agentapi.ConnectionsRequest) (io.ReadCloser, error)
	FlushConnections(ctx context.Context, instance string) error
	RenewDHCP(ctx context.Context, req agentapi.DHCPRenewRequest) error
	System(ctx context.Context) (*agentapi.SystemStatus, error)
	StartSystemJob(ctx context.Context, req agentapi.SystemJobRequest) error
	Reboot(ctx context.Context) error
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
	// newAgent builds a client from the current settings.
	newAgent func(s *models.Settings) (agentAPI, error)
	static   fs.FS
	// webCert serves HTTPS when portitor-web does (tls_cert); nil otherwise.
	webCert *tlsCert
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

	api := e.Group("/api", requireJSON, noStore)
	api.POST("/login", s.handleLogin)
	api.POST("/logout", s.handleLogout)
	api.GET("/version", func(c *echo.Context) error { return c.JSON(http.StatusOK, buildinfo.Get()) })

	s.tenantWrites = map[string]bool{}
	g := api.Group("", s.requireAuth, s.requireRole)
	g.GET("/me", s.handleMe)
	g.PUT("/me", s.handleUpdateMe)
	g.POST("/me/password", s.handleChangePassword)

	(&resource[models.Instance, *models.Instance]{db: s.db, scope: instanceScope, tenantWrites: []string{http.MethodPut}, tenantCheck: tenantInstanceCheck, order: "is_default desc, name", prepare: prepareInstance, present: presentInstance, afterCreate: seedInstance, beforeDelete: deleteInstance}).register(s, g, "/instances")
	(&resource[models.InterfaceZone, *models.InterfaceZone]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "name", prepare: prepareInterfaceZone, beforeDelete: deleteInterfaceZone}).register(s, g, "/interface-zones")
	(&resource[models.Interface, *models.Interface]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, tenantCheck: tenantInterfaceCheck, filters: []string{"instance_id"}, order: "name", prepare: prepareInterface, present: presentInterface, beforeDelete: deleteInterface}).register(s, g, "/interfaces")
	(&resource[models.WgPeer, *models.WgPeer]{db: s.db, scope: byParent("InterfaceID", "interface_id", "interfaces"), tenantWrites: tenantAll, filters: []string{"interface_id"}, order: "name", prepare: prepareWgPeer, present: presentWgPeer}).register(s, g, "/wg/peers")
	(&resource[models.Link, *models.Link]{db: s.db, scope: linkScope, order: "name", prepare: prepareLink, beforeDelete: deleteLink}).register(s, g, "/links")
	(&resource[models.Route, *models.Route]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "destination", prepare: prepareRoute}).register(s, g, "/routes")
	(&resource[models.RoutePrefixList, *models.RoutePrefixList]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "name", prepare: preparePrefixList, beforeDelete: deletePrefixList}).register(s, g, "/routing/prefix-lists")
	(&resource[models.RouteAsPathList, *models.RouteAsPathList]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "name", prepare: prepareAsPathList, beforeDelete: deleteAsPathList}).register(s, g, "/routing/as-path-lists")
	(&resource[models.RouteCommunityList, *models.RouteCommunityList]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "name", prepare: prepareCommunityList, beforeDelete: deleteCommunityList}).register(s, g, "/routing/community-lists")
	(&resource[models.RouteMap, *models.RouteMap]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "name", prepare: prepareRouteMap, beforeDelete: deleteRouteMap}).register(s, g, "/routing/route-maps")
	(&resource[models.BgpConfig, *models.BgpConfig]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "id", prepare: prepareBgpConfig}).register(s, g, "/bgp/config")
	(&resource[models.BgpPeerGroup, *models.BgpPeerGroup]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "name", prepare: preparePeerGroup, present: presentPeerGroup, beforeDelete: deletePeerGroup}).register(s, g, "/bgp/peer-groups")
	(&resource[models.BgpNeighbor, *models.BgpNeighbor]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "address", prepare: prepareNeighbor, present: presentNeighbor}).register(s, g, "/bgp/neighbors")
	(&resource[models.OspfConfig, *models.OspfConfig]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id", "version"}, order: "version", prepare: prepareOspfConfig}).register(s, g, "/ospf/config")
	(&resource[models.SnmpUser, *models.SnmpUser]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "name", prepare: prepareSnmpUser, present: presentSnmpUser}).register(s, g, "/snmp/users")
	(&resource[models.OspfInterface, *models.OspfInterface]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id", "version"}, order: "name", prepare: prepareOspfInterface, present: presentOspfInterface}).register(s, g, "/ospf/interfaces")
	(&resource[models.VrrpRouter, *models.VrrpRouter]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "interface, vrid", prepare: prepareVrrpRouter}).register(s, g, "/vrrp/routers")
	(&resource[models.BfdInterface, *models.BfdInterface]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "interface", prepare: prepareBfdInterface}).register(s, g, "/bfd/interfaces")
	(&resource[models.Vrf, *models.Vrf]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "name", prepare: prepareVrf, beforeDelete: deleteVrf}).register(s, g, "/vrfs")
	(&resource[models.RateLimit, *models.RateLimit]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "name", prepare: prepareRateLimit, beforeDelete: deleteRateLimit}).register(s, g, "/rate-limits")
	(&resource[models.Rule, *models.Rule]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "position, id", prepare: prepareRule}).register(s, g, "/rules")
	(&resource[models.NatRule, *models.NatRule]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "position, id", prepare: prepareNat}).register(s, g, "/nat")
	(&resource[models.IpamPrefix, *models.IpamPrefix]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "prefix", prepare: prepareIpamPrefix}).register(s, g, "/ipam/prefixes")
	(&resource[models.IpamAddress, *models.IpamAddress]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "address", prepare: prepareIpamAddress}).register(s, g, "/ipam/addresses")
	(&resource[models.DnsZone, *models.DnsZone]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "name", prepare: prepareDnsZone}).register(s, g, "/dns/zones")
	(&resource[models.DnsRecord, *models.DnsRecord]{db: s.db, scope: byParent("ZoneID", "zone_id", "dns_zones"), tenantWrites: tenantAll, filters: []string{"zone_id"}, order: "rank, id", prepare: prepareDnsRecord}).register(s, g, "/dns/records")
	(&resource[models.DnsSoaTemplate, *models.DnsSoaTemplate]{db: s.db, scope: globalScope, tenantWrites: tenantAll, order: "name", prepare: prepareDnsSoaTemplate, beforeDelete: deleteDnsSoaTemplate}).register(s, g, "/dns/soa-templates")
	(&resource[models.DnsDnssecPolicy, *models.DnsDnssecPolicy]{db: s.db, scope: globalScope, tenantWrites: tenantAll, order: "name", prepare: prepareDnsDnssecPolicy, beforeDelete: deleteDnsDnssecPolicy}).register(s, g, "/dns/dnssec-policies")
	(&resource[models.DnsTemplate, *models.DnsTemplate]{db: s.db, scope: globalScope, tenantWrites: tenantAll, order: "name", prepare: prepareDnsTemplate, beforeDelete: deleteDnsTemplate}).register(s, g, "/dns/templates")
	(&resource[models.DyndnsClient, *models.DyndnsClient]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "name", prepare: prepareDyndnsClient, present: presentDyndnsClient, beforeDelete: deleteDyndnsClient}).register(s, g, "/dyndns/clients")
	(&resource[models.Certificate, *models.Certificate]{db: s.db, scope: byField("InstanceID", "instance_id"), tenantWrites: tenantAll, filters: []string{"instance_id"}, order: "name", prepare: prepareCertificate, present: presentCertificate}).register(s, g, "/certificates")
	(&resource[models.DyndnsRecord, *models.DyndnsRecord]{db: s.db, scope: byParent("ClientID", "client_id", "dyndns_clients"), tenantWrites: tenantAll, filters: []string{"client_id"}, order: "id", prepare: prepareDyndnsRecord}).register(s, g, "/dyndns/records")
	(&resource[models.AddressObject, *models.AddressObject]{db: s.db, order: "name", prepare: prepareAddressObject, beforeDelete: deleteAddressObject}).register(s, g, "/objects")
	(&resource[models.AddressList, *models.AddressList]{db: s.db, order: "name", prepare: prepareAddressList, beforeDelete: deleteAddressList}).register(s, g, "/address-lists")
	(&resource[models.IpList, *models.IpList]{db: s.db, order: "name", prepare: prepareIpList, present: presentIpList, beforeDelete: deleteIpList}).register(s, g, "/ip-lists")
	(&resource[models.ObjectFolder, *models.ObjectFolder]{db: s.db, order: "name", prepare: prepareObjectFolder, beforeDelete: deleteObjectFolder}).register(s, g, "/object-folders")
	(&resource[models.Task, *models.Task]{db: s.db, order: "name", prepare: prepareTask}).register(s, g, "/tasks")
	(&resource[models.Service, *models.Service]{db: s.db, order: "name", prepare: prepareService, beforeDelete: deleteService}).register(s, g, "/custom-services")

	// Instance admins use these too; the handlers check the instance.
	for _, r := range []string{"PUT /api/dns/zones/:id/records", "PUT /api/dyndns/clients/:id/records", "POST /api/rules/reorder", "POST /api/nat/reorder",
		"POST /api/interfaces/:id/wg-rekey", "POST /api/wg/import", "POST /api/agent/capture", "POST /api/agent/trace", "POST /api/agent/servicelog", "POST /api/agent/connections", "POST /api/agent/connections/flush", "POST /api/agent/dhcp/renew",
		"POST /api/deploy/apply", "POST /api/deploy/confirm", "POST /api/deploy/rollback"} {
		s.tenantWrites[r] = true
	}
	g.PUT("/dns/zones/:id/records", s.handleZoneRecords)
	g.PUT("/dyndns/clients/:id/records", s.handleDyndnsRecords)
	g.GET("/ipam/tree", s.handleIpamTree)
	g.GET("/ipam/prefixes/:id/next-free", s.handleNextFree)
	g.GET("/rules/auto", s.handleAutoRules)
	g.GET("/services", func(c *echo.Context) error { return c.JSON(http.StatusOK, fwconfig.Services) })
	g.GET("/certificates/cas", func(c *echo.Context) error { return c.JSON(http.StatusOK, fwconfig.ACMECAs) })
	g.GET("/certificates/:id/download", s.handleCertificateDownload)
	g.GET("/dyndns/providers", func(c *echo.Context) error { return c.JSON(http.StatusOK, fwconfig.DNSProviders) })
	g.GET("/predefined-services", func(c *echo.Context) error { return c.JSON(http.StatusOK, netobj.Predefined) })
	g.GET("/icmp-types", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string][]fwconfig.ICMPType{"icmp": fwconfig.ICMPTypes, "icmpv6": fwconfig.ICMPv6Types})
	})
	g.POST("/rules/reorder", s.handleReorder("rules"))
	g.POST("/nat/reorder", s.handleReorder("nat_rules"))
	g.GET("/wg/peers/:id/config", s.handleWgClientConfig)
	g.POST("/interfaces/:id/wg-rekey", s.handleWgRekey)
	g.POST("/wg/import", s.handleWgImport)
	g.GET("/interfaces/:id/wg-next-free", s.handleWgNextFree)
	g.POST("/ip-lists/:id/refresh", s.handleIPListRefresh)
	g.POST("/tasks/:id/run", s.handleTaskRun)
	g.GET("/schedule/preview", s.handleSchedulePreview)

	g.GET("/settings", s.handleGetSettings)
	g.PUT("/settings", s.handlePutSettings)
	g.POST("/backup", s.handleBackup)
	g.POST(strings.TrimPrefix(restorePath, "/api"), s.handleRestore, middleware.BodyLimit(backupMaxSize/3*4+1<<20))
	g.GET("/users", s.handleListUsers)
	g.POST("/users", s.handleCreateUser)
	g.PUT("/users/:id", s.handleUpdateUser)
	g.POST("/users/:id/password", s.handleSetUserPassword)
	g.DELETE("/users/:id", s.handleDeleteUser)
	g.GET("/roles", s.handleListRoles)
	g.POST("/roles", s.handleCreateRole)
	g.PUT("/roles/:id", s.handleUpdateRole)
	g.DELETE("/roles/:id", s.handleDeleteRole)

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
	g.GET("/agent/vrrp", s.handleAgentVRRP)
	g.GET("/agent/bfd", s.handleAgentBFD)
	g.GET("/agent/ntp", s.handleAgentNTP)
	g.GET("/agent/rule-counters", s.handleAgentRuleCounters)
	g.GET("/agent/logs", s.handleAgentLogs)
	g.GET("/agent/packet-log", s.handleAgentPacketLog)
	g.GET("/agent/dns-query-log", s.handleAgentDNSQueryLog)
	g.GET("/agent/console", s.handleAgentConsole)
	g.POST("/agent/capture", s.handleAgentCapture)
	g.POST("/agent/trace", s.handleAgentTrace)
	g.POST("/agent/servicelog", s.handleAgentServiceLog)
	g.POST("/agent/connections", s.handleAgentConnections)
	g.POST("/agent/connections/flush", s.handleAgentConnectionsFlush)
	g.POST("/agent/dhcp/renew", s.handleAgentDHCPRenew)
	g.GET("/system", s.handleSystem)
	g.POST("/system/jobs", s.handleSystemJob)
	g.POST("/system/reboot", s.handleSystemReboot)

	e.GET("/wiregasm/*", s.handleWiregasm)

	api.Any("/*", func(c *echo.Context) error { return errJSON(c, http.StatusNotFound, "no such API endpoint") })

	// The Vue SPA owns every other path; unknown paths fall back to
	// index.html so client-side routes survive a reload.
	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		Filesystem: s.static,
		Root:       ".",
		HTML5:      true,
		Skipper: func(c *echo.Context) bool {
			p := c.Request().URL.Path
			return strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/wiregasm/")
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

// tenantAll: an instance admin adds, changes and deletes the rows.
var tenantAll = []string{http.MethodPost, http.MethodPut, http.MethodDelete}

// tenantInstanceCheck: an instance admin changes their instance's
// settings, but not its name.
func tenantInstanceCheck(in, old *models.Instance) error {
	if in.Name != old.Name {
		return bad("only a global admin renames a virtual firewall")
	}
	return nil
}

// deleteInstance refuses to delete the default instance: it is the host.
func deleteInstance(tx *gorm.DB, in *models.Instance) error {
	if in.IsDefault {
		return bad("the default virtual firewall is the host itself and can't be deleted")
	}
	// The cascade would delete the DNS templates in any order, and those
	// in use refuse it: zones first, then templates, then what they use.
	for _, m := range []any{&models.DnsZone{}, &models.DnsTemplate{}, &models.DnsSoaTemplate{}, &models.DnsDnssecPolicy{}} {
		if err := tx.Where("instance_id = ?", in.ID).Delete(m).Error; err != nil {
			return err
		}
	}
	return nil
}

// tenantInterfaceCheck: physical NICs belong to the host, so only a global
// admin hands one to an instance (adds, renames or removes it). Old is nil
// on create and delete.
func tenantInterfaceCheck(i, old *models.Interface) error {
	if (i.Kind == fwconfig.KindPhysical || i.Kind == "") && (old == nil || old.Name != i.Name || old.InstanceID != i.InstanceID) {
		return bad("only a global admin adds, renames or removes a physical interface")
	}
	return nil
}

// DefaultInstanceName is the instance created on start when there is none.
const DefaultInstanceName = "main"

// ensureDefaultInstance creates the default instance if there are no
// instances, since everything else belongs to one. It logs the policy
// drops of all three chains.
func (s *Server) ensureDefaultInstance() error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var n int64
		if err := tx.Model(&models.Instance{}).Count(&n).Error; err != nil || n > 0 {
			return err
		}
		// Log what no rule matched, so a new install shows what it drops.
		in := models.Instance{Name: DefaultInstanceName, IsDefault: true,
			LogDrops: models.StringList{fwconfig.ChainInput, fwconfig.ChainForward, fwconfig.ChainOutput}}
		if err := prepareInstance(tx, &in, nil); err != nil {
			return err
		}
		if err := tx.Create(&in).Error; err != nil {
			return err
		}
		if err := seedInstance(tx, &in); err != nil {
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
