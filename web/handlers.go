// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/ipam"
	"github.com/abundo/portitor/internal/netobj"
	"github.com/abundo/portitor/internal/render"
	"github.com/abundo/portitor/internal/wgkeys"
	"github.com/abundo/portitor/models"
)

// ----- IPAM -----

func (s *Server) handleIpamTree(c *echo.Context) error {
	id, err := echo.QueryParam[uint](c, "instance_id")
	if err != nil {
		return errJSON(c, http.StatusBadRequest, "instance_id is required")
	}
	var prefixes []models.IpamPrefix
	var addrs []models.IpamAddress
	if err := s.db.Where("instance_id = ?", id).Find(&prefixes).Error; err != nil {
		return err
	}
	if err := s.db.Where("instance_id = ?", id).Find(&addrs).Error; err != nil {
		return err
	}
	tree := ipam.Tree(prefixes, addrs)
	if tree == nil {
		tree = []*ipam.Node{}
	}
	return c.JSON(http.StatusOK, tree)
}

// handleAutoRules lists the input rules the agent adds for an instance's
// services (DHCP, DNS, WireGuard), rendered from the current database. A
// configuration with problems still lists what it can. For the default
// instance it also asks the agent for its anti-lockout rule, which comes
// from agent.yaml; an unreachable agent just leaves it out.
func (s *Server) handleAutoRules(c *echo.Context) error {
	id, err := echo.QueryParam[uint](c, "instance_id")
	if err != nil {
		return errJSON(c, http.StatusBadRequest, "instance_id is required")
	}
	var mi models.Instance
	if err := s.db.First(&mi, id).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	doc, err := builder.Build(s.db, 0)
	var ve *fwconfig.ValidationError
	if err != nil && !errors.As(err, &ve) {
		return err
	}
	out := []render.AutoRule{}
	if mi.IsDefault {
		if l := s.antiLockout(c.Request().Context()); l != nil {
			out = append(out, l.Rule())
		}
	}
	exp := doc.Expand()
	if in := exp.Instance(mi.Name); in != nil {
		out = append(out, render.AutoInputRules(in)...)
	}
	return c.JSON(http.StatusOK, out)
}

// antiLockout returns the agent's anti-lockout rule, or nil when it is
// disabled or the agent cannot be asked.
func (s *Server) antiLockout(ctx context.Context) *render.AntiLockout {
	a, _, err := s.agent()
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := a.Status(ctx)
	if err != nil || st.AntiLockout == nil || st.AntiLockout.Port <= 0 || len(st.AntiLockout.AllowFrom) == 0 {
		return nil
	}
	return st.AntiLockout
}

func (s *Server) handleNextFree(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var p models.IpamPrefix
	if err := s.db.First(&p, id).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var prefixes []models.IpamPrefix
	var addrs []models.IpamAddress
	s.db.Where("instance_id = ?", p.InstanceID).Find(&prefixes)
	s.db.Where("instance_id = ?", p.InstanceID).Find(&addrs)
	ip, err := ipam.NextFree(p, prefixes, addrs)
	if err != nil {
		return errJSON(c, http.StatusConflict, err.Error())
	}
	return c.JSON(http.StatusOK, map[string]string{"address": ip.String()})
}

// ----- rule ordering -----

// handleReorder sets positions from the order of the given ids.
func (s *Server) handleReorder(table string) echo.HandlerFunc {
	return func(c *echo.Context) error {
		var req struct {
			IDs []uint `json:"ids"`
		}
		if err := c.Bind(&req); err != nil {
			return errJSON(c, http.StatusBadRequest, "invalid request")
		}
		err := s.db.Transaction(func(tx *gorm.DB) error {
			for i, id := range req.IDs {
				if err := tx.Table(table).Where("id = ?", id).Update("position", (i+1)*10).Error; err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		return c.NoContent(http.StatusNoContent)
	}
}

// ----- WireGuard -----

func (s *Server) handleWgRekey(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var ifc models.Interface
	if err := s.db.First(&ifc, id).Error; err != nil || ifc.Kind != fwconfig.KindWireGuard {
		return errJSON(c, http.StatusNotFound, "no such WireGuard interface")
	}
	priv, pub, err := wgkeys.Generate()
	if err != nil {
		return err
	}
	ifc.WgPrivateKey, ifc.WgPublicKey = priv, pub
	if err := s.db.Save(&ifc).Error; err != nil {
		return err
	}
	return c.JSON(http.StatusOK, ifc)
}

// handleWgClientConfig renders a wg-quick config for the remote side of a
// peer. ?split=1 routes only the instance's IPAM prefixes through the
// tunnel instead of everything. A site peer (one with networks) always
// gets those prefixes, less the ones behind it, and no DNS.
func (s *Server) handleWgClientConfig(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var peer models.WgPeer
	if err := s.db.First(&peer, id).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var ifc models.Interface
	if err := s.db.First(&ifc, peer.InterfaceID).Error; err != nil {
		return err
	}
	var inst models.Instance
	s.db.First(&inst, ifc.InstanceID)
	st, err := s.settings()
	if err != nil {
		return err
	}

	var objs []models.AddressObject
	s.db.Find(&objs)
	addrs, err := netobj.New(objs).Prefixes(peer.AllowedIPs)
	if err != nil {
		return errJSON(c, http.StatusBadRequest, err.Error())
	}
	cc := render.WGClientConfig{
		PrivateKey:      peer.ClientPrivateKey,
		Addresses:       addrs,
		ServerPublicKey: ifc.WgPublicKey,
		PresharedKey:    peer.PresharedKey,
		AllowedIPs:      []string{"0.0.0.0/0", "::/0"},
		Keepalive:       ifc.WgKeepalive,
		Endpoint:        ifc.WgEndpoint,
	}
	if cc.Endpoint == "" && st.WgEndpointHost != "" && ifc.WgListenPort > 0 {
		host := st.WgEndpointHost
		if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
			host = "[" + host + "]"
		}
		cc.Endpoint = fmt.Sprintf("%s:%d", host, ifc.WgListenPort)
	}
	site := len(peer.Networks) > 0
	if inst.DnsEnabled && ifc.DnsListen && !site {
		var addrs []models.IpamAddress
		s.db.Where("interface_id = ?", ifc.ID).Find(&addrs)
		for _, a := range addrs {
			cc.DNS = append(cc.DNS, a.Address)
		}
	}
	if site || c.QueryParam("split") == "1" {
		remote, err := netobj.New(objs).Prefixes(peer.Networks)
		if err != nil {
			return errJSON(c, http.StatusBadRequest, err.Error())
		}
		var prefixes []models.IpamPrefix
		s.db.Where("instance_id = ?", ifc.InstanceID).Find(&prefixes)
		roots := ipam.Tree(prefixes, nil)
		cc.AllowedIPs = nil
		for _, r := range roots {
			if !insideAny(r.CIDR, remote) {
				cc.AllowedIPs = append(cc.AllowedIPs, r.CIDR)
			}
		}
	}
	var warnings []string
	if peer.ClientPrivateKey == "" {
		warnings = append(warnings, "The client's private key is not stored here (its public key was pasted); fill it in on the client.")
	}
	if cc.Endpoint == "" {
		warnings = append(warnings, "Set the public endpoint on the interface (or the endpoint host under Settings, and a listen port on the interface).")
	}
	if site && len(cc.AllowedIPs) == 0 {
		warnings = append(warnings, "This instance has no prefixes under IP addresses, so the config routes nothing to this side.")
	}
	return c.JSON(http.StatusOK, map[string]any{"config": render.WireGuardClientConf(cc), "warnings": warnings, "site": site})
}

// handleWgNextFree suggests allowed IPs for a new peer: per address family
// of the WireGuard interface, a host address of the IPAM prefix holding
// the interface's address that is neither in IPAM nor in the allowed IPs of
// a peer of the instance. Both families get the same host number if one is
// free in both (10.99.0.2/32 and fd99::2/128).
func (s *Server) handleWgNextFree(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var ifc models.Interface
	if err := s.db.First(&ifc, id).Error; err != nil || ifc.Kind != fwconfig.KindWireGuard {
		return errJSON(c, http.StatusNotFound, "no such WireGuard interface")
	}
	var prefixes []models.IpamPrefix
	var addrs []models.IpamAddress
	s.db.Where("instance_id = ?", ifc.InstanceID).Find(&prefixes)
	s.db.Where("instance_id = ?", ifc.InstanceID).Find(&addrs)

	// Peers' allowed IPs count as used: hosts as addresses, networks
	// behind a peer as prefixes.
	var peers []models.WgPeer
	s.db.Where("interface_id IN (?)", s.db.Model(&models.Interface{}).Select("id").Where("instance_id = ?", ifc.InstanceID)).Find(&peers)
	var objs []models.AddressObject
	s.db.Find(&objs)
	set := netobj.New(objs)
	used, usedPrefixes := addrs, prefixes
	for _, p := range peers {
		list, err := set.Prefixes(p.AllowedIPs)
		if err != nil {
			continue
		}
		for _, e := range list {
			pfx, err := netip.ParsePrefix(e)
			if err != nil {
				continue
			}
			if pfx.IsSingleIP() {
				used = append(used, models.IpamAddress{Address: pfx.Addr().String()})
			} else {
				usedPrefixes = append(usedPrefixes, models.IpamPrefix{Prefix: pfx.Masked().String()})
			}
		}
	}

	// One prefix per address family, IPv4 first: the interface's first
	// address in each family decides it.
	var targets []models.IpamPrefix
	var warnings []string
	seen := map[bool]bool{} // by Is4
	for _, a := range addrs {
		if a.InterfaceID == nil || *a.InterfaceID != ifc.ID {
			continue
		}
		ip, err := netip.ParseAddr(a.Address)
		if err != nil {
			continue
		}
		pfx, ok := ipam.Enclosing(prefixes, ip)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("%s on %s is not inside any IPAM prefix; add its prefix (e.g. %s) under IP addresses to get a suggestion.", ip, ifc.Name, suggestPrefix(ip)))
			continue
		}
		if seen[ip.Is4()] {
			continue
		}
		for _, p := range prefixes {
			if q, err := netip.ParsePrefix(p.Prefix); err == nil && q.Masked() == pfx {
				seen[ip.Is4()] = true
				if ip.Is4() {
					targets = append([]models.IpamPrefix{p}, targets...)
				} else {
					targets = append(targets, p)
				}
				break
			}
		}
	}
	out := []string{}
	if len(targets) > 0 {
		// The same host number in every family if possible, else each
		// family on its own.
		ips, err := ipam.NextFreeCommon(targets, usedPrefixes, used)
		if err != nil {
			ips = nil
			for _, t := range targets {
				ip, err := ipam.NextFree(t, usedPrefixes, used)
				if err != nil {
					warnings = append(warnings, err.Error())
					continue
				}
				ips = append(ips, ip)
			}
		}
		for _, ip := range ips {
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()).String())
		}
	}
	return c.JSON(http.StatusOK, map[string]any{"addresses": out, "warnings": warnings})
}

// suggestPrefix is the usual subnet around a tunnel address: /24 for
// IPv4, /64 for IPv6.
func suggestPrefix(ip netip.Addr) string {
	bits := 64
	if ip.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(ip, bits).Masked().String()
}

// ----- settings & users -----

type settingsView struct {
	models.Settings
	HasAgentToken bool `json:"has_agent_token"`
}

func (s *Server) handleGetSettings(c *echo.Context) error {
	st, err := s.settings()
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, settingsView{*st, st.AgentToken != ""})
}

func (s *Server) handlePutSettings(c *echo.Context) error {
	st, err := s.settings()
	if err != nil {
		return err
	}
	var req struct {
		AgentURL         *string `json:"agent_url"`
		AgentToken       *string `json:"agent_token"` // empty/absent keeps the stored token
		AgentFingerprint *string `json:"agent_fingerprint"`
		ConfirmTimeout   *int    `json:"confirm_timeout"`
		WgEndpointHost   *string `json:"wg_endpoint_host"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	if req.AgentURL != nil {
		u := strings.TrimSpace(*req.AgentURL)
		if u != "" && !strings.HasPrefix(u, "https://") {
			return errJSON(c, http.StatusBadRequest, "agent URL must start with https://")
		}
		st.AgentURL = strings.TrimRight(u, "/")
	}
	if req.AgentToken != nil && strings.TrimSpace(*req.AgentToken) != "" {
		st.AgentToken = strings.TrimSpace(*req.AgentToken)
	}
	if req.AgentFingerprint != nil {
		st.AgentFingerprint = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(*req.AgentFingerprint), ":", ""))
		if st.AgentFingerprint != "" && len(st.AgentFingerprint) != 64 {
			return errJSON(c, http.StatusBadRequest, "fingerprint must be 64 hex characters (SHA-256)")
		}
	}
	if req.ConfirmTimeout != nil {
		if *req.ConfirmTimeout < 0 || *req.ConfirmTimeout > 1800 {
			return errJSON(c, http.StatusBadRequest, "confirm timeout must be 0-1800 seconds")
		}
		st.ConfirmTimeout = *req.ConfirmTimeout
	}
	if req.WgEndpointHost != nil {
		h := strings.TrimSpace(*req.WgEndpointHost)
		if h != "" && !fwconfig.ValidEndpoint(h+":1") && !fwconfig.ValidEndpoint("["+h+"]:1") {
			return errJSON(c, http.StatusBadRequest, "endpoint host must be a host name or IP address")
		}
		st.WgEndpointHost = h
	}
	if err := s.db.Save(st).Error; err != nil {
		return err
	}
	return c.JSON(http.StatusOK, settingsView{*st, st.AgentToken != ""})
}

func (s *Server) handleListUsers(c *echo.Context) error {
	users := []models.User{}
	if err := s.db.Order("username").Find(&users).Error; err != nil {
		return err
	}
	return c.JSON(http.StatusOK, users)
}

func (s *Server) handleCreateUser(c *echo.Context) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		return errJSON(c, http.StatusBadRequest, "username is required")
	}
	u := models.User{Username: req.Username}
	if err := setPassword(&u, req.Password); err != nil {
		return errJSON(c, http.StatusBadRequest, err.Error())
	}
	if err := s.db.Create(&u).Error; err != nil {
		return dbError(c, err)
	}
	return c.JSON(http.StatusCreated, u)
}

func (s *Server) handleDeleteUser(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	if id == currentUser(c).ID {
		return errJSON(c, http.StatusBadRequest, "you cannot delete yourself")
	}
	if err := s.db.Delete(&models.User{}, id).Error; err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// ----- deploy -----

// problemsResponse answers 422 with the list of configuration problems.
func problemsResponse(c *echo.Context, err error) error {
	var ve *fwconfig.ValidationError
	if errors.As(err, &ve) {
		return c.JSON(http.StatusUnprocessableEntity, map[string]any{"error": "the configuration has problems", "problems": ve.Problems})
	}
	return err
}

func agentError(c *echo.Context, err error) error {
	var ae *agentclient.Error
	if errors.As(err, &ae) {
		return c.JSON(http.StatusBadGateway, map[string]any{"error": ae.Message, "problems": ae.Problems, "result": ae.Result})
	}
	var br *badRequest
	if errors.As(err, &br) {
		return errJSON(c, http.StatusBadRequest, br.msg)
	}
	return c.JSON(http.StatusBadGateway, map[string]any{"error": err.Error()})
}

func (s *Server) handleDeployCheck(c *echo.Context) error {
	st, err := s.settings()
	if err != nil {
		return err
	}
	doc, err := builder.Build(s.db, st.Generation+1)
	problems := []string{}
	var ve *fwconfig.ValidationError
	if errors.As(err, &ve) {
		problems = ve.Problems
	} else if err != nil {
		return err
	}
	counts := map[string]int{"instances": len(doc.Instances), "links": len(doc.Links)}
	for _, in := range doc.Instances {
		counts["interfaces"] += len(in.Interfaces)
		for _, r := range in.Rules {
			if r.Kind != fwconfig.RuleKindComment {
				counts["rules"]++
			}
		}
		counts["nat"] += len(in.NAT)
	}
	return c.JSON(http.StatusOK, map[string]any{"problems": problems, "counts": counts, "generation": st.Generation})
}

func (s *Server) handleDeployPreview(c *echo.Context) error {
	a, st, err := s.agent()
	if err != nil {
		return agentError(c, err)
	}
	doc, err := builder.Build(s.db, st.Generation+1)
	if err != nil {
		return problemsResponse(c, err)
	}
	res, err := a.Render(c.Request().Context(), *doc)
	if err != nil {
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, res)
}

func (s *Server) handleDeployApply(c *echo.Context) error {
	var req struct {
		ConfirmTimeout *int `json:"confirm_timeout"`
	}
	_ = c.Bind(&req)
	dep, res, err := s.deploy(c.Request().Context(), currentUser(c).Username, req.ConfirmTimeout)
	var ve *fwconfig.ValidationError
	switch {
	case errors.As(err, &ve):
		return problemsResponse(c, err)
	case err != nil:
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, map[string]any{"deployment": dep, "result": res})
}

// deploy builds the document, applies it and records the deployment.
// timeout nil takes the confirm timeout from the settings.
func (s *Server) deploy(ctx context.Context, username string, timeout *int) (*models.Deployment, *agentapi.ApplyResult, error) {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	a, st, err := s.agent()
	if err != nil {
		return nil, nil, err
	}
	gen := st.Generation + 1
	// Build from the snapshot, so it is exactly what Revert restores even
	// if an edit comes in meanwhile.
	snap, err := s.takeSnapshot(gen)
	if err != nil {
		return nil, nil, err
	}
	kept := false
	defer func() {
		if !kept {
			os.Remove(snap)
		}
	}()
	snapDB, err := openSnapshot(snap)
	if err != nil {
		return nil, nil, err
	}
	doc, err := builder.Build(snapDB, gen)
	closeDB(snapDB)
	if err != nil {
		return nil, nil, err
	}
	confirm := st.ConfirmTimeout
	if timeout != nil {
		confirm = *timeout
	}
	// Burn the generation even if the apply fails, so every attempt the
	// agent sees has a unique number.
	st.Generation = gen
	if err := s.db.Save(st).Error; err != nil {
		return nil, nil, err
	}
	docJSON, _ := json.Marshal(redactDoc(*doc))
	dep := models.Deployment{Generation: gen, Username: username, Document: string(docJSON), DocHash: docHash(*doc)}

	res, applyErr := a.Apply(ctx, *doc, confirm)
	switch {
	case applyErr != nil:
		dep.Status = "failed"
		dep.Message = applyErr.Error()
		var ae *agentclient.Error
		if errors.As(applyErr, &ae) && ae.Result != nil {
			res = ae.Result
			if ae.Result.RolledBack {
				dep.Message += " (previous configuration restored)"
			}
		}
	case res.ConfirmBy != nil:
		dep.Status = "pending"
		dep.Message = "confirm before " + res.ConfirmBy.Local().Format(time.TimeOnly)
	default:
		dep.Status = "applied"
	}
	if res != nil {
		dep.Log = strings.Join(res.Log, "\n")
	}
	if err := s.db.Create(&dep).Error; err != nil {
		return nil, nil, err
	}
	if dep.Status != "failed" {
		s.keepSnapshot(snap, gen)
		kept = true
	}
	return &dep, res, applyErr
}

func (s *Server) latestDeployment() (*models.Deployment, error) {
	var dep models.Deployment
	err := s.db.Order("generation desc, id desc").First(&dep).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &dep, err
}

// docHash identifies a document's content, whatever its generation.
func docHash(doc fwconfig.Document) string {
	doc.Generation = 0
	b, _ := json.Marshal(doc)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// liveDeployment is the latest deployment the firewall runs (or runs
// pending confirmation); a failed or rolled back one left the previous
// one in place.
func (s *Server) liveDeployment() (*models.Deployment, error) {
	var dep models.Deployment
	err := s.db.Where("status IN ?", []string{"applied", "pending", "confirmed"}).Order("generation desc, id desc").First(&dep).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &dep, err
}

// handleDeployChanges tells whether the database differs from what is
// deployed, for the "uncommitted changes" banner.
func (s *Server) handleDeployChanges(c *echo.Context) error {
	resp := struct {
		Changed  bool `json:"changed"`
		Deployed bool `json:"deployed"`
		Problems int  `json:"problems"`
	}{}
	live, err := s.liveDeployment()
	if err != nil {
		return err
	}
	resp.Deployed = live != nil
	doc, err := builder.Build(s.db, 0)
	var ve *fwconfig.ValidationError
	switch {
	case errors.As(err, &ve):
		// What is deployed was valid, so this is a change.
		resp.Changed, resp.Problems = true, len(ve.Problems)
	case err != nil:
		return err
	case live == nil:
		resp.Changed = true
	case live.DocHash != "":
		resp.Changed = live.DocHash != docHash(*doc)
	default:
		// Older rows only have the redacted document, so key changes go
		// unnoticed there.
		var old fwconfig.Document
		if json.Unmarshal([]byte(live.Document), &old) != nil {
			resp.Changed = true
			break
		}
		resp.Changed = docHash(old) != docHash(redactDoc(*doc))
	}
	return c.JSON(http.StatusOK, resp)
}

func (s *Server) handleDeployConfirm(c *echo.Context) error {
	a, _, err := s.agent()
	if err != nil {
		return agentError(c, err)
	}
	dep, err := s.latestDeployment()
	if err != nil {
		return err
	}
	if dep == nil || dep.Status != "pending" {
		return errJSON(c, http.StatusConflict, "no change is waiting for confirmation")
	}
	if err := a.Confirm(c.Request().Context(), dep.Generation); err != nil {
		return agentError(c, err)
	}
	dep.Status, dep.Message = "confirmed", "confirmed by "+currentUser(c).Username
	s.db.Save(dep)
	return c.JSON(http.StatusOK, dep)
}

func (s *Server) handleDeployRollback(c *echo.Context) error {
	a, _, err := s.agent()
	if err != nil {
		return agentError(c, err)
	}
	res, err := a.Rollback(c.Request().Context())
	if err != nil {
		return agentError(c, err)
	}
	if dep, _ := s.latestDeployment(); dep != nil && dep.Status == "pending" {
		dep.Status, dep.Message = "rolled_back", "rolled back by "+currentUser(c).Username
		s.db.Save(dep)
	}
	return c.JSON(http.StatusOK, res)
}

func (s *Server) handleDeployments(c *echo.Context) error {
	limit := 50
	if n, err := strconv.Atoi(c.QueryParam("limit")); err == nil && n > 0 && n <= 500 {
		limit = n
	}
	deps := []models.Deployment{}
	if err := s.db.Order("id desc").Limit(limit).Find(&deps).Error; err != nil {
		return err
	}
	return c.JSON(http.StatusOK, deps)
}

func (s *Server) handleAgentStatus(c *echo.Context) error {
	a, _, err := s.agent()
	if err != nil {
		return agentError(c, err)
	}
	st, err := a.Status(c.Request().Context())
	if err != nil {
		return agentError(c, err)
	}
	// A pending deployment that the agent no longer holds was either
	// confirmed elsewhere or rolled back on timeout.
	if dep, _ := s.latestDeployment(); dep != nil && dep.Status == "pending" && st.Pending == nil {
		if st.Generation == dep.Generation {
			dep.Status, dep.Message = "confirmed", "confirmed"
		} else {
			dep.Status, dep.Message = "rolled_back", fmt.Sprintf("not confirmed in time; agent restored generation %d", st.Generation)
		}
		s.db.Save(dep)
	}
	sync, err := s.syncNICs(st.NICs)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, struct {
		*agentapi.Status
		NICSync *nicSync `json:"nic_sync"`
	}{st, sync})
}

func (s *Server) handleAgentLeases(c *echo.Context) error {
	a, _, err := s.agent()
	if err != nil {
		return agentError(c, err)
	}
	l, err := a.Leases(c.Request().Context())
	if err != nil {
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, l)
}

// handleAgentRuleCounters passes on the traffic per rule (by rule id), for
// the Rules page.
func (s *Server) handleAgentRuleCounters(c *echo.Context) error {
	a, _, err := s.agent()
	if err != nil {
		return agentError(c, err)
	}
	rc, err := a.RuleCounters(c.Request().Context())
	if err != nil {
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, rc)
}

// handleAgentLogs passes on the agent's log records after ?after=<id>,
// for the log panel.
func (s *Server) handleAgentLogs(c *echo.Context) error {
	after, _ := strconv.ParseInt(c.QueryParam("after"), 10, 64)
	a, _, err := s.agent()
	if err != nil {
		return agentError(c, err)
	}
	l, err := a.Logs(c.Request().Context(), after)
	if err != nil {
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, l)
}

// handleAgentPacketLog passes on the packets the rulesets logged after
// ?after=<id>, for the log panel's logged packets.
func (s *Server) handleAgentPacketLog(c *echo.Context) error {
	after, _ := strconv.ParseInt(c.QueryParam("after"), 10, 64)
	a, _, err := s.agent()
	if err != nil {
		return agentError(c, err)
	}
	l, err := a.PacketLog(c.Request().Context(), after)
	if err != nil {
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, l)
}

// redactDoc strips key material before a document is stored in the
// deployment history.
func redactDoc(doc fwconfig.Document) fwconfig.Document {
	out := doc
	out.Instances = make([]fwconfig.Instance, len(doc.Instances))
	for i, in := range doc.Instances {
		cp := in
		cp.Interfaces = make([]fwconfig.Interface, len(in.Interfaces))
		for j, ifc := range in.Interfaces {
			if ifc.WireGuard != nil {
				wg := *ifc.WireGuard
				wg.PrivateKey = "<redacted>"
				wg.Peers = make([]fwconfig.WGPeer, len(ifc.WireGuard.Peers))
				for k, p := range ifc.WireGuard.Peers {
					if p.PresharedKey != "" {
						p.PresharedKey = "<redacted>"
					}
					wg.Peers[k] = p
				}
				ifc.WireGuard = &wg
			}
			cp.Interfaces[j] = ifc
		}
		cp.DynDNS = make([]fwconfig.DynDNS, len(in.DynDNS))
		for j, d := range in.DynDNS {
			if d.TSIG != nil {
				t := *d.TSIG
				t.Secret = "<redacted>"
				d.TSIG = &t
			}
			cp.DynDNS[j] = d
		}
		out.Instances[i] = cp
	}
	out.IPLists = make([]fwconfig.IPList, len(doc.IPLists))
	for i, l := range doc.IPLists {
		if l.Password != "" {
			l.Password = "<redacted>"
		}
		if l.APIKey != "" {
			l.APIKey = "<redacted>"
		}
		out.IPLists[i] = l
	}
	return out
}

// insideAny reports whether prefix cidr lies within one of the prefixes.
func insideAny(cidr string, prefixes []string) bool {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	for _, s := range prefixes {
		if q, err := netip.ParsePrefix(s); err == nil && q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
