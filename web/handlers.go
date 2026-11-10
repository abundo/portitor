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
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/confview"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/ipam"
	"github.com/abundo/portitor/internal/render"
	"github.com/abundo/portitor/models"
)

// ----- IPAM -----

// handleIpamTree is the prefix tree of the instance ?instance=<name>.
func (s *Server) handleIpamTree(c *echo.Context) error {
	in, err := s.namedInstance(c, c.QueryParam("instance"), false)
	if in == nil {
		return err
	}
	id := in.ID
	v, err := s.view(c.Request().Context())
	if err != nil {
		return err
	}
	tree := ipam.Tree(confview.Of(v.IpamPrefixes, id), confview.Of(v.IpamAddresses, id), confview.Of(v.Interfaces, id), zoneAddresses(v, id))
	if tree == nil {
		tree = []*ipam.Node{}
	}
	return c.JSON(http.StatusOK, tree)
}

// zoneAddresses lists the A and AAAA records of an instance's forward
// zones, with their names fully qualified, in zone and record order.
func zoneAddresses(v *confview.View, instanceID uint) []ipam.RecordAddress {
	zones := confview.Where(confview.Of(v.DnsZones, instanceID), func(z *models.DnsZone) bool { return z.Type == fwconfig.ZoneForward })
	slices.SortStableFunc(zones, func(a, b models.DnsZone) int { return strings.Compare(a.Name, b.Name) })
	var out []ipam.RecordAddress
	for _, z := range zones {
		records := confview.Where(v.DnsRecords, func(r *models.DnsRecord) bool { return r.ZoneID == z.ID })
		zone := strings.TrimSuffix(z.Name, ".")
		domain := ""
		for _, r := range records {
			switch r.Type {
			case models.DnsRecordDomain:
				domain = r.Name
			case "A", "AAAA":
				name := builder.RecordName(domain, r.Name)
				if abs, ok := strings.CutSuffix(name, "."); ok {
					name = abs
				} else if name == "@" {
					name = zone
				} else {
					name += "." + zone
				}
				out = append(out, ipam.RecordAddress{Zone: z.Name, Name: name, Address: r.Value, Mac: r.Mac, Description: r.Description})
			}
		}
	}
	return out
}

// handleAutoRules lists the input rules the agent adds for an instance's
// (?instance=<name>) services (DHCP, DNS, WireGuard), rendered from the current database. A
// configuration with problems still lists what it can. For the default
// instance it also asks the agent for its anti-lockout rule, which comes
// from agent.yaml; an unreachable agent just leaves it out.
func (s *Server) handleAutoRules(c *echo.Context) error {
	mi, err := s.namedInstance(c, c.QueryParam("instance"), false)
	if mi == nil {
		return err
	}
	in, err := s.candidateInput(c.Request().Context())
	if err != nil {
		return err
	}
	doc, err := builder.BuildFirewall(in, 0, mi.FirewallID)
	var ve *fwconfig.ValidationError
	if err != nil && !errors.As(err, &ve) {
		return err
	}
	out := []render.AutoRule{}
	if mi.IsDefault {
		if l := s.antiLockout(c.Request().Context(), mi.FirewallID); l != nil {
			out = append(out, l.Rules()...)
		}
	}
	exp := doc.Expand()
	if in := exp.Instance(mi.Name); in != nil {
		out = append(out, render.AutoInputRules(in)...)
	}
	return c.JSON(http.StatusOK, out)
}

// antiLockout returns the firewall's anti-lockout rule, or nil when it is
// disabled or the agent cannot be asked.
func (s *Server) antiLockout(ctx context.Context, firewallID uint) *render.AntiLockout {
	a, _, err := s.firewallAgent(firewallID)
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
	v, err := s.view(c.Request().Context())
	if err != nil {
		return err
	}
	p := confview.ByID(v.IpamPrefixes, id)
	if p == nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	if ok, err := allowInstance(c, p.InstanceID, false); !ok {
		return err
	}
	in := p.InstanceID
	ip, err := ipam.NextFree(*p, confview.Of(v.IpamPrefixes, in), ipam.Used(confview.Of(v.IpamAddresses, in), confview.Of(v.Interfaces, in)))
	if err != nil {
		return errJSON(c, http.StatusConflict, err.Error())
	}
	return c.JSON(http.StatusOK, map[string]string{"address": ip.String()})
}

// ----- rule ordering -----

// ----- WireGuard -----

// handleWgClientConfig renders a wg-quick config for the remote side of a
// peer. ?split=1 routes only the instance's prefixes (IPAM's and its
// interfaces') through the tunnel instead of everything. A site peer (one with networks) always
// gets those prefixes, less the ones behind it, and no DNS.
func (s *Server) handleWgClientConfig(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	v, err := s.view(c.Request().Context())
	if err != nil {
		return err
	}
	peer := confview.ByID(v.WgPeers, id)
	if peer == nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	ifc := confview.ByID(v.Interfaces, peer.InterfaceID)
	if ifc == nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	// The config holds the client's private key: an admin's only.
	if ok, err := allowInstance(c, ifc.InstanceID, true); !ok {
		return err
	}
	st, err := s.settings()
	if err != nil {
		return err
	}

	objs := nameSet(v)
	addrs, err := objs.Prefixes(peer.AllowedIPs)
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
	if ifc.DnsListen && !site {
		for _, a := range ifc.Addresses {
			if p, err := netip.ParsePrefix(a); err == nil {
				cc.DNS = append(cc.DNS, p.Addr().String())
			}
		}
	}
	if site || c.QueryParam("split") == "1" {
		remote, err := objs.Prefixes(peer.Networks)
		if err != nil {
			return errJSON(c, http.StatusBadRequest, err.Error())
		}
		roots := ipam.Tree(confview.Of(v.IpamPrefixes, ifc.InstanceID), nil, confview.Of(v.Interfaces, ifc.InstanceID), nil)
		cc.AllowedIPs = nil
		for _, r := range roots {
			if r.Kind == "prefix" && !insideAny(r.CIDR, remote) {
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
		warnings = append(warnings, "This virtual firewall has no prefixes (under IP addresses or on its interfaces), so the config routes nothing to this side.")
	}
	return c.JSON(http.StatusOK, map[string]any{"config": render.WireGuardClientConf(cc), "warnings": warnings, "site": site})
}

// handleWgNextFree suggests allowed IPs for a new peer: per address family
// of the WireGuard interface, a host address of the prefix of the
// interface's address that is neither in IPAM, on an interface nor in the
// allowed IPs of a peer of the instance. Both families get the same host
// number if one is free in both (10.99.0.2/32 and fd99::2/128).
func (s *Server) handleWgNextFree(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	v, err := s.view(c.Request().Context())
	if err != nil {
		return err
	}
	ifc := confview.ByID(v.Interfaces, id)
	if ifc == nil || ifc.Kind != fwconfig.KindWireGuard {
		return errJSON(c, http.StatusNotFound, "no such WireGuard interface")
	}
	if ok, err := allowInstance(c, ifc.InstanceID, false); !ok {
		return err
	}
	prefixes := confview.Of(v.IpamPrefixes, ifc.InstanceID)
	addrs := confview.Of(v.IpamAddresses, ifc.InstanceID)
	ifaces := confview.Of(v.Interfaces, ifc.InstanceID)

	// Peers' allowed IPs count as used: hosts as addresses, networks
	// behind a peer as prefixes.
	peers := confview.Where(v.WgPeers, func(p *models.WgPeer) bool {
		i := confview.ByID(v.Interfaces, p.InterfaceID)
		return i != nil && i.InstanceID == ifc.InstanceID
	})
	set := nameSet(v)
	used, usedPrefixes := ipam.Used(addrs, ifaces), prefixes
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
	// address in each family decides it. The IPAM prefix of the same CIDR,
	// if there is one, adds its DHCP range as taken.
	var targets []models.IpamPrefix
	var warnings []string
	seen := map[bool]bool{} // by Is4
	for _, a := range ifc.Addresses {
		p, err := netip.ParsePrefix(a)
		if err != nil || seen[p.Addr().Is4()] {
			continue
		}
		pfx := p.Masked()
		if pfx.IsSingleIP() {
			warnings = append(warnings, fmt.Sprintf("%s on %s is a single address; give it a prefix length (e.g. %s) to get a suggestion.", p, ifc.Name, netip.PrefixFrom(p.Addr(), suggestBits(p.Addr()))))
			continue
		}
		seen[p.Addr().Is4()] = true
		t := models.IpamPrefix{Prefix: pfx.String()}
		for _, q := range prefixes {
			if qp, err := netip.ParsePrefix(q.Prefix); err == nil && qp.Masked() == pfx {
				t = q
				break
			}
		}
		if p.Addr().Is4() {
			targets = append([]models.IpamPrefix{t}, targets...)
		} else {
			targets = append(targets, t)
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

// suggestBits is the usual prefix length of a tunnel address: /24 for
// IPv4, /64 for IPv6.
func suggestBits(ip netip.Addr) int {
	if ip.Is4() {
		return 24
	}
	return 64
}

// ----- settings & users -----

type settingsView struct {
	models.Settings
	// WebCertificate is the certificate portitor-config serves (kept by
	// its id, settings.web_certificate_id), or nil for tls_cert.
	WebCertificate *certRef `json:"web_certificate"`
	// WebTLS says portitor-web serves HTTPS itself (tls_cert), so a
	// web certificate takes effect.
	WebTLS bool `json:"web_tls"`
}

// certRef names a certificate: its virtual firewall's name and its own.
type certRef struct {
	Instance string `json:"instance"`
	Name     string `json:"name"`
}

func (s *Server) handleGetSettings(c *echo.Context) error {
	v, err := s.settingsView(c.Request().Context())
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, v)
}

// settingsView is the Settings as the GUI has them.
func (s *Server) settingsView(ctx context.Context) (*settingsView, error) {
	st, err := s.settings()
	if err != nil {
		return nil, err
	}
	v := &settingsView{Settings: *st, WebTLS: s.cfg.TLSCert != ""}
	if st.WebCertificateID != nil {
		cert, err := s.certificateByID(ctx, *st.WebCertificateID)
		if err != nil {
			return nil, err
		}
		if cert != nil {
			in, err := s.instanceByID(ctx, cert.InstanceID)
			if err != nil {
				return nil, err
			}
			if in != nil {
				v.WebCertificate = &certRef{in.Name, cert.Name}
			}
		}
	}
	return v, nil
}

// certificateNamed is the candidate's certificate ref names, nil when
// there is none.
func (s *Server) certificateNamed(ctx context.Context, ref certRef) (*models.Certificate, error) {
	v, err := s.view(ctx)
	if err != nil {
		return nil, err
	}
	for i, c := range v.Certificates {
		if in := v.InstanceByID(c.InstanceID); in != nil && in.Name == ref.Instance && c.Name == ref.Name {
			return &v.Certificates[i], nil
		}
	}
	return nil, nil
}

// handlePutSettings changes the Settings: the configuration's as an edit
// of the tree's settings, checked like any other (checkEdit: the leaves'
// ranges and types, virtual firewalls off with more than a host on a
// firewall), and portitor-config's own certificate.
func (s *Server) handlePutSettings(c *echo.Context) error {
	var req struct {
		ConfirmTimeout   *int    `json:"confirm_timeout"`
		WgEndpointHost   *string `json:"wg_endpoint_host"`
		CaptureRateKbps  *int    `json:"capture_rate_kbps"`
		VirtualFirewalls *bool   `json:"virtual_firewalls"`
		TOTPDefault      *bool   `json:"totp_default"`
		// The IPv4 packets with options dropped to the firewall and
		// through it.
		DropIPOptionsInput   *bool `json:"drop_ip_options_input"`
		DropIPOptionsForward *bool `json:"drop_ip_options_forward"`
		// WebCertificate: absent keeps, null clears.
		WebCertificate optional[certRef] `json:"web_certificate"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	// The certificate is checked first, so a refused one changes nothing.
	var certID *uint
	if ref := req.WebCertificate.value; ref != nil {
		cert, err := s.certificateNamed(c.Request().Context(), *ref)
		if err != nil {
			return err
		}
		if cert == nil {
			return errJSON(c, http.StatusBadRequest, "no such certificate")
		}
		certID = &cert.ID
	}
	leaves := map[string]any{}
	putLeaf(leaves, "confirm-timeout", req.ConfirmTimeout)
	putLeaf(leaves, "wg-endpoint-host", req.WgEndpointHost)
	putLeaf(leaves, "capture-rate-kbps", req.CaptureRateKbps)
	putLeaf(leaves, "virtual-firewalls", req.VirtualFirewalls)
	putLeaf(leaves, "totp-default", req.TOTPDefault)
	putLeaf(leaves, "drop-ip-options-input", req.DropIPOptionsInput)
	putLeaf(leaves, "drop-ip-options-forward", req.DropIPOptionsForward)
	if len(leaves) > 0 {
		body, err := json.Marshal(leaves)
		if err != nil {
			return err
		}
		warnings, err := s.userEdit(c, func(work *datastore.Tree) error {
			return work.EditJSON(datastore.Path{{Name: "settings"}}, datastore.EditMerge, body)
		})
		if err != nil {
			return editError(c, err)
		}
		warn(c, warnings)
	}
	if req.WebCertificate.set {
		old, err := s.settings()
		if err != nil {
			return err
		}
		if err := s.db.Exec("UPDATE settings SET web_certificate_id = ? WHERE id = 1", certID).Error; err != nil {
			return err
		}
		if s.webCert != nil && !equalPtr(old.WebCertificateID, certID) {
			s.webCert.reset()
		}
	}
	v, err := s.settingsView(c.Request().Context())
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, v)
}

// optional is a JSON member that may be absent (set false), null (value
// nil) or a value.
type optional[T any] struct {
	set   bool
	value *T
}

func (o *optional[T]) UnmarshalJSON(data []byte) error {
	o.set = true
	if string(data) == "null" {
		o.value = nil
		return nil
	}
	o.value = new(T)
	return json.Unmarshal(data, o.value)
}

// putLeaf sets leaves[name] to *v when the request gave it.
func putLeaf[T any](leaves map[string]any, name string, v *T) {
	if v != nil {
		leaves[name] = *v
	}
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
		FullName string `json:"full_name"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
		// TOTPRequired: absent takes the default under Settings.
		TOTPRequired *bool `json:"totp_required"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	if req.TOTPRequired == nil {
		st, err := s.settings()
		if err != nil {
			return err
		}
		req.TOTPRequired = &st.TOTPDefault
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		return errJSON(c, http.StatusBadRequest, "username is required")
	}
	req.FullName, req.Email = strings.TrimSpace(req.FullName), strings.TrimSpace(req.Email)
	if msg := checkNameEmail(req.FullName, req.Email); msg != "" {
		return errJSON(c, http.StatusBadRequest, msg)
	}
	if req.Role == "" {
		req.Role = models.RoleViewer
	}
	if !validRole(req.Role) {
		return errJSON(c, http.StatusBadRequest, "role must be admin, viewer or none")
	}
	u := models.User{Username: req.Username, FullName: req.FullName, Email: req.Email, Role: req.Role, TOTPRequired: *req.TOTPRequired}
	if err := setPassword(&u, req.Password); err != nil {
		return errJSON(c, http.StatusBadRequest, err.Error())
	}
	if err := s.db.Create(&u).Error; err != nil {
		return dbError(c, err)
	}
	return c.JSON(http.StatusCreated, u)
}

func validRole(role string) bool {
	return role == models.RoleAdmin || role == models.RoleViewer || role == models.RoleNone
}

// validLevel is a member's level in a role.
func validLevel(level string) bool {
	return level == models.RoleAdmin || level == models.RoleViewer
}

// handleUpdateUser changes a user's full name and email (kept when left
// out), another user's role, which ends their sessions so a demoted admin
// loses an open console too, and whether they must use two-factor login. The caller's own role cannot change, which keeps at
// least one admin.
func (s *Server) handleUpdateUser(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var req struct {
		Role         string  `json:"role"`
		FullName     *string `json:"full_name"`
		Email        *string `json:"email"`
		TOTPRequired *bool   `json:"totp_required"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	if !validRole(req.Role) {
		return errJSON(c, http.StatusBadRequest, "role must be admin, viewer or none")
	}
	if id == currentUser(c).ID && req.Role != currentUser(c).Role {
		return errJSON(c, http.StatusBadRequest, "you cannot change your own role")
	}
	var u models.User
	if err := s.db.First(&u, id).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	changed := false
	if req.FullName != nil || req.Email != nil {
		name, email := u.FullName, u.Email
		if req.FullName != nil {
			name = strings.TrimSpace(*req.FullName)
		}
		if req.Email != nil {
			email = strings.TrimSpace(*req.Email)
		}
		if msg := checkNameEmail(name, email); msg != "" {
			return errJSON(c, http.StatusBadRequest, msg)
		}
		changed = changed || name != u.FullName || email != u.Email
		u.FullName, u.Email = name, email
	}
	if u.Role != req.Role {
		u.Role = req.Role
		u.TokenVersion++
		changed = true
	}
	if req.TOTPRequired != nil && *req.TOTPRequired != u.TOTPRequired {
		u.TOTPRequired = *req.TOTPRequired
		changed = true
	}
	if changed {
		if err := s.db.Save(&u).Error; err != nil {
			return err
		}
	}
	return c.JSON(http.StatusOK, u)
}

// handleSetUserPassword sets another user's password and ends their
// sessions. Your own goes through /me/password, which asks for the current one.
func (s *Server) handleSetUserPassword(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	if id == currentUser(c).ID {
		return errJSON(c, http.StatusBadRequest, "change your own password under Change password")
	}
	var u models.User
	if err := s.db.First(&u, id).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	if err := setPassword(&u, req.Password); err != nil {
		return errJSON(c, http.StatusBadRequest, err.Error())
	}
	// A directory user becomes a local one.
	u.LdapServer = ""
	u.TokenVersion++
	if err := s.db.Save(&u).Error; err != nil {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

func (s *Server) handleDeleteUser(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	if id == currentUser(c).ID {
		return errJSON(c, http.StatusBadRequest, "you cannot delete yourself")
	}
	var u models.User
	if err := s.db.First(&u, id).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
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

// docHash identifies a document's content, whatever its generation.
func docHash(doc fwconfig.Document) string {
	doc.Generation = 0
	b, _ := json.Marshal(doc)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
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
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		deps = filterDeployments(deps, names)
	}
	return c.JSON(http.StatusOK, deps)
}

func (s *Server) handleAgentLeases(c *echo.Context) error {
	l, err := fromActive(c.Request().Context(), s, agentAPI.Leases, func(into, from *agentapi.LeasesResponse) {
		into.Client = append(into.Client, from.Client...)
		for k, v := range from.Server {
			if into.Server == nil {
				into.Server = map[string][]agentapi.ServerLease{}
			}
			into.Server[k] = append(into.Server[k], v...)
		}
	})
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		filterLeases(l, names)
	}
	return c.JSON(http.StatusOK, l)
}

// handleAgentNeighbours passes on the ARP, ND and LLDP neighbours of the
// instances' interfaces, for the Neighbours page: of an HA pair, the
// active host's (fromActive).
func (s *Server) handleAgentNeighbours(c *echo.Context) error {
	n, err := fromActive(c.Request().Context(), s, agentAPI.Neighbours, func(into, from *agentapi.NeighboursResponse) {
		into.IP, into.LLDP, into.LLDPPorts = append(into.IP, from.IP...), append(into.LLDP, from.LLDP...), append(into.LLDPPorts, from.LLDPPorts...)
	})
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		filterNeighbours(n, names)
	}
	return c.JSON(http.StatusOK, n)
}

// handleAgentRoutingTable passes on the instances' IPv4 and IPv6 routes,
// for the Routes page.
func (s *Server) handleAgentRoutingTable(c *echo.Context) error {
	t, err := fromAll(c.Request().Context(), s, agentAPI.RoutingTable, func(into, from *agentapi.RoutingTableResponse) { into.Routes = append(into.Routes, from.Routes...) })
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		filterRoutes(t, names)
	}
	return c.JSON(http.StatusOK, t)
}

// handleAgentBGP passes on the BGP state (neighbours, BGP table) of the
// instances, for the BGP page.
func (s *Server) handleAgentBGP(c *echo.Context) error {
	b, err := fromAll(c.Request().Context(), s, agentAPI.BGP, func(into, from *agentapi.BGPResponse) { into.Instances = append(into.Instances, from.Instances...) })
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		filterBGP(b, names)
	}
	return c.JSON(http.StatusOK, b)
}

// handleAgentBGPRoutes passes on the prefixes received, filtered and
// advertised of one BGP neighbour (?instance=&vrf=&neighbor=; no vrf: the
// main table's), for the BGP page.
func (s *Server) handleAgentBGPRoutes(c *echo.Context) error {
	inst, nbr := c.QueryParam("instance"), c.QueryParam("neighbor")
	if inst == "" || nbr == "" {
		return errJSON(c, http.StatusBadRequest, "instance and neighbor are required")
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil && !names[inst] {
		return errJSON(c, http.StatusForbidden, "forbidden")
	}
	a, _, err := s.instanceAgent(inst)
	if err != nil {
		return agentError(c, err)
	}
	r, err := a.BGPNeighborRoutes(c.Request().Context(), inst, c.QueryParam("vrf"), nbr)
	if err != nil {
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, r)
}

// handleAgentBGPNeighbor passes on FRR's view of one BGP neighbour
// (?instance=&vrf=&neighbor=), for the BGP page.
func (s *Server) handleAgentBGPNeighbor(c *echo.Context) error {
	inst, nbr := c.QueryParam("instance"), c.QueryParam("neighbor")
	if inst == "" || nbr == "" {
		return errJSON(c, http.StatusBadRequest, "instance and neighbor are required")
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil && !names[inst] {
		return errJSON(c, http.StatusForbidden, "forbidden")
	}
	a, _, err := s.instanceAgent(inst)
	if err != nil {
		return agentError(c, err)
	}
	r, err := a.BGPNeighborDetail(c.Request().Context(), inst, c.QueryParam("vrf"), nbr)
	if err != nil {
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, r)
}

// handleAgentOSPF passes on the OSPF state (areas, interfaces,
// neighbours, routes) of the instances, for the OSPF page.
func (s *Server) handleAgentOSPF(c *echo.Context) error {
	o, err := fromAll(c.Request().Context(), s, agentAPI.OSPF, func(into, from *agentapi.OSPFResponse) { into.Instances = append(into.Instances, from.Instances...) })
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		filterOSPF(o, names)
	}
	return c.JSON(http.StatusOK, o)
}

// handleAgentISIS passes on the IS-IS state (adjacencies, interfaces,
// routes) of the instances, for the IS-IS page.
func (s *Server) handleAgentISIS(c *echo.Context) error {
	o, err := fromAll(c.Request().Context(), s, agentAPI.ISIS, func(into, from *agentapi.ISISResponse) { into.Instances = append(into.Instances, from.Instances...) })
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		filterISIS(o, names)
	}
	return c.JSON(http.StatusOK, o)
}

// handleAgentVRRP passes on the state of the instances' virtual routers,
// for the VRRP page.
func (s *Server) handleAgentVRRP(c *echo.Context) error {
	v, err := fromAll(c.Request().Context(), s, agentAPI.VRRP, func(into, from *agentapi.VRRPResponse) { into.Instances = append(into.Instances, from.Instances...) })
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		filterVRRP(v, names)
	}
	return c.JSON(http.StatusOK, v)
}

// handleAgentBFD passes on the instances' BFD sessions, for the BFD page.
func (s *Server) handleAgentBFD(c *echo.Context) error {
	b, err := fromAll(c.Request().Context(), s, agentAPI.BFD, func(into, from *agentapi.BFDResponse) { into.Instances = append(into.Instances, from.Instances...) })
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		filterBFD(b, names)
	}
	return c.JSON(http.StatusOK, b)
}

// handleAgentNTP passes on the instances' NTP sources and statistics, for
// the NTP page.
func (s *Server) handleAgentNTP(c *echo.Context) error {
	n, err := fromAll(c.Request().Context(), s, agentAPI.NTP, func(into, from *agentapi.NTPResponse) { into.Instances = append(into.Instances, from.Instances...) })
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		filterNTP(n, names)
	}
	return c.JSON(http.StatusOK, n)
}

// handleAgentNAT64 passes on the instances' NAT64 sessions and counters,
// for the NAT64 page.
func (s *Server) handleAgentNAT64(c *echo.Context) error {
	n, err := fromAll(c.Request().Context(), s, agentAPI.NAT64, func(into, from *agentapi.NAT64Response) { into.Instances = append(into.Instances, from.Instances...) })
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		filterNAT64(n, names)
	}
	return c.JSON(http.StatusOK, n)
}

// handleAgentRuleCounters passes on the traffic per rule (by rule id), for
// the Rules page.
func (s *Server) handleAgentRuleCounters(c *echo.Context) error {
	rc, err := fromAll(c.Request().Context(), s, agentAPI.RuleCounters, func(into, from *agentapi.RuleCountersResponse) {
		for k, v := range from.Rules {
			into.Rules[k] = v
		}
		for k, v := range from.Drops {
			if into.Drops == nil {
				into.Drops = map[string]map[string]agentapi.ChainDrops{}
			}
			into.Drops[k] = v
		}
	})
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		if err := s.filterRuleCounters(rc, currentAccess(c).readable(), names); err != nil {
			return err
		}
	}
	return c.JSON(http.StatusOK, rc)
}

// handleAgentRateLimits passes on the traffic per rate limit (by instance
// and name), for the Rate limits page; an HA pair's two hosts add up.
func (s *Server) handleAgentRateLimits(c *echo.Context) error {
	rl, err := fromAll(c.Request().Context(), s, agentAPI.RateLimits, func(into, from *agentapi.RateLimitsResponse) {
		if into.Instances == nil {
			into.Instances = map[string]map[string]agentapi.RateLimitStats{}
		}
		for in, limits := range from.Instances {
			if into.Instances[in] == nil {
				into.Instances[in] = map[string]agentapi.RateLimitStats{}
			}
			for name, v := range limits {
				st := into.Instances[in][name]
				st.Add(v)
				into.Instances[in][name] = st
			}
		}
	})
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		maps.DeleteFunc(rl.Instances, func(k string, _ map[string]agentapi.RateLimitStats) bool { return !names[k] })
	}
	return c.JSON(http.StatusOK, rl)
}

// handleAgentLogs passes on the agent's log records after ?after=<id>,
// for the log panel.
func (s *Server) handleAgentLogs(c *echo.Context) error {
	after, _ := strconv.ParseInt(c.QueryParam("after"), 10, 64)
	a, err := s.firewallFromRequest(c)
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
	a, err := s.firewallFromRequest(c)
	if err != nil {
		return agentError(c, err)
	}
	l, err := a.PacketLog(c.Request().Context(), after)
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		filterPacketLog(l, names)
	}
	return c.JSON(http.StatusOK, l)
}

// handleAgentDNSQueryLog passes on the DNS queries logged after
// ?after=<id>, for the log panel's DNS queries.
func (s *Server) handleAgentDNSQueryLog(c *echo.Context) error {
	after, _ := strconv.ParseInt(c.QueryParam("after"), 10, 64)
	a, err := s.firewallFromRequest(c)
	if err != nil {
		return agentError(c, err)
	}
	l, err := a.DNSQueryLog(c.Request().Context(), after)
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		filterDNSQueryLog(l, names)
	}
	return c.JSON(http.StatusOK, l)
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

func equalPtr[T comparable](a, b *T) bool {
	return a == b || a != nil && b != nil && *a == *b
}
