// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// OpenVPN, per instance: an interface of kind openvpn holds the server
// (ovpn_* fields, prepareOpenVPN). Its users are the directory's
// (directory.go). The tls-crypt key is generated here and never shown,
// but in the client config.

func prepareOpenVPN(tx *gorm.DB, i, old *models.Interface) error {
	if i.Ipv4Mode == fwconfig.ModeDHCP {
		return bad("OpenVPN interfaces have static addresses")
	}
	// Both hosts of an HA pair have the same (builder.peerValues).
	i.PeerAddresses = models.StringList{}
	if i.OvpnTlsCrypt == "" {
		key, err := fwconfig.GenerateOpenVPNKey()
		if err != nil {
			return err
		}
		i.OvpnTlsCrypt = key
	}
	if i.OvpnMode == "" {
		i.OvpnMode = fwconfig.OpenVPNAdaptive
	}
	if err := oneOf("mode", i.OvpnMode, fwconfig.OpenVPNModes...); err != nil {
		return err
	}
	if i.OvpnPort == 0 {
		i.OvpnPort = fwconfig.OpenVPNPort
	}
	if i.OvpnPort < 1 || i.OvpnPort > 65535 {
		return bad("port must be 1-65535")
	}
	var others int64
	if err := tx.Model(&models.Interface{}).Where("instance_id = ? AND kind = ? AND id <> ?", i.InstanceID, fwconfig.KindOpenVPN, i.ID).Count(&others).Error; err != nil {
		return err
	}
	if others > 0 {
		return bad("a virtual firewall has one OpenVPN interface")
	}
	tcpAddrs, err := ifaceAddrs("TCP tunnel addresses", i.OvpnTcpAddresses, false)
	if err != nil {
		return err
	}
	i.OvpnTcpAddresses = tcpAddrs
	if i.OvpnMode != fwconfig.OpenVPNAdaptive {
		tcpAddrs = nil // kept for the adaptive mode, unused
	}
	if errs := fwconfig.CheckOpenVPNAddresses(i.OvpnMode, i.Addresses, tcpAddrs); len(errs) > 0 {
		return bad("addresses: " + strings.Join(errs, "; "))
	}
	tcp := *i
	tcp.Addresses = tcpAddrs
	if err := checkAddrsFree(tx, &tcp); err != nil {
		return err
	}
	i.OvpnListen = strings.TrimSpace(i.OvpnListen)
	if i.OvpnListen != "" {
		if i.OvpnListen == i.Name {
			return bad("listen interface: clients come in on another interface")
		}
		if ok, err := ifaceNamed(tx, i.InstanceID, i.OvpnListen); err != nil || !ok {
			if err != nil {
				return err
			}
			return bad(fmt.Sprintf("listen interface: %s is not an interface of this virtual firewall", i.OvpnListen))
		}
	}
	if id := i.OvpnCertificateID; id != nil {
		var c models.Certificate
		if err := tx.First(&c, *id).Error; err != nil || c.InstanceID != i.InstanceID {
			return bad("certificate: pick one of this virtual firewall")
		}
		if err := refuseCA(&c, "certificate"); err != nil {
			return err
		}
	}
	if id := i.OvpnRoleID; id != nil {
		if err := tx.First(&models.Role{}, *id).Error; err != nil {
			return bad("role: no such role")
		}
	}
	// A role set once is required until it is taken away here: a deleted
	// role lets no one in.
	i.OvpnRequireRole = i.OvpnRoleID != nil
	i.OvpnRoutes = cleanList(i.OvpnRoutes)
	for _, r := range i.OvpnRoutes {
		if p, err := netip.ParsePrefix(r); err != nil || p.Masked() != p {
			return bad(fmt.Sprintf("routes: %s is not a network (e.g. 192.168.1.0/24)", r))
		}
	}
	i.OvpnDns = cleanList(i.OvpnDns)
	for _, d := range i.OvpnDns {
		if _, err := netip.ParseAddr(d); err != nil {
			return bad(fmt.Sprintf("DNS servers: %s is not an address", d))
		}
	}
	i.OvpnDnsDomain = strings.TrimSuffix(strings.TrimSpace(i.OvpnDnsDomain), ".")
	if i.OvpnDnsDomain != "" && !fwconfig.ValidDomain(i.OvpnDnsDomain) {
		return bad("DNS domain: not a domain name")
	}
	i.OvpnHost = strings.TrimSpace(i.OvpnHost)
	if i.OvpnHost != "" && !fwconfig.ValidDomain(i.OvpnHost) {
		if _, err := netip.ParseAddr(i.OvpnHost); err != nil {
			return bad("public host: a name or an address")
		}
	}
	return nil
}

// ifaceNamed says whether the instance has an interface or link end
// called name.
func ifaceNamed(tx *gorm.DB, instanceID uint, name string) (bool, error) {
	var n int64
	if err := tx.Model(&models.Interface{}).Where("instance_id = ? AND name = ?", instanceID, name).Count(&n).Error; err != nil {
		return false, err
	}
	if n > 0 {
		return true, nil
	}
	err := tx.Model(&models.Link{}).Where("(instance_a_id = ? AND interface_a = ?) OR (instance_b_id = ? AND interface_b = ?)", instanceID, name, instanceID, name).Count(&n).Error
	return n > 0, err
}

// tenantOpenVPN keeps an instance admin's OpenVPN to the users of their
// virtual firewall: its role's members only, not every user of the
// firewall.
func (s *Server) tenantOpenVPN(i *models.Interface) error {
	if i.Kind != fwconfig.KindOpenVPN {
		return nil
	}
	var r models.Role
	if err := s.db.Where("instance_id = ?", i.InstanceID).First(&r).Error; err != nil {
		return bad("OpenVPN: only a global admin sets up OpenVPN here")
	}
	i.OvpnRoleID = &r.ID
	return nil
}

// refuseOpenVPNCertificate refuses deleting a certificate an OpenVPN
// server uses.
func refuseOpenVPNCertificate(tx *gorm.DB, c *models.Certificate) error {
	return usedBy(tx, "certificate "+c.Name, &models.Interface{}, "ovpn_certificate_id", c.ID, func() []string {
		var names []string
		tx.Model(&models.Interface{}).Where("ovpn_certificate_id = ?", c.ID).Order("name").Pluck("name", &names)
		for j := range names {
			names[j] = "OpenVPN " + names[j]
		}
		return names
	})
}

// refuseOpenVPNRole refuses deleting a role an OpenVPN server requires.
func refuseOpenVPNRole(tx *gorm.DB, r *models.Role) error {
	return usedBy(tx, "role "+r.Name, &models.Interface{}, "ovpn_role_id", r.ID, func() []string {
		var names []string
		tx.Model(&models.Interface{}).Where("ovpn_role_id = ?", r.ID).Order("name").Pluck("name", &names)
		for j := range names {
			names[j] = "OpenVPN " + names[j]
		}
		return names
	})
}

// handleAgentOpenVPN passes on the OpenVPN servers and their clients, for
// the OpenVPN page.
func (s *Server) handleAgentOpenVPN(c *echo.Context) error {
	o, err := fromAll(c.Request().Context(), s, agentAPI.OpenVPN, func(into, from *agentapi.OpenVPNResponse) { into.Servers = append(into.Servers, from.Servers...) })
	if err != nil {
		return agentError(c, err)
	}
	names, err := s.readableInstanceNames(c)
	if err != nil {
		return err
	}
	if names != nil {
		o.Servers = slices.DeleteFunc(o.Servers, func(x agentapi.OpenVPNServer) bool { return !names[x.Instance] })
	}
	return c.JSON(http.StatusOK, o)
}

// handleOpenVPNClientConfig makes an OpenVPN client config for the
// interface's server: UDP first then TCP (adaptive), the CA that signed
// the server's certificate (from the agent) and the name to check, and
// the tls-crypt key. It holds no user's password: the client asks.
func (s *Server) handleOpenVPNClientConfig(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var ifc models.Interface
	if err := s.db.First(&ifc, id).Error; err != nil || ifc.Kind != fwconfig.KindOpenVPN {
		return errJSON(c, http.StatusNotFound, "no such OpenVPN interface")
	}
	// The tls-crypt key: an admin's only.
	if ok, err := allowInstance(c, ifc.InstanceID, true); !ok {
		return err
	}
	var inst models.Instance
	if err := s.db.First(&inst, ifc.InstanceID).Error; err != nil {
		return err
	}
	ag, _, err := s.instanceAgent(inst.Name)
	if err != nil {
		return agentError(c, err)
	}
	ca, err := ag.OpenVPNCA(c.Request().Context(), inst.Name)
	if err != nil {
		return errJSON(c, http.StatusBadRequest, "the server's certificate: "+err.Error()+" (commit first, and wait for the certificate)")
	}
	if ca.CommonName == "" {
		return errJSON(c, http.StatusBadRequest, "the server's certificate has no common name, which clients check it by")
	}
	host := ifc.OvpnHost
	if host == "" {
		host = ca.CommonName
	}
	var warnings []string
	if ifc.OvpnRequireRole && ifc.OvpnRoleID == nil {
		warnings = append(warnings, "No one can log in: its required role is gone; choose another.")
	}
	if !ifc.Enabled {
		warnings = append(warnings, "The interface is disabled.")
	}
	m := &models.Interface{OvpnMode: ifc.OvpnMode, OvpnPort: ifc.OvpnPort, OvpnTlsCrypt: ifc.OvpnTlsCrypt}
	cfg := openVPNClientConf(inst.Name, ifc.Name, host, ca, m)
	return c.JSON(http.StatusOK, map[string]any{
		"config": cfg, "filename": inst.Name + "-" + ifc.Name + ".ovpn", "warnings": warnings,
	})
}

// openVPNClientConf is the client config of a server (mode, port, key in
// ifc) reached at host.
func openVPNClientConf(instance, iface, host string, ca *agentapi.OpenVPNCA, ifc *models.Interface) string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "# OpenVPN client for %s (%s), from Portitor.\n", instance, iface)
	b.WriteString("client\ndev tun\nnobind\npersist-tun\n")
	b.WriteString("auth-user-pass\nauth-nocache\n")
	b.WriteString("remote-cert-tls server\n")
	fmt.Fprintf(b, "verify-x509-name %s name\n", ca.CommonName)
	b.WriteString("data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n")
	// Soon on to TCP when UDP gets no answer.
	b.WriteString("server-poll-timeout 10\nverb 3\n")
	protos := (&fwconfig.OpenVPN{Mode: ifc.OvpnMode}).Protocols()
	for _, p := range protos {
		b.WriteString("\n<connection>\n")
		if p == fwconfig.OpenVPNTCP {
			fmt.Fprintf(b, "remote %s %d tcp-client\n", host, ifc.OvpnPort)
		} else {
			fmt.Fprintf(b, "remote %s %d udp\nexplicit-exit-notify\n", host, ifc.OvpnPort)
		}
		b.WriteString("</connection>\n")
	}
	fmt.Fprintf(b, "\n<ca>\n%s</ca>\n", ca.CA)
	fmt.Fprintf(b, "<tls-crypt>\n%s</tls-crypt>\n", ifc.OvpnTlsCrypt)
	return b.String()
}
