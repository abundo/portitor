// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/http"
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
	m := &models.Interface{OvpnMode: ifc.OvpnMode, OvpnPort: ifc.OvpnPort, OvpnTlsCrypt: ifc.OvpnTlsCrypt, OvpnTwoFactor: ifc.OvpnTwoFactor}
	cfg := openVPNClientConf(inst.Name, ifc.Name, host, ca, m)
	return c.JSON(http.StatusOK, map[string]any{
		"config": cfg, "filename": inst.Name + "-" + ifc.Name + ".ovpn", "warnings": warnings,
	})
}

// openVPNClientConf is the client config of a server (mode, port, key and
// two-factor login in ifc) reached at host. With two-factor login the
// client asks for the code too (static-challenge), and sends it with the
// password (SCRV1, the agent's splitChallenge).
func openVPNClientConf(instance, iface, host string, ca *agentapi.OpenVPNCA, ifc *models.Interface) string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "# OpenVPN client for %s (%s), from Portitor.\n", instance, iface)
	b.WriteString("client\ndev tun\nnobind\npersist-tun\n")
	b.WriteString("auth-user-pass\nauth-nocache\n")
	if ifc.OvpnTwoFactor != fwconfig.OpenVPNTwoFactorOff {
		b.WriteString("static-challenge \"Authenticator code\" 1\n")
	}
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
