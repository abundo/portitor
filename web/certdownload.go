// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
	"github.com/labstack/echo/v5"
)

// handleCertificateDownload hands out a certificate, without its
// private key: ?format=pem (the certificate), chain (PEM, with the
// intermediates) or der (the certificate, binary).
func (s *Server) handleCertificateDownload(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var cert models.Certificate
	if err := s.db.First(&cert, id).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	if ok, err := allowInstance(c, cert.InstanceID, false); !ok {
		return err
	}
	// An imported certificate is the one in the database; an ACME one is
	// the agent's.
	chain := []byte(cert.FullChain)
	if cert.Source != fwconfig.CertSourceImport {
		var inst models.Instance
		if err := s.db.First(&inst, cert.InstanceID).Error; err != nil {
			return err
		}
		a, _, err := s.instanceAgent(inst.Name)
		if err != nil {
			return errJSON(c, http.StatusBadGateway, err.Error())
		}
		ca, ok := a.(certAgent)
		if !ok {
			return errJSON(c, http.StatusBadGateway, "agent client cannot fetch certificates")
		}
		ctx, cancel := context.WithTimeout(c.Request().Context(), 30*time.Second)
		defer cancel()
		f, err := ca.Certificate(ctx, inst.Name, cert.Name)
		if err != nil {
			return errJSON(c, http.StatusBadGateway, err.Error())
		}
		chain = []byte(f.FullChain)
	}
	return sendCertificate(c, cert.Name, chain)
}

// sendCertificate answers with a chain's certificate, as ?format asks.
func sendCertificate(c *echo.Context, name string, chain []byte) error {
	leaf, _ := pem.Decode(chain)
	if leaf == nil || leaf.Type != "CERTIFICATE" {
		return errJSON(c, http.StatusNotFound, "no certificate stored yet")
	}
	var (
		body []byte
		ext  string
		ct   string
	)
	switch c.QueryParam("format") {
	case "", "pem":
		body, ext, ct = pem.EncodeToMemory(leaf), "pem", "application/x-pem-file"
	case "chain":
		body, ext, ct = chain, "fullchain.pem", "application/x-pem-file"
	case "der":
		body, ext, ct = leaf.Bytes, "der", "application/pkix-cert"
	default:
		return errJSON(c, http.StatusBadRequest, "format: pem, chain or der")
	}
	c.Response().Header().Set("Content-Disposition", `attachment; filename="`+name+"."+ext+`"`)
	return c.Blob(http.StatusOK, ct, body)
}

// handleCertificateRenew orders an ACME certificate now, on its virtual
// firewall's firewall and that firewall's HA secondary: the active host
// orders, the standby copies it.
func (s *Server) handleCertificateRenew(c *echo.Context) error {
	var cert models.Certificate
	if !s.loadByID(c, &cert) {
		return nil
	}
	if ok, err := allowInstance(c, cert.InstanceID, true); !ok {
		return err
	}
	if cert.Source == fwconfig.CertSourceImport {
		return errJSON(c, http.StatusConflict, "an imported certificate is never renewed")
	}
	if !cert.Enabled {
		return errJSON(c, http.StatusConflict, "the certificate is off")
	}
	var in models.Instance
	if err := s.db.First(&in, cert.InstanceID).Error; err != nil {
		return err
	}
	var secondaries []models.Firewall
	if err := s.db.Where("ha_primary_id = ?", in.FirewallID).Find(&secondaries).Error; err != nil {
		return err
	}
	for _, fw := range secondaries {
		if a, _, err := s.firewallAgent(fw.ID); err == nil {
			_ = a.RenewCertificate(c.Request().Context(), in.Name, cert.Name)
		}
	}
	return s.startOnAgent(c, in.FirewallID, cert.Name, func(a agentAPI) error {
		return a.RenewCertificate(c.Request().Context(), in.Name, cert.Name)
	})
}
