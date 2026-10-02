// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/abundo/portitor/models"
	"github.com/labstack/echo/v5"
)

// handleCertificateDownload hands out an ACME certificate, without its
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
	var inst models.Instance
	if err := s.db.First(&inst, cert.InstanceID).Error; err != nil {
		return err
	}
	a, _, err := s.agent()
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
	chain := []byte(f.FullChain)
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
	c.Response().Header().Set("Content-Disposition", `attachment; filename="`+cert.Name+"."+ext+`"`)
	return c.Blob(http.StatusOK, ct, body)
}
