// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/netobj"
	"github.com/abundo/portitor/models"
)

// traceRequest is the browser's: the target is an address, the name of a
// named host or a DNS name (which the agent resolves), and family picks
// the address when there are both.
type traceRequest struct {
	Instance  string `json:"instance"`
	Interface string `json:"interface"`
	Target    string `json:"target"`
	Family    string `json:"family"` // "", "ipv4" or "ipv6"
	Count     int    `json:"count"`
}

// traceDNSName is a DNS name the agent may resolve (it checks again).
var traceDNSName = regexp.MustCompile(`^(?i)[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*\.?$`)

// handleAgentTrace runs a traceroute (mtr) on the agent and passes its
// events (JSON lines) to the browser as they come. The browser closing
// the request stops it.
func (s *Server) handleAgentTrace(c *echo.Context) error {
	var body traceRequest
	if err := c.Bind(&body); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	if !captureName.MatchString(body.Instance) || (body.Interface != "" && !captureName.MatchString(body.Interface)) {
		return errJSON(c, http.StatusBadRequest, "invalid virtual firewall or interface name")
	}
	if !currentAccess(c).isAdmin() {
		var inst models.Instance
		if err := s.db.Where("name = ?", body.Instance).First(&inst).Error; err != nil {
			return errJSON(c, http.StatusNotFound, "no such virtual firewall")
		}
		if ok, err := allowInstance(c, inst.ID, true); !ok {
			return err
		}
	}
	target, msg := s.traceTarget(body.Target, body.Family)
	if msg != "" {
		return errJSON(c, http.StatusBadRequest, msg)
	}
	a, _, err := s.agent()
	if err != nil {
		return agentError(c, err)
	}
	req := agentapi.TraceRequest{Instance: body.Instance, Interface: body.Interface, Target: target, Family: body.Family, Count: body.Count}
	r := c.Request()
	stream, err := a.Trace(r.Context(), req)
	if err != nil {
		return agentError(c, err)
	}
	defer stream.Close()

	user := currentUser(c)
	slog.Info("traceroute started", "user", user.Username, "instance", req.Instance, "interface", req.Interface, "target", body.Target)
	w := c.Response()
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // the server's timeout is for requests
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	buf := make([]byte, 8<<10)
	for {
		n, rerr := stream.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				break
			}
			_ = rc.Flush()
		}
		if rerr != nil {
			break
		}
	}
	return nil
}

// traceTarget resolves the target to one address: a literal, or a named
// host's address of the family asked for (IPv4 first when it has both).
// Any other name goes to the agent as a DNS name.
func (s *Server) traceTarget(target, family string) (string, string) {
	if a, err := netip.ParseAddr(target); err == nil && a.Zone() == "" {
		return a.String(), ""
	}
	if family != "" && family != "ipv4" && family != "ipv6" {
		return "", "family must be ipv4 or ipv6"
	}
	var objs []models.AddressObject
	if netobj.IsName(target) {
		if err := s.db.Where("name = ?", target).Find(&objs).Error; err != nil {
			return "", "cannot look up " + target
		}
	}
	if len(objs) == 0 {
		if !traceDNSName.MatchString(target) || len(target) > 253 {
			return "", "the target must be an IP address, a named host or a DNS name"
		}
		return target, ""
	}
	addrs, err := netobj.New(objs).Host(target)
	if err != nil {
		return "", err.Error()
	}
	var v4, v6 string
	for _, a := range addrs {
		if fwconfig.AddrFamily(a) == "ipv4" {
			v4 = a
		} else {
			v6 = a
		}
	}
	switch {
	case family == "ipv6" && v6 != "":
		return v6, ""
	case family == "ipv6":
		return "", target + " has no IPv6 address"
	case family == "ipv4" && v4 == "":
		return "", target + " has no IPv4 address"
	case v4 != "":
		return v4, ""
	case v6 != "":
		return v6, ""
	}
	return "", target + " has no addresses"
}
