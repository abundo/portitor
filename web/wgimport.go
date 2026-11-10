// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/wgimport"
)

// wgImport is a wg-quick config file to import as a WireGuard interface
// (internal/wgimport reads it).
type wgImport struct {
	// Instance is the virtual firewall's name.
	Instance string `json:"instance"`
	Name       string `json:"name"`
	Config     string `json:"config"`
	// Overwrite replaces the keys, port, addresses and peers of an
	// existing WireGuard interface of that name.
	Overwrite bool `json:"overwrite"`
}

// errWgExists answers an import of an existing interface without Overwrite.
var errWgExists = errors.New("exists")

// handleWgImport creates a WireGuard interface and its peers from a
// wg-quick config, or with overwrite replaces those of an existing one
// (its other settings, zones and rules stay).
func (s *Server) handleWgImport(c *echo.Context) error {
	var req wgImport
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid JSON")
	}
	inst, err := s.namedInstance(c, req.Instance, true)
	if inst == nil {
		return err
	}
	parsed, err := wgimport.Parse(req.Config)
	if err != nil {
		return errJSON(c, http.StatusBadRequest, err.Error())
	}
	name := strings.TrimSpace(req.Name)
	ifc := map[string]any{
		"wg-private-key": parsed.PrivateKey, "wg-public-key": parsed.PublicKey,
		"wg-listen-port": parsed.ListenPort, "addresses": append([]string{}, parsed.Addresses...),
		"ipv4-mode": fwconfig.ModeStatic,
	}
	if parsed.MTU != 0 {
		ifc["mtu"] = parsed.MTU
	}
	ps := []map[string]any{}
	for _, p := range parsed.Peers {
		peer := map[string]any{"name": p.Name, "enabled": true, "public-key": p.PublicKey, "allowed-ips": append([]string{}, p.AllowedIPs...)}
		if p.PresharedKey != "" {
			peer["preshared-key"] = p.PresharedKey
		}
		if p.Endpoint != "" {
			peer["endpoint"] = p.Endpoint
		}
		if p.Keepalive != 0 {
			peer["keepalive"] = p.Keepalive
		}
		ps = append(ps, peer)
	}
	at := datastore.Path{{Name: "instance", Keys: []string{inst.Name}}, {Name: "interface", Keys: []string{name}}}
	ws, err := s.userEdit(c, func(work *datastore.Tree) error {
		old, _, err := work.Find(at)
		if err != nil {
			return err
		}
		if old != nil {
			if old.Leaf("kind") != fwconfig.KindWireGuard {
				return bad(fmt.Sprintf("%s exists and is not a WireGuard interface", name))
			}
			if !req.Overwrite {
				return errWgExists
			}
			body, _ := json.Marshal(ifc)
			if err := work.EditJSON(at, datastore.EditMerge, body); err != nil {
				return err
			}
			peersBody, _ := json.Marshal(ps)
			return work.EditJSON(datastore.Path{at[0], at[1], {Name: "wireguard-peer"}}, datastore.EditReplace, peersBody)
		}
		ifc["name"], ifc["kind"], ifc["enabled"], ifc["wireguard-peer"] = name, fwconfig.KindWireGuard, true, ps
		body, _ := json.Marshal(ifc)
		return work.EditJSON(datastore.Path{at[0], {Name: "interface"}}, datastore.EditCreate, body)
	})
	if errors.Is(err, errWgExists) {
		return errJSON(c, http.StatusConflict, fmt.Sprintf("%s exists", req.Name))
	}
	if err != nil {
		return editError(c, err)
	}
	warn(c, ws)
	warnings := parsed.Warnings
	if warnings == nil {
		warnings = []string{}
	}
	return c.JSON(http.StatusOK, map[string]any{"interface": map[string]any{"name": name}, "peers": len(parsed.Peers), "warnings": warnings})
}

func errText(err error) string {
	var br *badRequest
	if errors.As(err, &br) {
		return br.msg
	}
	return err.Error()
}
