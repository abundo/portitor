// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/wgkeys"
	"github.com/abundo/portitor/models"
)

// wgImport is a wg-quick config file to import as a WireGuard interface.
type wgImport struct {
	InstanceID uint   `json:"instance_id"`
	Name       string `json:"name"`
	Config     string `json:"config"`
	// Overwrite replaces the keys, port, addresses and peers of an
	// existing WireGuard interface of that name.
	Overwrite bool `json:"overwrite"`
}

// parseWgQuick reads a wg-quick config: the [Interface] section into ifc,
// each [Peer] into a peer. A comment line right above [Peer] ("# phone",
// "# Name = phone") names the peer. Keys wg-quick runs on the host (DNS,
// PostUp, Table...) are reported as warnings and left out.
func parseWgQuick(text string) (ifc models.Interface, peers []models.WgPeer, warnings []string, err error) {
	section, comment := "", ""
	ignored := map[string]bool{}
	ln := 0
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if c, ok := strings.CutPrefix(line, "#"); ok {
			c = strings.TrimSpace(c)
			if k, v, ok := strings.Cut(c, "="); ok && strings.EqualFold(strings.TrimSpace(k), "name") {
				c = strings.TrimSpace(v)
			}
			comment = c
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			switch section {
			case "interface":
			case "peer":
				name := comment
				if name == "" {
					name = fmt.Sprintf("peer%d", len(peers)+1)
				}
				peers = append(peers, models.WgPeer{Name: name, Enabled: true})
			default:
				return ifc, nil, nil, bad(fmt.Sprintf("line %d: unknown section %s", ln, line))
			}
			comment = ""
			continue
		}
		comment = ""
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return ifc, nil, nil, bad(fmt.Sprintf("line %d: expected key = value", ln))
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		num := func() (int, error) {
			if v == "off" {
				return 0, nil
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return 0, bad(fmt.Sprintf("line %d: %s is not a number", ln, v))
			}
			return n, nil
		}
		switch section {
		case "interface":
			switch k {
			case "privatekey":
				ifc.WgPrivateKey = v
			case "listenport":
				if ifc.WgListenPort, err = num(); err != nil {
					return
				}
			case "address":
				for _, a := range splitList(v) {
					if !strings.Contains(a, "/") {
						if ip, perr := netip.ParseAddr(a); perr == nil {
							a = netip.PrefixFrom(ip, ip.BitLen()).String()
						}
					}
					ifc.Addresses = append(ifc.Addresses, a)
				}
			case "mtu":
				if ifc.Mtu, err = num(); err != nil {
					return
				}
			default:
				ignored["[Interface] "+k] = true
			}
		case "peer":
			p := &peers[len(peers)-1]
			switch k {
			case "publickey":
				p.PublicKey = v
			case "presharedkey":
				p.PresharedKey = v
			case "allowedips":
				p.AllowedIPs = append(p.AllowedIPs, splitList(v)...)
			case "endpoint":
				p.Endpoint = v
			case "persistentkeepalive":
				if p.Keepalive, err = num(); err != nil {
					return
				}
			default:
				ignored["[Peer] "+k] = true
			}
		default:
			return ifc, nil, nil, bad(fmt.Sprintf("line %d: a key outside [Interface] or [Peer]", ln))
		}
	}
	if err = sc.Err(); err != nil {
		return
	}
	if ifc.WgPrivateKey == "" {
		return ifc, nil, nil, bad("the config has no [Interface] PrivateKey")
	}
	if !fwconfig.ValidWGKey(ifc.WgPrivateKey) {
		return ifc, nil, nil, bad("PrivateKey is not a WireGuard key")
	}
	if ifc.WgPublicKey, err = wgkeys.Public(ifc.WgPrivateKey); err != nil {
		return
	}
	for i := range peers {
		if peers[i].PresharedKey != "" && !fwconfig.ValidWGKey(peers[i].PresharedKey) {
			return ifc, nil, nil, bad(fmt.Sprintf("peer %s: PresharedKey is not a WireGuard key", peers[i].Name))
		}
	}
	for k := range ignored {
		warnings = append(warnings, k+" is not imported")
	}
	return ifc, peers, warnings, nil
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
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
	if ok, err := allowInstance(c, req.InstanceID, true); !ok {
		return err
	}
	parsed, peers, warnings, err := parseWgQuick(req.Config)
	if err != nil {
		return dbError(c, err)
	}
	inst, err := s.instanceByID(c.Request().Context(), req.InstanceID)
	if err != nil {
		return err
	}
	if inst == nil {
		return errJSON(c, http.StatusBadRequest, "no such virtual firewall")
	}
	name := strings.TrimSpace(req.Name)
	ifc := map[string]any{
		"wg-private-key": parsed.WgPrivateKey, "wg-public-key": parsed.WgPublicKey,
		"wg-listen-port": parsed.WgListenPort, "addresses": append([]string{}, parsed.Addresses...),
		"ipv4-mode": fwconfig.ModeStatic,
	}
	if parsed.Mtu != 0 {
		ifc["mtu"] = parsed.Mtu
	}
	ps := []map[string]any{}
	for _, p := range peers {
		if p.PublicKey == "" {
			return errJSON(c, http.StatusBadRequest, fmt.Sprintf("peer %s has no PublicKey", p.Name))
		}
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
	if warnings == nil {
		warnings = []string{}
	}
	return c.JSON(http.StatusOK, map[string]any{"interface": map[string]any{"name": name}, "peers": len(peers), "warnings": warnings})
}

func errText(err error) string {
	var br *badRequest
	if errors.As(err, &br) {
		return br.msg
	}
	return err.Error()
}
