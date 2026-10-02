// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

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

type wgImportResult struct {
	Interface models.Interface `json:"interface"`
	Peers     int              `json:"peers"`
	Warnings  []string         `json:"warnings"`
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
	var res wgImportResult
	err = s.db.Transaction(func(tx *gorm.DB) error {
		var old models.Interface
		ifc := models.Interface{InstanceID: req.InstanceID, Name: strings.TrimSpace(req.Name), Kind: fwconfig.KindWireGuard, Enabled: true}
		var oldp *models.Interface
		err := tx.Where("instance_id = ? AND name = ?", req.InstanceID, ifc.Name).First(&old).Error
		switch {
		case err == nil:
			if old.Kind != fwconfig.KindWireGuard {
				return bad(fmt.Sprintf("%s exists and is not a WireGuard interface", ifc.Name))
			}
			if !req.Overwrite {
				return errWgExists
			}
			ifc = old
			oldp = &old
		case !errors.Is(err, gorm.ErrRecordNotFound):
			return err
		}
		ifc.WgPrivateKey, ifc.WgPublicKey = parsed.WgPrivateKey, parsed.WgPublicKey
		ifc.WgListenPort = parsed.WgListenPort
		ifc.Addresses = parsed.Addresses
		if ifc.Addresses == nil {
			ifc.Addresses = models.StringList{}
		}
		if parsed.Mtu != 0 {
			ifc.Mtu = parsed.Mtu
		}
		ifc.Ipv4Mode = fwconfig.ModeStatic
		if err := prepareInterface(tx, &ifc, oldp); err != nil {
			return err
		}
		if err := tx.Save(&ifc).Error; err != nil {
			return err
		}
		if err := tx.Where("interface_id = ?", ifc.ID).Delete(&models.WgPeer{}).Error; err != nil {
			return err
		}
		for i := range peers {
			p := &peers[i]
			p.InterfaceID = ifc.ID
			if p.PublicKey == "" {
				return bad(fmt.Sprintf("peer %s has no PublicKey", p.Name))
			}
			if err := prepareWgPeer(tx, p, nil); err != nil {
				return bad(fmt.Sprintf("peer %s: %s", p.Name, errText(err)))
			}
			if err := tx.Create(p).Error; err != nil {
				return err
			}
		}
		res = wgImportResult{Interface: ifc, Peers: len(peers), Warnings: warnings}
		return nil
	})
	if errors.Is(err, errWgExists) {
		return errJSON(c, http.StatusConflict, fmt.Sprintf("%s exists", req.Name))
	}
	if err != nil {
		return dbError(c, err)
	}
	if res.Warnings == nil {
		res.Warnings = []string{}
	}
	return c.JSON(http.StatusOK, res)
}

func errText(err error) string {
	var br *badRequest
	if errors.As(err, &br) {
		return br.msg
	}
	return err.Error()
}
