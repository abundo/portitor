// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// BootstrapOptions is the first configuration of a new firewall, where
// portitor-web runs on the firewall itself (the installer ISO's first-boot
// setup runs `portitor-web bootstrap`).
type BootstrapOptions struct {
	AgentURL         string
	AgentToken       string
	AgentFingerprint string
	// LAN is the interface the GUI is reached on, with Address (and its
	// prefix length) on it.
	LAN     string
	Address netip.Prefix
	// WAN, if set, is the interface to the Internet: static with
	// WANAddress, or DHCP (which brings the default route) without.
	WAN        string
	WANAddress netip.Prefix
	// Gateway, if valid, becomes the default route. It is on the WAN when
	// that is static, else on the LAN; a DHCP WAN takes none.
	Gateway netip.Addr
	// GUIPort is portitor-web's port, opened on the LAN.
	GUIPort int
}

func (o *BootstrapOptions) check() error {
	if !fwconfig.ValidIfname(o.LAN) {
		return fmt.Errorf("invalid interface name %q", o.LAN)
	}
	if !o.Address.IsValid() {
		return errors.New("the LAN address is required (address/prefix length)")
	}
	if err := checkHostPrefix("LAN", o.Address); err != nil {
		return err
	}
	gwNet := o.Address
	if o.WAN != "" {
		if !fwconfig.ValidIfname(o.WAN) {
			return fmt.Errorf("invalid interface name %q", o.WAN)
		}
		if o.WAN == o.LAN {
			return errors.New("the WAN and the LAN must be different interfaces")
		}
		if o.WANAddress.IsValid() {
			if err := checkHostPrefix("WAN", o.WANAddress); err != nil {
				return err
			}
			if o.WANAddress.Overlaps(o.Address) {
				return fmt.Errorf("the WAN %s overlaps the LAN %s", o.WANAddress.Masked(), o.Address.Masked())
			}
			gwNet = o.WANAddress
		} else if o.Gateway.IsValid() {
			return errors.New("the WAN uses DHCP, which brings the default gateway")
		}
	} else if o.WANAddress.IsValid() {
		return errors.New("a WAN address needs the WAN interface")
	}
	if o.Gateway.IsValid() {
		if !gwNet.Contains(o.Gateway) || o.Gateway == gwNet.Addr() {
			return fmt.Errorf("the gateway %s must be another address in %s", o.Gateway, gwNet.Masked())
		}
	}
	if o.GUIPort < 1 || o.GUIPort > 65535 {
		return fmt.Errorf("invalid GUI port %d", o.GUIPort)
	}
	return nil
}

// checkHostPrefix checks an interface address with its prefix length.
func checkHostPrefix(what string, p netip.Prefix) error {
	a := p.Addr()
	if !a.IsGlobalUnicast() {
		return fmt.Errorf("%s: %s is not a unicast address", what, a)
	}
	if a.Is4() && p.Bits() < 31 {
		if a == p.Masked().Addr() {
			return fmt.Errorf("%s: %s is the network address of %s", what, a, p.Masked())
		}
		if a == broadcast(p) {
			return fmt.Errorf("%s: %s is the broadcast address of %s", what, a, p.Masked())
		}
	}
	return nil
}

func broadcast(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	for i := range 4 {
		b[3-i] |= byte(host >> (8 * i))
	}
	return netip.AddrFrom4(b)
}

// Bootstrap configures a new installation and deploys it: the agent
// settings, the LAN interface with its address, the WAN interface (static
// or DHCP), the default route, and rules that let the LAN reach the GUI and
// ping the firewall. Every other
// interface is imported as it is (syncNICs). It refuses once anything has
// been deployed. A failed run can be repeated.
func Bootstrap(ctx context.Context, s *Server, o BootstrapOptions) (*models.Deployment, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	if err := s.ensureDefaultInstance(); err != nil {
		return nil, err
	}
	st, err := s.settings()
	if err != nil {
		return nil, err
	}
	if st.Generation > 0 {
		return nil, errors.New("this installation has been deployed already; configure it in the GUI")
	}
	st.AgentURL = strings.TrimRight(o.AgentURL, "/")
	st.AgentToken = o.AgentToken
	st.AgentFingerprint = strings.ToLower(strings.ReplaceAll(o.AgentFingerprint, ":", ""))
	if err := s.db.Save(st).Error; err != nil {
		return nil, err
	}

	// The agent has usually just started.
	a, _, err := s.agent()
	if err != nil {
		return nil, err
	}
	var status *agentapi.Status
	for i := 0; ; i++ {
		status, err = a.Status(ctx)
		if err == nil {
			break
		}
		if i == 30 {
			return nil, fmt.Errorf("agent: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if _, err := s.syncNICs(status.NICs); err != nil {
		return nil, err
	}

	err = s.db.Transaction(func(tx *gorm.DB) error {
		var in models.Instance
		if err := tx.Where("is_default = ?", true).First(&in).Error; err != nil {
			return err
		}
		return bootstrapNetwork(tx, in.ID, o)
	})
	var br *badRequest
	if errors.As(err, &br) {
		return nil, errors.New(br.msg)
	}
	if err != nil {
		return nil, err
	}
	noConfirm := 0
	dep, _, err := s.deploy(ctx, "bootstrap", &noConfirm)
	if err != nil {
		var ve *fwconfig.ValidationError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("%w: %s", err, strings.Join(ve.Problems, "; "))
		}
		return dep, err
	}
	slog.Info("bootstrap deployed", "lan", o.LAN, "address", o.Address, "wan", o.WAN, "generation", dep.Generation)
	return dep, nil
}

func bootstrapNetwork(tx *gorm.DB, instanceID uint, o BootstrapOptions) error {
	if _, err := bootstrapIface(tx, instanceID, o.LAN, o.Address, "LAN", "firewall (GUI)"); err != nil {
		return err
	}
	if o.WAN != "" {
		if _, err := bootstrapIface(tx, instanceID, o.WAN, o.WANAddress, "WAN", "firewall (WAN)"); err != nil {
			return err
		}
	}

	var n int64
	if o.Gateway.IsValid() {
		dest := "0.0.0.0/0"
		if o.Gateway.Is6() {
			dest = "::/0"
		}
		if err := tx.Model(&models.Route{}).Where("instance_id = ? AND destination = ?", instanceID, dest).Count(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			r := models.Route{InstanceID: instanceID, Destination: dest, Gateway: o.Gateway.String(), Enabled: true, Description: "default route"}
			if err := prepareRoute(tx, &r, nil); err != nil {
				return err
			}
			if err := tx.Create(&r).Error; err != nil {
				return err
			}
		}
	}

	for _, r := range []models.Rule{
		{Protocol: "tcp", DstPorts: strconv.Itoa(o.GUIPort), Description: "portitor-web from the LAN"},
		{Protocol: "icmp", Description: "ping from the LAN"},
	} {
		if err := tx.Model(&models.Rule{}).Where("instance_id = ? AND description = ?", instanceID, r.Description).Count(&n).Error; err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		r.InstanceID, r.Chain, r.Action, r.Enabled = instanceID, fwconfig.ChainInput, fwconfig.ActionAccept, true
		r.InInterfaces, r.OutInterfaces = models.StringList{o.LAN}, models.StringList{}
		r.SrcAddrs, r.DstAddrs = models.StringList{}, models.StringList{}
		if err := prepareRule(tx, &r, nil); err != nil {
			return err
		}
		if err := tx.Create(&r).Error; err != nil {
			return err
		}
	}
	return nil
}

// bootstrapIface enables an interface: static with address (its prefix and
// address go into IPAM), or DHCP when address is not valid.
func bootstrapIface(tx *gorm.DB, instanceID uint, name string, address netip.Prefix, prefixDesc, addrDesc string) (*models.Interface, error) {
	var ifc models.Interface
	if err := tx.Where("instance_id = ? AND name = ?", instanceID, name).First(&ifc).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, bad(fmt.Sprintf("the agent reports no interface %s", name))
		}
		return nil, err
	}
	old := ifc
	ifc.Enabled = true
	switch {
	case !address.IsValid():
		ifc.Ipv4Mode = fwconfig.ModeDHCP
	case address.Addr().Is4():
		ifc.Ipv4Mode = fwconfig.ModeStatic
	}
	if err := prepareInterface(tx, &ifc, &old); err != nil {
		return nil, err
	}
	if err := tx.Save(&ifc).Error; err != nil {
		return nil, err
	}
	if !address.IsValid() {
		return &ifc, nil
	}

	prefix := address.Masked().String()
	var n int64
	if err := tx.Model(&models.IpamPrefix{}).Where("instance_id = ? AND prefix = ?", instanceID, prefix).Count(&n).Error; err != nil {
		return nil, err
	}
	if n == 0 {
		p := models.IpamPrefix{InstanceID: instanceID, Prefix: prefix, Description: prefixDesc, DhcpDnsServers: models.StringList{}}
		if err := prepareIpamPrefix(tx, &p, nil); err != nil {
			return nil, err
		}
		if err := tx.Create(&p).Error; err != nil {
			return nil, err
		}
	}

	addr := address.Addr().String()
	var ia models.IpamAddress
	err := tx.Where("instance_id = ? AND address = ?", instanceID, addr).First(&ia).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		ia = models.IpamAddress{InstanceID: instanceID, Address: addr, InterfaceID: &ifc.ID, Description: addrDesc}
		if err := prepareIpamAddress(tx, &ia, nil); err != nil {
			return nil, err
		}
		if err := tx.Create(&ia).Error; err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	case ia.InterfaceID != nil && *ia.InterfaceID != ifc.ID:
		return nil, bad(fmt.Sprintf("%s is assigned to another interface", addr))
	default:
		if err := tx.Model(&ia).Update("interface_id", ifc.ID).Error; err != nil {
			return nil, err
		}
	}
	return &ifc, nil
}
