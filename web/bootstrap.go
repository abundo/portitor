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
	// Gateway, if valid, becomes the default route.
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
	a := o.Address.Addr()
	if !a.IsGlobalUnicast() {
		return fmt.Errorf("%s is not a unicast address", a)
	}
	if a.Is4() && o.Address.Bits() < 31 {
		net := o.Address.Masked().Addr()
		if a == net {
			return fmt.Errorf("%s is the network address of %s", a, o.Address.Masked())
		}
		if a == broadcast(o.Address) {
			return fmt.Errorf("%s is the broadcast address of %s", a, o.Address.Masked())
		}
	}
	if o.Gateway.IsValid() {
		if !o.Address.Contains(o.Gateway) || o.Gateway == a {
			return fmt.Errorf("the gateway %s must be another address in %s", o.Gateway, o.Address.Masked())
		}
	}
	if o.GUIPort < 1 || o.GUIPort > 65535 {
		return fmt.Errorf("invalid GUI port %d", o.GUIPort)
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
// settings, the LAN interface with its address, the default route, and
// rules that let the LAN reach the GUI and ping the firewall. Every other
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
		return bootstrapLAN(tx, in.ID, o)
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
	slog.Info("bootstrap deployed", "lan", o.LAN, "address", o.Address, "generation", dep.Generation)
	return dep, nil
}

func bootstrapLAN(tx *gorm.DB, instanceID uint, o BootstrapOptions) error {
	var ifc models.Interface
	if err := tx.Where("instance_id = ? AND name = ?", instanceID, o.LAN).First(&ifc).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return bad(fmt.Sprintf("the agent reports no interface %s", o.LAN))
		}
		return err
	}
	old := ifc
	ifc.Enabled = true
	if o.Address.Addr().Is4() {
		ifc.Ipv4Mode = fwconfig.ModeStatic
	}
	if err := prepareInterface(tx, &ifc, &old); err != nil {
		return err
	}
	if err := tx.Save(&ifc).Error; err != nil {
		return err
	}

	prefix := o.Address.Masked().String()
	var n int64
	if err := tx.Model(&models.IpamPrefix{}).Where("instance_id = ? AND prefix = ?", instanceID, prefix).Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		p := models.IpamPrefix{InstanceID: instanceID, Prefix: prefix, Description: "LAN", DhcpDnsServers: models.StringList{}}
		if err := prepareIpamPrefix(tx, &p, nil); err != nil {
			return err
		}
		if err := tx.Create(&p).Error; err != nil {
			return err
		}
	}

	addr := o.Address.Addr().String()
	var ia models.IpamAddress
	err := tx.Where("instance_id = ? AND address = ?", instanceID, addr).First(&ia).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		ia = models.IpamAddress{InstanceID: instanceID, Address: addr, InterfaceID: &ifc.ID, Description: "firewall (GUI)"}
		if err := prepareIpamAddress(tx, &ia, nil); err != nil {
			return err
		}
		if err := tx.Create(&ia).Error; err != nil {
			return err
		}
	case err != nil:
		return err
	case ia.InterfaceID != nil && *ia.InterfaceID != ifc.ID:
		return bad(fmt.Sprintf("%s is assigned to another interface", addr))
	default:
		if err := tx.Model(&ia).Update("interface_id", ifc.ID).Error; err != nil {
			return err
		}
	}

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
