// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
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
	// prefix length) on it, or DHCP without. A DHCP LAN takes no default
	// route when there is a WAN.
	LAN     string
	Address netip.Prefix
	// WAN, if set, is the interface to the Internet: static with
	// WANAddress, or DHCP (which brings the default route) without.
	WAN        string
	WANAddress netip.Prefix
	// Gateway, if valid, becomes the default route. It is on the WAN when
	// that is static, else on the static LAN; DHCP there takes none.
	Gateway netip.Addr
	// GUIPort is portitor-web's port, opened on the LAN; 0 opens none
	// (portitor-web runs on another host).
	GUIPort int
	// DHCPStart and DHCPEnd, if valid, are a DHCP range on the static LAN:
	// the LAN prefix serves DHCP, with the LAN address as gateway (and DNS
	// server, when DNS listens there, unless DHCPDNS). Without them DHCP
	// stays as it is.
	DHCPStart, DHCPEnd netip.Addr
	// DHCPDNS, if set, are the DNS servers DHCP hands out.
	DHCPDNS []netip.Addr
	// Reconfigure runs after a deploy too (portitor-setup run again): the
	// LAN and WAN get exactly these settings, the IPv4 default route is the
	// gateway or none, and the GUI and ping rules move to the LAN.
	Reconfigure bool
}

func (o *BootstrapOptions) check() error {
	if o.AgentFingerprint == "" && !o.Reconfigure {
		return errors.New("the agent fingerprint is required")
	}
	if !fwconfig.ValidIfname(o.LAN) {
		return fmt.Errorf("invalid interface name %q", o.LAN)
	}
	if o.Address.IsValid() {
		if err := checkHostPrefix("LAN", o.Address); err != nil {
			return err
		}
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
			if o.Address.IsValid() && o.WANAddress.Overlaps(o.Address) {
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
		if !gwNet.IsValid() {
			return errors.New("the LAN uses DHCP, which brings the default gateway")
		}
		if !gwNet.Contains(o.Gateway) || o.Gateway == gwNet.Addr() {
			return fmt.Errorf("the gateway %s must be another address in %s", o.Gateway, gwNet.Masked())
		}
	}
	if o.DHCPStart.IsValid() != o.DHCPEnd.IsValid() {
		return errors.New("the DHCP range needs both start and end")
	}
	if o.DHCPStart.IsValid() {
		if !o.Address.IsValid() || !o.Address.Addr().Is4() {
			return errors.New("a DHCP server needs a static IPv4 LAN address")
		}
		lan := o.Address.Masked()
		for _, a := range []netip.Addr{o.DHCPStart, o.DHCPEnd} {
			if !lan.Contains(a) || a == lan.Addr() || (lan.Bits() < 31 && a == broadcast(lan)) {
				return fmt.Errorf("the DHCP range: %s is not a host address in %s", a, lan)
			}
		}
		if o.DHCPStart.Compare(o.DHCPEnd) > 0 {
			return errors.New("the DHCP range starts after its end")
		}
		if l := o.Address.Addr(); l.Compare(o.DHCPStart) >= 0 && l.Compare(o.DHCPEnd) <= 0 {
			return fmt.Errorf("the DHCP range holds the LAN address %s", l)
		}
	} else if len(o.DHCPDNS) > 0 {
		return errors.New("DHCP DNS servers need a DHCP range")
	}
	for _, a := range o.DHCPDNS {
		if !a.Is4() {
			return fmt.Errorf("DHCP DNS server %s is not an IPv4 address", a)
		}
	}
	if o.GUIPort < 0 || o.GUIPort > 65535 {
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
// or DHCP), the default route, rules that let the LAN reach the GUI and SSH (the portitor-mgmt service)
// and ping the firewall and forward from the LAN to the WAN, and a
// masquerade on the WAN (the instance's "allow all output" rule lets the
// firewall's own traffic out). Every other
// interface is imported as it is (syncNICs). It refuses once anything has
// been deployed, unless o.Reconfigure. Without an agent fingerprint the
// stored agent settings are kept. A failed run can be repeated.
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
	if st.Generation > 0 && !o.Reconfigure {
		return nil, errors.New("this installation has been deployed already; configure it in the GUI, or run portitor-setup")
	}
	if o.AgentFingerprint != "" {
		st.AgentURL = strings.TrimRight(o.AgentURL, "/")
		st.AgentToken = o.AgentToken
		st.AgentFingerprint = strings.ToLower(strings.ReplaceAll(o.AgentFingerprint, ":", ""))
		if err := s.db.Save(st).Error; err != nil {
			return nil, err
		}
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
		if err := bootstrapNetwork(tx, in.ID, o); err != nil {
			return err
		}
		return bootstrapDNS(tx, in.ID, o)
	})
	var br *badRequest
	if errors.As(err, &br) {
		return nil, errors.New(br.msg)
	}
	if err != nil {
		return nil, err
	}
	noConfirm := 0
	dep, _, err := s.deploy(ctx, "bootstrap", &noConfirm, nil)
	if err != nil {
		var ve *fwconfig.ValidationError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("%w: %s", err, strings.Join(ve.Problems, "; "))
		}
		return dep, err
	}
	slog.Info("bootstrap deployed", "lan", o.LAN, "address", o.Address, "wan", o.WAN, "reconfigure", o.Reconfigure, "generation", dep.Generation)
	return dep, nil
}

func bootstrapNetwork(tx *gorm.DB, instanceID uint, o BootstrapOptions) error {
	if _, err := bootstrapIface(tx, instanceID, o.LAN, o.Address, "LAN", o.WAN != "", o.Reconfigure); err != nil {
		return err
	}
	if err := bootstrapDHCP(tx, instanceID, o); err != nil {
		return err
	}
	if o.WAN != "" {
		if _, err := bootstrapIface(tx, instanceID, o.WAN, o.WANAddress, "WAN", false, o.Reconfigure); err != nil {
			return err
		}
	}

	var n int64
	if o.Reconfigure {
		if err := reconfigureDefaultRoute(tx, instanceID, o.Gateway); err != nil {
			return err
		}
	} else if o.Gateway.IsValid() {
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

	lan, wan := models.StringList{o.LAN}, models.StringList{o.WAN}
	mgmt, err := bootstrapMgmtService(tx, o)
	if err != nil {
		return err
	}
	rules := []models.Rule{
		{Chain: fwconfig.ChainInput, InInterfaces: lan, Services: models.StringList{mgmt}, Description: "management from the LAN"},
		{Chain: fwconfig.ChainInput, InInterfaces: lan, Services: models.StringList{"all-icmp"}, Description: "ping from the LAN"},
	}
	if o.WAN != "" {
		rules = append(rules, models.Rule{Chain: fwconfig.ChainForward, InInterfaces: lan, OutInterfaces: wan, Description: "LAN to WAN"})
	}
	for _, r := range rules {
		// The input rules are the LAN's way in: reconfigure enables them,
		// and creates them if missing. The forward rule is created by the
		// first bootstrap only; reconfigure moves it to the new LAN and WAN.
		keep := r.Chain == fwconfig.ChainInput
		if r.OutInterfaces == nil {
			r.OutInterfaces = models.StringList{}
		}
		same := func() *gorm.DB {
			return tx.Model(&models.Rule{}).Where("instance_id = ? AND chain = ? AND description = ?", instanceID, r.Chain, r.Description)
		}
		if err := same().Count(&n).Error; err != nil {
			return err
		}
		if n > 0 {
			if !o.Reconfigure {
				continue
			}
			// The rules follow the (new) LAN and WAN.
			updates := map[string]any{"in_interfaces": r.InInterfaces, "out_interfaces": r.OutInterfaces}
			if keep {
				updates["enabled"] = true
			}
			if err := same().Updates(updates).Error; err != nil {
				return err
			}
			continue
		}
		if o.Reconfigure && !keep {
			continue
		}
		r.InstanceID, r.Action, r.Enabled = instanceID, fwconfig.ActionAccept, true
		r.SrcAddrs, r.DstAddrs = models.StringList{}, models.StringList{}
		if err := prepareRule(tx, &r, nil); err != nil {
			return err
		}
		if err := tx.Create(&r).Error; err != nil {
			return err
		}
	}

	if o.WAN == "" {
		return nil
	}
	// The LAN reaches the Internet through the WAN's address.
	const natDesc = "masquerade to the WAN"
	masq := func() *gorm.DB {
		return tx.Model(&models.NatRule{}).Where("instance_id = ? AND kind = ? AND description = ?", instanceID, fwconfig.NATMasquerade, natDesc)
	}
	if err := masq().Count(&n).Error; err != nil {
		return err
	}
	switch {
	case n > 0 && o.Reconfigure:
		return masq().Update("out_interfaces", wan).Error
	case n > 0 || o.Reconfigure:
		return nil
	}
	nat := models.NatRule{InstanceID: instanceID, Kind: fwconfig.NATMasquerade, InInterfaces: models.StringList{}, OutInterfaces: wan,
		SrcAddrs: models.StringList{}, DstAddrs: models.StringList{}, Enabled: true, Description: natDesc}
	if err := prepareNat(tx, &nat, nil); err != nil {
		return err
	}
	return tx.Create(&nat).Error
}

// bootstrapDHCP serves the DHCP range on the LAN prefix (bootstrapIface
// created it, or the user did), with the default gateway, and turns the
// instance's DHCP server on.
func bootstrapDHCP(tx *gorm.DB, instanceID uint, o BootstrapOptions) error {
	if !o.DHCPStart.IsValid() {
		return nil
	}
	if err := tx.Model(&models.Instance{}).Where("id = ?", instanceID).Update("dhcp_enabled", true).Error; err != nil {
		return err
	}
	var p models.IpamPrefix
	if err := tx.Where("instance_id = ? AND prefix = ?", instanceID, o.Address.Masked().String()).First(&p).Error; err != nil {
		return err
	}
	old := p
	p.DhcpEnabled, p.DhcpRangeStart, p.DhcpRangeEnd = true, o.DHCPStart.String(), o.DHCPEnd.String()
	if len(o.DHCPDNS) > 0 {
		p.DhcpDnsServers = models.StringList{}
		for _, a := range o.DHCPDNS {
			p.DhcpDnsServers = append(p.DhcpDnsServers, a.String())
		}
	}
	if err := prepareIpamPrefix(tx, &p, &old); err != nil {
		return err
	}
	return tx.Save(&p).Error
}

// bootstrapDNS creates a starting point for DNS where there is none: the
// SOA template soa-1, the DNS template dns-1 with the firewall as
// ns1.home.arpa (at the LAN address, if static), and the zone home.arpa.
func bootstrapDNS(tx *gorm.DB, instanceID uint, o BootstrapOptions) error {
	var n int64
	var soa models.DnsSoaTemplate
	if err := tx.Order("id").Limit(1).Find(&soa).Error; err != nil {
		return err
	}
	if soa.ID == 0 {
		soa = models.DnsSoaTemplate{Name: "soa-1", Mname: "ns1.home.arpa", Rname: "unknown@home.arpa",
			Refresh: 86400, Retry: 7200, Expire: 3600000, Minimum: 3600}
		if err := prepareDnsSoaTemplate(tx, &soa, nil); err != nil {
			return err
		}
		if err := tx.Create(&soa).Error; err != nil {
			return err
		}
	}
	var tmpl models.DnsTemplate
	if err := tx.Order("id").Limit(1).Find(&tmpl).Error; err != nil {
		return err
	}
	if tmpl.ID == 0 {
		ns := models.DnsNameserver{Name: "ns1.home.arpa"}
		if o.Address.IsValid() {
			ns.Address = o.Address.Addr().String()
		}
		tmpl = models.DnsTemplate{Name: "dns-1", SoaTemplateID: soa.ID, DefaultTtl: 3600, Nameservers: models.DnsNameserverList{ns}}
		if err := prepareDnsTemplate(tx, &tmpl, nil); err != nil {
			return err
		}
		if err := tx.Create(&tmpl).Error; err != nil {
			return err
		}
	}
	if err := tx.Model(&models.DnsZone{}).Where("instance_id = ?", instanceID).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	z := models.DnsZone{InstanceID: instanceID, Name: "home.arpa", Type: fwconfig.ZoneForward, DnsTemplateID: &tmpl.ID}
	if err := prepareDnsZone(tx, &z, nil); err != nil {
		return err
	}
	return tx.Create(&z).Error
}

// bootstrapMgmtService returns the name of the management service: SSH and
// the GUI port (when portitor-web runs here), kept at the port on reconfigure.
func bootstrapMgmtService(tx *gorm.DB, o BootstrapOptions) (string, error) {
	ports := models.ServicePortList{{Protocol: "tcp", DstLo: 22}}
	if o.GUIPort > 0 && o.GUIPort != 22 {
		ports = append(ports, models.ServicePort{Protocol: "tcp", DstLo: o.GUIPort})
	}
	gui := models.Service{Name: "portitor-mgmt", Type: models.ServiceTypePorts, Description: "Portitor management: SSH and the portitor-web GUI",
		Ports: ports}
	var old models.Service
	switch err := tx.Where("name = ?", gui.Name).First(&old).Error; {
	case errors.Is(err, gorm.ErrRecordNotFound):
		if err := prepareService(tx, &gui, nil); err != nil {
			return "", err
		}
		if err := tx.Create(&gui).Error; err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	case o.Reconfigure:
		if err := tx.Model(&old).Update("ports", gui.Ports).Error; err != nil {
			return "", err
		}
	}
	return gui.Name, nil
}

// reconfigureDefaultRoute makes gw the only IPv4 default route, or removes
// them when gw is not valid (a DHCP WAN brings its own).
func reconfigureDefaultRoute(tx *gorm.DB, instanceID uint, gw netip.Addr) error {
	var routes []models.Route
	if err := tx.Where("instance_id = ? AND destination IN ?", instanceID, []string{"0.0.0.0/0", "default"}).Order("id").Find(&routes).Error; err != nil {
		return err
	}
	kept := false
	for _, r := range routes {
		if r.Destination == "default" {
			if a, err := netip.ParseAddr(r.Gateway); err != nil || !a.Is4() {
				continue
			}
		}
		if !gw.IsValid() || kept {
			if err := tx.Delete(&r).Error; err != nil {
				return err
			}
			continue
		}
		r.Destination, r.Gateway, r.InterfaceID, r.Enabled = "0.0.0.0/0", gw.String(), nil, true
		if err := prepareRoute(tx, &r, nil); err != nil {
			return err
		}
		if err := tx.Save(&r).Error; err != nil {
			return err
		}
		kept = true
	}
	if !gw.IsValid() || kept {
		return nil
	}
	r := models.Route{InstanceID: instanceID, Destination: "0.0.0.0/0", Gateway: gw.String(), Enabled: true, Description: "default route"}
	if err := prepareRoute(tx, &r, nil); err != nil {
		return err
	}
	return tx.Create(&r).Error
}

// bootstrapIface enables an interface, labelled role (LAN or WAN) unless
// the user labelled it: static with address (its prefix goes into IPAM,
// described as role), or DHCP when address is not valid, without a default
// route if noRoute. With reconfigure, or DHCP, address becomes the
// interface's only IPv4 address, taken from another interface if need be.
func bootstrapIface(tx *gorm.DB, instanceID uint, name string, address netip.Prefix, role string, noRoute, reconfigure bool) (*models.Interface, error) {
	var ifc models.Interface
	if err := tx.Where("instance_id = ? AND name = ?", instanceID, name).First(&ifc).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, bad(fmt.Sprintf("the agent reports no interface %s", name))
		}
		return nil, err
	}
	old := ifc
	ifc.Enabled = true
	ifc.DhcpNoDefaultRoute = noRoute
	// The role as label, unless the user has labelled the interface; the
	// description goes if the user has not written one (bootstrap used to
	// put the role there).
	switch ifc.Label {
	case "", "LAN", "WAN":
		ifc.Label = role
	}
	switch ifc.Description {
	case "found on the firewall", "LAN", "WAN":
		ifc.Description = ""
	}
	switch {
	case !address.IsValid():
		ifc.Ipv4Mode = fwconfig.ModeDHCP
	case address.Addr().Is4():
		ifc.Ipv4Mode = fwconfig.ModeStatic
	}

	// The addresses to keep: with reconfigure or DHCP no other IPv4 one,
	// and none with the new address's IP (it comes back with its length).
	addrs := models.StringList{}
	for _, a := range ifc.Addresses {
		p, err := netip.ParsePrefix(a)
		if err != nil || (address.IsValid() && p.Addr() == address.Addr()) ||
			(p.Addr().Is4() && (reconfigure || !address.IsValid())) {
			continue
		}
		addrs = append(addrs, a)
	}
	if address.IsValid() {
		addrs = append(addrs, address.String())
		if err := takeAddress(tx, &ifc, address.Addr(), reconfigure); err != nil {
			return nil, err
		}
	}
	ifc.Addresses = addrs
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
	if n == 0 && !address.IsSingleIP() {
		p := models.IpamPrefix{InstanceID: instanceID, Prefix: prefix, Description: role, DhcpDnsServers: models.StringList{}}
		if err := prepareIpamPrefix(tx, &p, nil); err != nil {
			return nil, err
		}
		if err := tx.Create(&p).Error; err != nil {
			return nil, err
		}
	}
	return &ifc, nil
}

// takeAddress removes ip from the other interfaces of ifc's instance, with
// reconfigure; without, an address on another interface is an error.
func takeAddress(tx *gorm.DB, ifc *models.Interface, ip netip.Addr, reconfigure bool) error {
	var others []models.Interface
	if err := tx.Where("instance_id = ? AND id <> ?", ifc.InstanceID, ifc.ID).Find(&others).Error; err != nil {
		return err
	}
	for _, o := range others {
		keep := models.StringList{}
		for _, a := range o.Addresses {
			if p, err := netip.ParsePrefix(a); err != nil || p.Addr() != ip {
				keep = append(keep, a)
			}
		}
		if len(keep) == len(o.Addresses) {
			continue
		}
		if !reconfigure {
			return bad(fmt.Sprintf("%s is on another interface (%s)", ip, o.Name))
		}
		if err := tx.Model(&o).Update("addresses", keep).Error; err != nil {
			return err
		}
	}
	return nil
}
