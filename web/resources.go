// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"unicode"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/netobj"
	"github.com/abundo/portitor/internal/wgkeys"
	"github.com/abundo/portitor/models"
)

// Entry-time checks. They cover shape and references; the full semantic
// check is fwconfig.Validate at deploy time (see builder.Build), which also
// runs again on the agent.

func oneOf(field, v string, allowed ...string) error {
	if !slices.Contains(allowed, v) {
		return bad(fmt.Sprintf("%s must be one of %s", field, strings.Join(allowed, ", ")))
	}
	return nil
}

func instanceExists(tx *gorm.DB, id uint) error {
	var n int64
	tx.Model(&models.Instance{}).Where("id = ?", id).Count(&n)
	if n == 0 {
		return bad("virtual firewall does not exist")
	}
	return nil
}

func cleanList(list models.StringList) models.StringList {
	out := models.StringList{}
	for _, s := range list {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ifaceAddrs checks interface addresses (192.168.1.1/24): each is a host
// of its prefix. With delegated, an address may also be relative to a
// delegated prefix (<wan0>:2000::1/64). It returns them in canonical
// form, without repeats.
func ifaceAddrs(field string, list models.StringList, delegated bool) (models.StringList, error) {
	out := models.StringList{}
	for _, s := range cleanList(list) {
		if delegated && fwconfig.IsDelegated(s) {
			d, err := fwconfig.ParseDelegated(s)
			if err != nil {
				return nil, bad(fmt.Sprintf("%s: %q: %v (e.g. <wan0>:2000::1/64)", field, s, err))
			}
			if d.IsPrefix() && d.Bits < 127 {
				return nil, bad(fmt.Sprintf("%s: %s is the network address of the prefix; give the interface's own address, e.g. <%s>:%x::1/%d", field, s, d.Interface, d.Subnet, d.Bits))
			}
			if !slices.Contains(out, d.String()) {
				out = append(out, d.String())
			}
			continue
		}
		p, err := fwconfig.ParseInterfaceAddress(s)
		if err != nil {
			if _, perr := netip.ParsePrefix(s); perr != nil {
				return nil, bad(fmt.Sprintf("%s: %q is not an address with a prefix length (e.g. 192.168.1.1/24)", field, s))
			}
			return nil, bad(fmt.Sprintf("%s: %v", field, err))
		}
		if !slices.Contains(out, p.String()) {
			out = append(out, p.String())
		}
	}
	return out, nil
}

// checkAddrsFree refuses an address of interface i that another interface
// of its instance has.
func checkAddrsFree(tx *gorm.DB, i *models.Interface) error {
	var others []models.Interface
	if err := tx.Where("instance_id = ? AND id <> ?", i.InstanceID, i.ID).Find(&others).Error; err != nil {
		return err
	}
	for _, a := range i.Addresses {
		if fwconfig.IsDelegated(a) {
			for _, o := range others {
				if slices.Contains(o.Addresses, a) {
					return bad(fmt.Sprintf("%s is already on %s", a, o.Name))
				}
			}
			continue
		}
		ip := netip.MustParsePrefix(a).Addr()
		for _, o := range others {
			for _, b := range o.Addresses {
				if p, err := netip.ParsePrefix(b); err == nil && p.Addr() == ip {
					return bad(fmt.Sprintf("%s is already on %s", ip, o.Name))
				}
			}
		}
	}
	return nil
}

func prepareInstance(tx *gorm.DB, in, old *models.Instance) error {
	in.Name = strings.TrimSpace(in.Name)
	if !fwconfig.ValidInstanceName(in.Name) {
		return bad("name: lowercase letters and digits, starting with a letter, at most 12 characters")
	}
	if old == nil {
		var st models.Settings
		var n int64
		if err := tx.Select("virtual_firewalls").First(&st, 1).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err := tx.Model(&models.Instance{}).Count(&n).Error; err != nil {
			return err
		}
		if n > 0 && !st.VirtualFirewalls {
			return bad("virtual firewalls are turned off (Settings)")
		}
	}
	in.LogDrops = cleanList(in.LogDrops)
	for _, c := range in.LogDrops {
		if err := oneOf("log drops", c, fwconfig.ChainInput, fwconfig.ChainForward, fwconfig.ChainOutput); err != nil {
			return err
		}
	}
	in.LogInvalid = cleanList(in.LogInvalid)
	for _, c := range in.LogInvalid {
		if err := oneOf("log invalid", c, fwconfig.ChainInput, fwconfig.ChainForward, fwconfig.ChainOutput); err != nil {
			return err
		}
	}
	in.LogAuto = cleanList(in.LogAuto)
	for _, s := range in.LogAuto {
		if !fwconfig.ValidAutoService(s) {
			return bad(fmt.Sprintf("log auto: invalid service %q", s))
		}
	}
	in.DnsForwarders = cleanList(in.DnsForwarders)
	in.DnsAllowRecursion = cleanList(in.DnsAllowRecursion)
	if in.DnsUpstream == "" {
		in.DnsUpstream = fwconfig.UpstreamRoot
	}
	if err := oneOf("upstream DNS", in.DnsUpstream, fwconfig.UpstreamForward, fwconfig.UpstreamRoot, fwconfig.UpstreamDHCP); err != nil {
		return err
	}
	if in.DnsUpstream == fwconfig.UpstreamForward && len(in.DnsForwarders) == 0 {
		return bad("DNS forwarders: enter at least one DNS server, or pick another upstream")
	}
	if in.DnsForwardMode == "" {
		in.DnsForwardMode = fwconfig.ForwardFirst
	}
	if err := oneOf("DNS forward mode", in.DnsForwardMode, fwconfig.ForwardFirst, fwconfig.ForwardOnly); err != nil {
		return err
	}
	if in.DnsDnssecValidation == "" {
		in.DnsDnssecValidation = fwconfig.DNSSECValidationAuto
	}
	if err := oneOf("DNSSEC validation", in.DnsDnssecValidation, fwconfig.DNSSECValidationAuto, fwconfig.DNSSECValidationNo); err != nil {
		return err
	}
	if err := checkEntries(tx, "DNS forwarders", in.DnsForwarders, entryHost); err != nil {
		return err
	}
	if err := checkEntries(tx, "allow recursion", in.DnsAllowRecursion, entryCIDR); err != nil {
		return err
	}
	in.Nat64Prefix = strings.TrimSpace(in.Nat64Prefix)
	if in.Nat64Prefix == "" {
		in.Nat64Prefix = fwconfig.NAT64WellKnownPrefix
	}
	if err := fwconfig.CheckNAT64Prefix(in.Nat64Prefix); err != nil {
		return bad(err.Error())
	}
	in.Nat64Pool4 = cleanList(in.Nat64Pool4)
	for _, s := range in.Nat64Pool4 {
		if pfx, err := netip.ParsePrefix(s); err != nil || !pfx.Addr().Is4() || pfx != pfx.Masked() {
			return bad(fmt.Sprintf("NAT64 IPv4 pool: %q is not an IPv4 prefix", s))
		}
	}
	seen := map[string]bool{}
	for i := range in.NtpServers {
		s := &in.NtpServers[i]
		s.Address = strings.TrimSpace(s.Address)
		if !fwconfig.ValidNTPServer(s.Address) {
			return bad(fmt.Sprintf("NTP servers: %q is not an address or host name", s.Address))
		}
		if seen[s.Address] {
			return bad(fmt.Sprintf("NTP servers: %s is listed twice", s.Address))
		}
		seen[s.Address] = true
	}
	if in.NtpEnabled && len(in.NtpServers) == 0 {
		return bad("NTP: enter at least one server")
	}
	in.NtpAllow = cleanList(in.NtpAllow)
	if err := checkEntries(tx, "NTP allowed clients", in.NtpAllow, entryCIDR); err != nil {
		return err
	}
	if err := prepareInstanceSNMP(tx, in); err != nil {
		return err
	}
	in.DnsQueryLogClients = cleanList(in.DnsQueryLogClients)
	if err := checkEntries(tx, "query log clients", in.DnsQueryLogClients, entryCIDR); err != nil {
		return err
	}
	in.DnsQueryLogNames = cleanList(in.DnsQueryLogNames)
	for i, n := range in.DnsQueryLogNames {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if !fwconfig.ValidDomain(n) {
			return bad(fmt.Sprintf("query log names: %q is not a valid domain", n))
		}
		in.DnsQueryLogNames[i] = n
	}
	in.DnsQueryLogTypes = cleanList(in.DnsQueryLogTypes)
	for i, t := range in.DnsQueryLogTypes {
		t = strings.ToUpper(t)
		if !fwconfig.ValidQueryType(t) {
			return bad(fmt.Sprintf("query log types: %q is not a DNS query type", t))
		}
		in.DnsQueryLogTypes[i] = t
	}
	if in.DhcpDomainName != "" && !fwconfig.ValidDomain(in.DhcpDomainName) {
		return bad("DHCP domain name is not a valid domain")
	}
	if in.DhcpLeaseTime == 0 {
		in.DhcpLeaseTime = 86400
	}
	if in.DhcpLeaseTime < 300 {
		return bad("DHCP lease time must be at least 300 seconds")
	}
	// The default instance is the host itself, with its files in the
	// standard places: it is the first instance, and stays the default.
	if old != nil {
		in.IsDefault = old.IsDefault
	} else {
		var n int64
		tx.Model(&models.Instance{}).Where("is_default").Count(&n)
		in.IsDefault = n == 0
	}
	return renameInstanceRole(tx, in, old)
}

// seedInstance adds the instance's role and the rules a new instance starts
// with. The output chain drops by default, so an explicit rule keeps the
// firewall's own traffic open until the user narrows it.
func seedInstance(tx *gorm.DB, in *models.Instance) error {
	if err := createInstanceRole(tx, in); err != nil {
		return err
	}
	return tx.Create(&models.Rule{
		InstanceID: in.ID, Position: nextPosition(tx, "rules", in.ID), Chain: fwconfig.ChainOutput,
		Action: fwconfig.ActionAccept, Enabled: true, Description: "allow all output",
		InInterfaces: models.StringList{}, OutInterfaces: models.StringList{},
		SrcAddrs: models.StringList{}, DstAddrs: models.StringList{},
	}).Error
}

// prepareTunnel checks a 6in4 interface's tunnel and tunnel broker
// account; other kinds have none.
func prepareTunnel(i *models.Interface) error {
	newKey := strings.TrimSpace(i.NewHeUpdateKey)
	i.NewHeUpdateKey = ""
	if i.Kind != fwconfig.Kind6in4 {
		i.TunnelRemote, i.TunnelLocal, i.HeTunnelID, i.HeUsername, i.HeUpdateKey = "", "", "", "", ""
		i.TunnelDefaultRoute = false
		return nil
	}
	if i.Ipv4Mode == fwconfig.ModeDHCP {
		return bad("6in4 tunnels have static addresses")
	}
	i.TunnelRemote, i.TunnelLocal = strings.TrimSpace(i.TunnelRemote), strings.TrimSpace(i.TunnelLocal)
	if !fwconfig.ValidTunnelEndpoint(i.TunnelRemote) {
		return bad("tunnel server: the server's IPv4 address (Server IPv4 Address at tunnelbroker.net)")
	}
	if i.TunnelLocal != "" && !fwconfig.ValidTunnelEndpoint(i.TunnelLocal) {
		return bad("local address: an IPv4 address of the firewall, or empty for any")
	}
	i.HeTunnelID, i.HeUsername = strings.TrimSpace(i.HeTunnelID), strings.TrimSpace(i.HeUsername)
	if i.HeTunnelID == "" {
		i.HeUsername, i.HeUpdateKey = "", ""
		return nil
	}
	if !fwconfig.ValidTunnelID(i.HeTunnelID) {
		return bad("tunnel id: the number tunnelbroker.net shows as Tunnel ID")
	}
	if !fwconfig.ValidTunnelUser(i.HeUsername) {
		return bad("user name: the tunnelbroker.net account's user name")
	}
	if newKey != "" {
		if !fwconfig.ValidUpdateKey(newKey) {
			return bad("update key: at most 128 characters, no spaces")
		}
		i.HeUpdateKey = newKey
	}
	if i.HeUpdateKey == "" {
		return bad("update key: the tunnel's Update Key (Advanced tab at tunnelbroker.net)")
	}
	return nil
}

// presentInterface hides the tunnel broker update key.
func presentInterface(i *models.Interface) {
	i.HasHeUpdateKey = i.HeUpdateKey != ""
	i.NewHeUpdateKey = ""
}

func prepareInterface(tx *gorm.DB, i, old *models.Interface) error {
	if err := instanceExists(tx, i.InstanceID); err != nil {
		return err
	}
	i.Name = strings.TrimSpace(i.Name)
	if !fwconfig.ValidIfname(i.Name) || i.Name == "lo" {
		return bad("name: a Linux interface name (at most 15 characters, no spaces)")
	}
	if strings.HasPrefix(i.Name, fwconfig.IFBPrefix) {
		return bad("name: " + fwconfig.IFBPrefix + " names are for the shaping devices")
	}
	if strings.HasPrefix(i.Name, fwconfig.NAT64DevicePrefix) {
		return bad("name: " + fwconfig.NAT64DevicePrefix + " names are for the NAT64 devices")
	}
	i.Label = strings.TrimSpace(i.Label)
	if len(i.Label) > 32 || strings.ContainsFunc(i.Label, unicode.IsControl) {
		return bad("label: at most 32 characters, no control characters")
	}
	if i.Kind == "" {
		i.Kind = fwconfig.KindPhysical
	}
	if err := oneOf("kind", i.Kind, fwconfig.KindPhysical, fwconfig.KindVLAN, fwconfig.KindBridge, fwconfig.KindWireGuard, fwconfig.KindLoopback, fwconfig.Kind6in4); err != nil {
		return err
	}
	if old != nil && old.Kind != i.Kind {
		return bad("the kind of an interface cannot change; create a new one")
	}
	if i.Ipv4Mode == "" {
		i.Ipv4Mode = fwconfig.ModeStatic
	}
	if err := oneOf("IPv4 mode", i.Ipv4Mode, fwconfig.ModeStatic, fwconfig.ModeDHCP, fwconfig.ModeNone); err != nil {
		return err
	}
	if err := checkNewIfaceName(tx, i.InstanceID, i.Name, "name"); err != nil {
		return err
	}
	addrs, err := ifaceAddrs("addresses", i.Addresses, true)
	if err != nil {
		return err
	}
	i.Addresses = addrs
	if err := prepareDHCPv6(tx, i, old); err != nil {
		return err
	}
	for _, a := range i.Addresses {
		if fwconfig.IsDelegated(a) {
			continue
		}
		if i.Ipv4Mode == fwconfig.ModeDHCP && netip.MustParsePrefix(a).Addr().Is4() {
			return bad(fmt.Sprintf("addresses: %s is an IPv4 address, and IPv4 comes from the DHCP client; remove it or make IPv4 static", a))
		}
	}
	if err := checkAddrsFree(tx, i); err != nil {
		return err
	}
	if err := renumberPrefixes(tx, old, i); err != nil {
		return err
	}
	if i.Ipv4Mode != fwconfig.ModeDHCP {
		i.DnsFromDhcp = false
	}
	if i.DnsFromDhcp {
		// One per instance: taking the flag moves it here.
		if err := tx.Model(&models.Interface{}).Where("instance_id = ? AND id <> ?", i.InstanceID, i.ID).Update("dns_from_dhcp", false).Error; err != nil {
			return err
		}
	}
	if old != nil {
		if err := ifaceMoved(tx, old.InstanceID, old.Name, i.InstanceID, i.Name); err != nil {
			return err
		}
		if old.InstanceID != i.InstanceID {
			if err := refuseDyndnsIface(tx, old); err != nil {
				return err
			}
			if err := refuseCertificateIface(tx, old); err != nil {
				return err
			}
			if err := refuseIfaceMove(tx, old); err != nil {
				return err
			}
		}
	}
	i.Members = cleanList(i.Members)
	switch i.Kind {
	case fwconfig.KindVLAN:
		if i.VlanID < 1 || i.VlanID > 4094 {
			return bad("VLAN id must be 1-4094")
		}
		if !fwconfig.ValidIfname(i.Parent) {
			return bad("VLAN parent interface is required")
		}
	case fwconfig.KindLoopback:
		if i.Ipv4Mode == fwconfig.ModeDHCP {
			return bad("loopback interfaces have static addresses")
		}
	case fwconfig.KindWireGuard:
		if i.Ipv4Mode == fwconfig.ModeDHCP {
			return bad("WireGuard interfaces have static addresses")
		}
		if i.WgPrivateKey == "" {
			priv, pub, err := wgkeys.Generate()
			if err != nil {
				return err
			}
			i.WgPrivateKey, i.WgPublicKey = priv, pub
		}
		if i.WgListenPort < 0 || i.WgListenPort > 65535 {
			return bad("listen port must be 0-65535")
		}
		i.WgEndpoint = strings.TrimSpace(i.WgEndpoint)
		if i.WgEndpoint != "" && !fwconfig.ValidEndpoint(i.WgEndpoint) {
			return bad("public endpoint must be host:port")
		}
		if i.WgKeepalive < 0 || i.WgKeepalive > 65535 {
			return bad("keepalive must be 0-65535")
		}
	default:
		i.WgEndpoint, i.WgKeepalive = "", 0
	}
	if err := prepareTunnel(i); err != nil {
		return err
	}
	if i.Kind == fwconfig.KindWireGuard || i.Kind == fwconfig.KindLoopback || i.Kind == fwconfig.Kind6in4 {
		i.Lldp = false
	}
	if i.Kind == fwconfig.KindLoopback {
		i.ShapeEgress, i.ShapeIngress = 0, 0
	}
	if i.ShapeEgress < 0 || i.ShapeEgress > fwconfig.MaxShapeMbit || i.ShapeIngress < 0 || i.ShapeIngress > fwconfig.MaxShapeMbit {
		return bad(fmt.Sprintf("shaping: 0-%d Mbit/s", fwconfig.MaxShapeMbit))
	}
	if i.Kind != fwconfig.KindVLAN {
		i.Parent, i.VlanID = "", 0
	}
	if i.Kind != fwconfig.KindBridge {
		i.Members = models.StringList{}
	}
	return nil
}

func prepareWgPeer(tx *gorm.DB, p, old *models.WgPeer) error {
	var ifc models.Interface
	if tx.First(&ifc, p.InterfaceID).Error != nil || ifc.Kind != fwconfig.KindWireGuard {
		return bad("peer must belong to a WireGuard interface")
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return bad("name is required")
	}
	p.PublicKey = strings.TrimSpace(p.PublicKey)
	if p.PublicKey == "" && old == nil {
		// No key given: generate the client's key pair here, so the GUI
		// can hand out a complete client config.
		priv, pub, err := wgkeys.Generate()
		if err != nil {
			return err
		}
		psk, err := wgkeys.PresharedKey()
		if err != nil {
			return err
		}
		p.ClientPrivateKey, p.PublicKey, p.PresharedKey = priv, pub, psk
	}
	if !fwconfig.ValidWGKey(p.PublicKey) {
		return bad("public key is not a WireGuard key")
	}
	if old != nil && old.PublicKey != p.PublicKey && old.ClientPrivateKey != "" {
		p.ClientPrivateKey = "" // a pasted key replaces the generated pair
	}
	p.Endpoint = strings.TrimSpace(p.Endpoint)
	if p.Endpoint != "" && !fwconfig.ValidEndpoint(p.Endpoint) {
		return bad("endpoint must be host:port")
	}
	p.AllowedIPs = cleanList(p.AllowedIPs)
	if len(p.AllowedIPs) == 0 {
		return bad("allowed IPs: at least one CIDR (the peer's tunnel address, e.g. 10.99.0.2/32)")
	}
	if err := checkEntries(tx, "allowed IPs", p.AllowedIPs, entryCIDR); err != nil {
		return err
	}
	p.Networks = cleanList(p.Networks)
	if err := checkEntries(tx, "networks", p.Networks, entryCIDR); err != nil {
		return err
	}
	for _, n := range p.Networks {
		if pfx, err := netip.ParsePrefix(n); err == nil && pfx.Bits() == 0 {
			return bad("networks: " + n + " would be a default route; add a static route through the interface instead")
		}
	}
	if p.Keepalive < 0 || p.Keepalive > 65535 {
		return bad("keepalive must be 0-65535")
	}
	return nil
}

func presentWgPeer(p *models.WgPeer) {
	p.HasPresharedKey = p.PresharedKey != ""
	p.HasClientKey = p.ClientPrivateKey != ""
}

func prepareLink(tx *gorm.DB, l, old *models.Link) error {
	l.Name = strings.TrimSpace(l.Name)
	if !fwconfig.ValidName(l.Name) {
		return bad("name: no control characters")
	}
	if l.InstanceAID == l.InstanceBID {
		return bad("a link connects two different virtual firewalls")
	}
	l.InterfaceA, l.InterfaceB = strings.TrimSpace(l.InterfaceA), strings.TrimSpace(l.InterfaceB)
	for _, end := range []struct {
		inst  uint
		iface string
		addrs *models.StringList
		label string
	}{
		{l.InstanceAID, l.InterfaceA, &l.AddressesA, "side A"},
		{l.InstanceBID, l.InterfaceB, &l.AddressesB, "side B"},
	} {
		if err := instanceExists(tx, end.inst); err != nil {
			return bad(end.label + ": virtual firewall does not exist")
		}
		if !fwconfig.ValidIfname(end.iface) {
			return bad(end.label + ": interface name is required")
		}
		if err := checkNewIfaceName(tx, end.inst, end.iface, end.label+" interface"); err != nil {
			return err
		}
		addrs, err := ifaceAddrs(end.label+" addresses", *end.addrs, false)
		if err != nil {
			return err
		}
		*end.addrs = addrs
	}
	if old != nil {
		if err := ifaceMoved(tx, old.InstanceAID, old.InterfaceA, l.InstanceAID, l.InterfaceA); err != nil {
			return err
		}
		if err := ifaceMoved(tx, old.InstanceBID, old.InterfaceB, l.InstanceBID, l.InterfaceB); err != nil {
			return err
		}
	}
	return nil
}

func prepareRoute(tx *gorm.DB, r, _ *models.Route) error {
	if err := instanceExists(tx, r.InstanceID); err != nil {
		return err
	}
	r.Destination = strings.TrimSpace(r.Destination)
	r.Gateway = strings.TrimSpace(r.Gateway)
	if netobj.IsName(r.Destination) && r.Destination != "default" {
		if err := checkObjectName(tx, "destination", r.Destination, false); err != nil {
			return err
		}
	} else if r.Destination != "default" {
		p, err := netip.ParsePrefix(r.Destination)
		if err != nil {
			return bad("destination must be a CIDR, \"default\" or the name of a host/prefix")
		}
		r.Destination = p.Masked().String()
	}
	if r.Gateway != "" {
		if err := checkHost(tx, "gateway", r.Gateway); err != nil {
			return err
		}
	}
	if r.InterfaceID != nil {
		var i models.Interface
		if tx.First(&i, *r.InterfaceID).Error != nil || i.InstanceID != r.InstanceID {
			return bad("interface must belong to the same virtual firewall")
		}
	}
	if r.Gateway == "" && r.InterfaceID == nil {
		return bad("a route needs a gateway or an interface")
	}
	if r.Bfd && r.Gateway == "" {
		return bad("BFD watches the gateway: a route with BFD needs one")
	}
	if r.Bfd && r.Metric > 255 {
		return bad("with BFD, the metric is FRR's administrative distance: 0-255")
	}
	return nil
}

func nextPosition(tx *gorm.DB, table string, instanceID uint) int {
	var max *int
	tx.Table(table).Where("instance_id = ?", instanceID).Select("MAX(position)").Scan(&max)
	if max == nil {
		return 10
	}
	return *max + 10
}

func prepareRule(tx *gorm.DB, r, old *models.Rule) error {
	if err := instanceExists(tx, r.InstanceID); err != nil {
		return err
	}
	if err := oneOf("chain", r.Chain, fwconfig.ChainInput, fwconfig.ChainForward, fwconfig.ChainOutput); err != nil {
		return err
	}
	if err := oneOf("kind", r.Kind, "", models.RuleKindComment, models.RuleKindGroup); err != nil {
		return err
	}
	if r.IsNote() {
		// A comment or group keeps only its chain, place and text.
		*r = models.Rule{
			Base: r.Base, InstanceID: r.InstanceID, Position: r.Position, Chain: r.Chain,
			Kind: r.Kind, Description: strings.TrimSpace(r.Description), Enabled: true,
			InInterfaces: models.StringList{}, OutInterfaces: models.StringList{},
			SrcAddrs: models.StringList{}, DstAddrs: models.StringList{}, Services: models.StringList{},
		}
		if old == nil && r.Position == 0 {
			r.Position = nextPosition(tx, "rules", r.InstanceID)
		}
		return nil
	}
	if err := oneOf("action", r.Action, fwconfig.ActionAccept, fwconfig.ActionDrop, fwconfig.ActionReject); err != nil {
		return err
	}
	if err := oneOf("family", r.Family, "", "ipv4", "ipv6"); err != nil {
		return err
	}
	r.InInterfaces, r.OutInterfaces = dedupe(cleanList(r.InInterfaces)), dedupe(cleanList(r.OutInterfaces))
	if r.Chain == fwconfig.ChainInput {
		r.OutInterfaces = models.StringList{}
	}
	if r.Chain == fwconfig.ChainOutput {
		r.InInterfaces = models.StringList{}
	}
	if err := checkIfaceList(tx, r.InstanceID, "incoming interfaces", r.InInterfaces); err != nil {
		return err
	}
	if err := checkIfaceList(tx, r.InstanceID, "outgoing interfaces", r.OutInterfaces); err != nil {
		return err
	}
	r.SrcAddrs, r.DstAddrs = cleanList(r.SrcAddrs), cleanList(r.DstAddrs)
	if err := checkEntries(tx, "source", r.SrcAddrs, entryRule); err != nil {
		return err
	}
	if err := checkEntries(tx, "destination", r.DstAddrs, entryRule); err != nil {
		return err
	}
	r.Services = dedupe(cleanList(r.Services))
	if err := checkServices(tx, r.Services); err != nil {
		return err
	}
	r.RateLimit = strings.TrimSpace(r.RateLimit)
	if err := checkRateLimit(tx, r.InstanceID, r.RateLimit, r.Action); err != nil {
		return err
	}
	if old == nil && r.Position == 0 {
		r.Position = nextPosition(tx, "rules", r.InstanceID)
	}
	return nil
}

func prepareNat(tx *gorm.DB, n, old *models.NatRule) error {
	if err := instanceExists(tx, n.InstanceID); err != nil {
		return err
	}
	if err := oneOf("kind", n.Kind, fwconfig.NATDNAT, fwconfig.NATSNAT, fwconfig.NATMasquerade); err != nil {
		return err
	}
	if err := oneOf("protocol", n.Protocol, "", "tcp", "udp", "tcp,udp"); err != nil {
		return err
	}
	n.InInterfaces, n.OutInterfaces = dedupe(cleanList(n.InInterfaces)), dedupe(cleanList(n.OutInterfaces))
	if n.Kind == fwconfig.NATDNAT {
		n.OutInterfaces = models.StringList{}
	} else {
		n.InInterfaces = models.StringList{}
	}
	if err := checkIfaceList(tx, n.InstanceID, "incoming interfaces", n.InInterfaces); err != nil {
		return err
	}
	if err := checkIfaceList(tx, n.InstanceID, "outgoing interfaces", n.OutInterfaces); err != nil {
		return err
	}
	n.SrcAddrs, n.DstAddrs = cleanList(n.SrcAddrs), cleanList(n.DstAddrs)
	if err := checkEntries(tx, "source", n.SrcAddrs, entryAny); err != nil {
		return err
	}
	if err := checkEntries(tx, "destination", n.DstAddrs, entryAny); err != nil {
		return err
	}
	n.ToAddr = strings.TrimSpace(n.ToAddr)
	if n.Kind == fwconfig.NATMasquerade {
		n.ToAddr, n.ToPort = "", 0
	} else if n.ToAddr == "" {
		return bad("target address is required")
	} else if err := checkHost(tx, "target address", n.ToAddr); err != nil {
		return err
	}
	n.DstPorts = strings.TrimSpace(n.DstPorts)
	if n.DstPorts != "" {
		if n.Protocol == "" {
			return bad("ports need protocol tcp, udp or tcp+udp")
		}
		if _, err := fwconfig.ParsePorts(n.DstPorts); err != nil {
			return bad(err.Error() + "; use ports (22), ranges (8000-8080) or port names (https)")
		}
	}
	if n.Kind != fwconfig.NATDNAT {
		n.Hairpin = false
	} else if n.Hairpin && len(n.InInterfaces) == 0 {
		return bad("hairpin needs incoming interfaces (the WAN)")
	}
	if n.ToPort != 0 && n.Protocol == "" {
		return bad("a target port needs protocol tcp, udp or tcp+udp")
	}
	if old == nil && n.Position == 0 {
		n.Position = nextPosition(tx, "nat_rules", n.InstanceID)
	}
	return nil
}

func prepareIpamPrefix(tx *gorm.DB, p, _ *models.IpamPrefix) error {
	if err := instanceExists(tx, p.InstanceID); err != nil {
		return err
	}
	pfx, err := netip.ParsePrefix(strings.TrimSpace(p.Prefix))
	if err != nil {
		return bad("prefix must be a CIDR, e.g. 192.168.1.0/24")
	}
	pfx = pfx.Masked()
	p.Prefix = pfx.String()
	p.DhcpDnsServers = cleanList(p.DhcpDnsServers)
	if err := checkEntries(tx, "DNS servers", p.DhcpDnsServers, entryHost); err != nil {
		return err
	}
	if pfx.Addr().Is4() {
		if p.RaEnabled || p.RaSlaac {
			return bad("router advertisements are for IPv6 prefixes")
		}
	} else {
		if !p.RaEnabled {
			p.RaSlaac = false
		}
		if p.RaSlaac && pfx.Bits() != 64 {
			return bad("SLAAC needs a /64 prefix")
		}
		if p.DhcpEnabled && !p.RaEnabled {
			return bad("DHCPv6 needs router advertisements on the prefix: clients learn the default router from them")
		}
		if p.DhcpGateway != "" {
			return bad("IPv6 clients learn the gateway from router advertisements; leave the DHCP gateway empty")
		}
	}
	if !p.DhcpEnabled {
		return nil
	}
	if (p.DhcpRangeStart == "") != (p.DhcpRangeEnd == "") {
		return bad("the DHCP range needs both start and end")
	}
	for _, a := range []string{p.DhcpRangeStart, p.DhcpRangeEnd, p.DhcpGateway} {
		if a == "" {
			continue
		}
		ip, err := netip.ParseAddr(a)
		if err != nil || !pfx.Contains(ip) {
			return bad(fmt.Sprintf("%s is not inside %s", a, pfx))
		}
	}
	if p.DhcpRangeStart != "" {
		s, _ := netip.ParseAddr(p.DhcpRangeStart)
		e, _ := netip.ParseAddr(p.DhcpRangeEnd)
		if s.Compare(e) > 0 {
			return bad("DHCP range start is after its end")
		}
	}
	return nil
}

func prepareIpamAddress(tx *gorm.DB, a, _ *models.IpamAddress) error {
	if err := instanceExists(tx, a.InstanceID); err != nil {
		return err
	}
	ip, err := fwconfig.ParseAddr(strings.TrimSpace(a.Address))
	if err != nil {
		return bad("address must be a plain IP address, e.g. 192.168.1.10")
	}
	a.Address = ip.String()
	a.DnsName = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a.DnsName), "."))
	if a.DnsName != "" && !fwconfig.ValidDomain(a.DnsName) {
		return bad("DNS name must be a fully qualified name, e.g. nas.home.arpa")
	}
	a.Mac = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(a.Mac), "-", ":"))
	if a.Mac != "" {
		if !fwconfig.ValidMAC(a.Mac) {
			return bad("MAC must look like 02:00:00:00:00:01")
		}
		if a.DnsName == "" {
			return bad("a DHCP reservation needs a DNS name (reservations are made from DNS records)")
		}
	}
	return nil
}

func prepareDnsZone(tx *gorm.DB, z, old *models.DnsZone) error {
	if err := instanceExists(tx, z.InstanceID); err != nil {
		return err
	}
	if z.Type == "" {
		z.Type = fwconfig.ZoneForward
	}
	// Records belong to forward zones only.
	if old != nil && old.Type != z.Type {
		return bad("the type of a zone cannot change; create a new one")
	}
	z.Name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(z.Name), "."))
	switch z.Type {
	case fwconfig.ZoneForward:
		if !fwconfig.ValidDomain(z.Name) {
			return bad("name must be a domain, e.g. home.arpa")
		}
	case fwconfig.ZoneReverse4, fwconfig.ZoneReverse6:
		p, err := netip.ParsePrefix(z.Name)
		if err != nil || p.Addr().Is4() != (z.Type == fwconfig.ZoneReverse4) {
			return bad("a reverse zone is named by its prefix, e.g. 192.168.1.0/24")
		}
		z.Name = p.Masked().String()
	case fwconfig.ZoneForwardOnly:
		if !fwconfig.ValidDomain(z.Name) {
			return bad("name must be a domain, e.g. int.example.com")
		}
	default:
		return oneOf("type", z.Type, fwconfig.ZoneForward, fwconfig.ZoneReverse4, fwconfig.ZoneReverse6, fwconfig.ZoneForwardOnly)
	}
	z.Forwarders = cleanList(z.Forwarders)
	if z.Type == fwconfig.ZoneForwardOnly {
		// No SOA or NS: nothing is served.
		z.DnsTemplateID = nil
		if len(z.Forwarders) == 0 {
			return bad("forwarders: enter at least one DNS server")
		}
		if err := checkEntries(tx, "forwarders", z.Forwarders, entryHost); err != nil {
			return err
		}
	} else {
		z.Forwarders = nil
	}
	if z.DnsTemplateID != nil && *z.DnsTemplateID == 0 {
		z.DnsTemplateID = nil
	}
	if z.DnsTemplateID != nil {
		var t models.DnsTemplate
		if tx.First(&t, *z.DnsTemplateID).Error != nil || !usableBy(t.InstanceID, t.Global, z.InstanceID) {
			return bad("DNS template does not exist")
		}
	}
	return nil
}

func prepareDnsRecord(tx *gorm.DB, r, _ *models.DnsRecord) error {
	var z models.DnsZone
	if tx.First(&z, r.ZoneID).Error != nil {
		return bad("zone does not exist")
	}
	if z.Type != fwconfig.ZoneForward {
		return bad("records go in forward zones; reverse zones are generated, forward-only zones are forwarded")
	}
	return checkRecord(&z, r, "")
}

// checkDNS runs fwconfig's validation of a DNS server config, for a quick
// answer when an entry is saved rather than at deploy time.
func checkDNS(dns fwconfig.DNSServer) error {
	doc := fwconfig.Document{Version: fwconfig.Version, Instances: []fwconfig.Instance{{Name: "check", Default: true, DNS: dns}}}
	if err := doc.Validate(); err != nil {
		if ve, ok := err.(*fwconfig.ValidationError); ok {
			msgs := make([]string, len(ve.Problems))
			for i, p := range ve.Problems {
				// Drop the "instance check: dns zone ...: record ...:" context.
				msgs[i] = p[strings.LastIndex(p, ": ")+2:]
			}
			return bad(strings.Join(msgs, "; "))
		}
		return err
	}
	return nil
}

func soaDoc(s *models.DnsSoaTemplate) fwconfig.DNSSOATemplate {
	return fwconfig.DNSSOATemplate{Name: s.Name, MName: s.Mname, RName: s.Rname, Refresh: s.Refresh, Retry: s.Retry, Expire: s.Expire, Minimum: s.Minimum}
}

func dnssecDoc(k *models.DnsDnssecPolicy) fwconfig.DNSSECPolicy {
	return fwconfig.DNSSECPolicy{
		Name: k.Name, KSKLifetime: k.KskLifetime, KSKAlgorithm: k.KskAlgorithm, ZSKLifetime: k.ZskLifetime, ZSKAlgorithm: k.ZskAlgorithm,
		PurgeKeys: k.PurgeKeys, SignaturesValidity: k.SignaturesValidity, SignaturesValidityDNSKEY: k.SignaturesValidityDnskey, SignaturesRefresh: k.SignaturesRefresh,
	}
}

// dnsName trims a host name entered with or without the trailing dot.
func dnsName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// dnsOwner checks the instance and name of an SOA template, DNSSEC policy
// or DNS template (in table) before it is saved: it stays in its instance,
// only the default instance's may be global, and its name is unique among
// those its instance uses (its own and the global ones; a global one's
// among all, since every instance uses it). oldInstance is 0 on create.
func dnsOwner(tx *gorm.DB, table string, id, instanceID, oldInstance uint, global bool, name string) error {
	if oldInstance != 0 && instanceID != oldInstance {
		return bad("can't move to another virtual firewall")
	}
	var in models.Instance
	if instanceID == 0 || tx.First(&in, instanceID).Error != nil {
		return bad("virtual firewall does not exist")
	}
	if global && !in.IsDefault {
		return bad("only the default virtual firewall's can be global")
	}
	q := tx.Table(table).Where("name = ? AND id <> ?", name, id)
	if !global {
		q = q.Where("instance_id = ? OR global", instanceID)
	}
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return bad(fmt.Sprintf("name %q is in use", name))
	}
	return nil
}

// oldInstance is the instance a row was in before the change, 0 on create.
func oldInstance[T models.DnsSoaTemplate | models.DnsDnssecPolicy | models.DnsTemplate](old *T) uint {
	if old == nil {
		return 0
	}
	return uint(reflect.ValueOf(old).Elem().FieldByName("InstanceID").Uint())
}

// usableBy tells whether an SOA template, DNSSEC policy or DNS template of
// instance owner (global or not) may be used by a row of instance user.
func usableBy(owner uint, global bool, user uint) bool {
	return global || owner == user
}

// stillGlobal refuses to make a row local while rows of model elsewhere
// (another instance, or a global row) refer to it through column.
func stillGlobal(tx *gorm.DB, what string, model any, column string, id, instanceID uint, name func() []string) error {
	where := "instance_id <> ?"
	if _, ok := model.(*models.DnsTemplate); ok {
		where = "(instance_id <> ? OR global)"
	}
	var n int64
	if err := tx.Model(model).Where(column+" = ? AND "+where, id, instanceID).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return bad(fmt.Sprintf("%s stays global: it is used by %s", what, strings.Join(name(), ", ")))
	}
	return nil
}

func prepareDnsSoaTemplate(tx *gorm.DB, s, old *models.DnsSoaTemplate) error {
	s.Name = strings.TrimSpace(s.Name)
	if err := dnsOwner(tx, "dns_soa_templates", s.ID, s.InstanceID, oldInstance(old), s.Global, s.Name); err != nil {
		return err
	}
	if old != nil && old.Global && !s.Global {
		if err := stillGlobal(tx, s.Name, &models.DnsTemplate{}, "soa_template_id", s.ID, s.InstanceID, templateNames(tx, "soa_template_id", s.ID)); err != nil {
			return err
		}
	}
	s.Mname = dnsName(s.Mname)
	// Accept the mailbox written as an e-mail address.
	s.Rname = strings.Replace(dnsName(s.Rname), "@", ".", 1)
	return checkDNS(fwconfig.DNSServer{SOATemplates: []fwconfig.DNSSOATemplate{soaDoc(s)}})
}

func prepareDnsDnssecPolicy(tx *gorm.DB, k, old *models.DnsDnssecPolicy) error {
	for _, f := range []*string{&k.Name, &k.KskLifetime, &k.KskAlgorithm, &k.ZskLifetime, &k.ZskAlgorithm,
		&k.PurgeKeys, &k.SignaturesValidity, &k.SignaturesValidityDnskey, &k.SignaturesRefresh} {
		*f = strings.TrimSpace(*f)
	}
	if err := dnsOwner(tx, "dns_dnssec_policies", k.ID, k.InstanceID, oldInstance(old), k.Global, k.Name); err != nil {
		return err
	}
	if old != nil && old.Global && !k.Global {
		if err := stillGlobal(tx, k.Name, &models.DnsTemplate{}, "dnssec_policy_id", k.ID, k.InstanceID, templateNames(tx, "dnssec_policy_id", k.ID)); err != nil {
			return err
		}
	}
	return checkDNS(fwconfig.DNSServer{DNSSECPolicies: []fwconfig.DNSSECPolicy{dnssecDoc(k)}})
}

func prepareDnsTemplate(tx *gorm.DB, t, old *models.DnsTemplate) error {
	t.Name = strings.TrimSpace(t.Name)
	if err := dnsOwner(tx, "dns_templates", t.ID, t.InstanceID, oldInstance(old), t.Global, t.Name); err != nil {
		return err
	}
	if old != nil && old.Global && !t.Global {
		if err := stillGlobal(tx, t.Name, &models.DnsZone{}, "dns_template_id", t.ID, t.InstanceID, zoneNames(tx, t.ID)); err != nil {
			return err
		}
	}
	ns := models.DnsNameserverList{}
	for _, n := range t.Nameservers {
		n = models.DnsNameserver{Name: dnsName(n.Name), Address: strings.TrimSpace(n.Address)}
		if n.Name == "" {
			if n.Address != "" {
				return bad("nameservers: an address needs the nameserver's name")
			}
			continue
		}
		if n.Address != "" {
			ip, err := fwconfig.ParseAddr(n.Address)
			if err != nil {
				return bad(fmt.Sprintf("nameservers: %s: %q is not an IP address", n.Name, n.Address))
			}
			n.Address = ip.String()
		}
		// A second row of a name adds its other address.
		if slices.Contains(ns, n) {
			return bad(fmt.Sprintf("nameservers: %s is listed twice", strings.TrimSpace(n.Name+" "+n.Address)))
		}
		ns = append(ns, n)
	}
	t.Nameservers = ns
	if t.DnssecPolicyID != nil && *t.DnssecPolicyID == 0 {
		t.DnssecPolicyID = nil
	}
	var soa models.DnsSoaTemplate
	if tx.First(&soa, t.SoaTemplateID).Error != nil || !usableBy(soa.InstanceID, soa.Global, t.InstanceID) {
		return bad("pick an SOA template")
	}
	if t.Global && !soa.Global {
		return bad("a global DNS template needs a global SOA template")
	}
	dns := fwconfig.DNSServer{SOATemplates: []fwconfig.DNSSOATemplate{soaDoc(&soa)}}
	zt := fwconfig.DNSZoneTemplate{Name: t.Name, SOA: soa.Name, DefaultTTL: t.DefaultTtl, Nameservers: t.Nameservers.Names()}
	if t.DnssecPolicyID != nil {
		var k models.DnsDnssecPolicy
		if tx.First(&k, *t.DnssecPolicyID).Error != nil || !usableBy(k.InstanceID, k.Global, t.InstanceID) {
			return bad("DNSSEC policy does not exist")
		}
		if t.Global && !k.Global {
			return bad("a global DNS template needs a global DNSSEC policy")
		}
		dns.DNSSECPolicies = []fwconfig.DNSSECPolicy{dnssecDoc(&k)}
		zt.DNSSECPolicy = k.Name
	}
	dns.ZoneTemplates = []fwconfig.DNSZoneTemplate{zt}
	return checkDNS(dns)
}

// usedBy refuses a delete while rows of model still refer to id through
// column, naming them.
func usedBy(tx *gorm.DB, what string, model any, column string, id uint, name func() []string) error {
	var n int64
	if err := tx.Model(model).Where(column+" = ?", id).Count(&n).Error; err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	names := name()
	if len(names) > 5 {
		names = append(names[:5], "...")
	}
	return bad(fmt.Sprintf("%s is used by %s", what, strings.Join(names, ", ")))
}

func templateNames(tx *gorm.DB, column string, id uint) func() []string {
	return func() []string {
		var names []string
		tx.Model(&models.DnsTemplate{}).Where(column+" = ?", id).Order("name").Pluck("name", &names)
		for i := range names {
			names[i] = "DNS template " + names[i]
		}
		return names
	}
}

func deleteDnsSoaTemplate(tx *gorm.DB, s *models.DnsSoaTemplate) error {
	return usedBy(tx, s.Name, &models.DnsTemplate{}, "soa_template_id", s.ID, templateNames(tx, "soa_template_id", s.ID))
}

func deleteDnsDnssecPolicy(tx *gorm.DB, k *models.DnsDnssecPolicy) error {
	return usedBy(tx, k.Name, &models.DnsTemplate{}, "dnssec_policy_id", k.ID, templateNames(tx, "dnssec_policy_id", k.ID))
}

func deleteDnsTemplate(tx *gorm.DB, t *models.DnsTemplate) error {
	return usedBy(tx, t.Name, &models.DnsZone{}, "dns_template_id", t.ID, zoneNames(tx, t.ID))
}

func zoneNames(tx *gorm.DB, templateID uint) func() []string {
	return func() []string {
		var names []string
		tx.Model(&models.DnsZone{}).Where("dns_template_id = ?", templateID).Order("name").Pluck("name", &names)
		for i := range names {
			names[i] = "zone " + names[i]
		}
		return names
	}
}
