// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

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
		return bad("instance does not exist")
	}
	return nil
}

// zoneIn checks that an optional zone reference belongs to the instance.
func zoneIn(tx *gorm.DB, zoneID *uint, instanceID uint, field string) error {
	if zoneID == nil {
		return nil
	}
	var z models.Zone
	if tx.First(&z, *zoneID).Error != nil || z.InstanceID != instanceID {
		return bad(field + " must be a zone of the same instance")
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

func checkCIDRs(field string, list models.StringList) error {
	for _, s := range list {
		if _, err := netip.ParsePrefix(s); err != nil {
			return bad(fmt.Sprintf("%s: %q is not a CIDR (e.g. 192.168.1.0/24)", field, s))
		}
	}
	return nil
}

func prepareInstance(tx *gorm.DB, in, old *models.Instance) error {
	in.Name = strings.TrimSpace(in.Name)
	if !fwconfig.ValidInstanceName(in.Name) {
		return bad("name: lowercase letters and digits, starting with a letter, at most 12 characters")
	}
	in.DnsForwarders = cleanList(in.DnsForwarders)
	in.DnsAllowRecursion = cleanList(in.DnsAllowRecursion)
	if err := checkEntries(tx, "DNS forwarders", in.DnsForwarders, entryHost); err != nil {
		return err
	}
	if err := checkEntries(tx, "allow recursion", in.DnsAllowRecursion, entryCIDR); err != nil {
		return err
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
	if in.IsDefault {
		// Exactly one default: taking the flag moves it here.
		if err := tx.Model(&models.Instance{}).Where("is_default AND id <> ?", in.ID).Update("is_default", false).Error; err != nil {
			return err
		}
	} else if old != nil && old.IsDefault {
		return bad("mark another instance as default instead")
	} else {
		var n int64
		tx.Model(&models.Instance{}).Where("is_default").Count(&n)
		if n == 0 {
			in.IsDefault = true // the first instance is the default
		}
	}
	return nil
}

func prepareZone(tx *gorm.DB, z, old *models.Zone) error {
	if err := instanceExists(tx, z.InstanceID); err != nil {
		return err
	}
	if old != nil && old.InstanceID != z.InstanceID {
		return bad("a zone cannot move to another instance")
	}
	z.Name = strings.TrimSpace(z.Name)
	if !fwconfig.ValidZoneName(z.Name) {
		return bad("name: lowercase letters, digits and _, starting with a letter, at most 24 characters")
	}
	if z.InputPolicy == "" {
		z.InputPolicy = fwconfig.ActionDrop
	}
	return oneOf("input policy", z.InputPolicy, fwconfig.ActionAccept, fwconfig.ActionDrop, fwconfig.ActionReject)
}

func prepareInterface(tx *gorm.DB, i, old *models.Interface) error {
	if err := instanceExists(tx, i.InstanceID); err != nil {
		return err
	}
	i.Name = strings.TrimSpace(i.Name)
	if !fwconfig.ValidIfname(i.Name) || i.Name == "lo" {
		return bad("name: a Linux interface name (at most 15 characters, no spaces)")
	}
	if i.Kind == "" {
		i.Kind = fwconfig.KindPhysical
	}
	if err := oneOf("kind", i.Kind, fwconfig.KindPhysical, fwconfig.KindVLAN, fwconfig.KindBridge, fwconfig.KindWireGuard); err != nil {
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
	if err := zoneIn(tx, i.ZoneID, i.InstanceID, "zone"); err != nil {
		return err
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
	if p.Keepalive < 0 || p.Keepalive > 65535 {
		return bad("keepalive must be 0-65535")
	}
	return nil
}

func presentWgPeer(p *models.WgPeer) {
	p.HasPresharedKey = p.PresharedKey != ""
	p.HasClientKey = p.ClientPrivateKey != ""
}

func prepareLink(tx *gorm.DB, l, _ *models.Link) error {
	l.Name = strings.TrimSpace(l.Name)
	if !fwconfig.ValidZoneName(l.Name) {
		return bad("name: lowercase letters, digits and _, at most 24 characters")
	}
	if l.InstanceAID == l.InstanceBID {
		return bad("a link connects two different instances")
	}
	for _, end := range []struct {
		inst  uint
		iface string
		zone  *uint
		addrs *models.StringList
		label string
	}{
		{l.InstanceAID, l.InterfaceA, l.ZoneAID, &l.AddressesA, "side A"},
		{l.InstanceBID, l.InterfaceB, l.ZoneBID, &l.AddressesB, "side B"},
	} {
		if err := instanceExists(tx, end.inst); err != nil {
			return bad(end.label + ": instance does not exist")
		}
		if !fwconfig.ValidIfname(end.iface) {
			return bad(end.label + ": interface name is required")
		}
		if err := zoneIn(tx, end.zone, end.inst, end.label+" zone"); err != nil {
			return err
		}
		*end.addrs = cleanList(*end.addrs)
		if err := checkCIDRs(end.label+" addresses", *end.addrs); err != nil {
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
			return bad("interface must belong to the same instance")
		}
	}
	if r.Gateway == "" && r.InterfaceID == nil {
		return bad("a route needs a gateway or an interface")
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
	if err := oneOf("action", r.Action, fwconfig.ActionAccept, fwconfig.ActionDrop, fwconfig.ActionReject); err != nil {
		return err
	}
	if err := oneOf("family", r.Family, "", "ipv4", "ipv6"); err != nil {
		return err
	}
	if err := oneOf("protocol", r.Protocol, "", "tcp", "udp", "icmp", "icmpv6"); err != nil {
		return err
	}
	if r.Chain == fwconfig.ChainInput {
		r.DstZoneID = nil
	}
	if r.Chain == fwconfig.ChainOutput {
		r.SrcZoneID = nil
	}
	if err := zoneIn(tx, r.SrcZoneID, r.InstanceID, "source zone"); err != nil {
		return err
	}
	if err := zoneIn(tx, r.DstZoneID, r.InstanceID, "destination zone"); err != nil {
		return err
	}
	r.SrcAddrs, r.DstAddrs = cleanList(r.SrcAddrs), cleanList(r.DstAddrs)
	if err := checkEntries(tx, "source", r.SrcAddrs, entryAny); err != nil {
		return err
	}
	if err := checkEntries(tx, "destination", r.DstAddrs, entryAny); err != nil {
		return err
	}
	r.DstPorts = strings.TrimSpace(r.DstPorts)
	if r.DstPorts != "" {
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return bad("ports need protocol tcp or udp")
		}
		if _, err := fwconfig.ParsePorts(r.DstPorts); err != nil {
			return bad(err.Error())
		}
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
	if err := oneOf("protocol", n.Protocol, "", "tcp", "udp"); err != nil {
		return err
	}
	if n.Kind == fwconfig.NATDNAT {
		n.OutZoneID = nil
	} else {
		n.InZoneID = nil
	}
	if err := zoneIn(tx, n.InZoneID, n.InstanceID, "incoming zone"); err != nil {
		return err
	}
	if err := zoneIn(tx, n.OutZoneID, n.InstanceID, "outgoing zone"); err != nil {
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
	if n.DstPorts != "" {
		if n.Protocol == "" {
			return bad("ports need protocol tcp or udp")
		}
		if _, err := fwconfig.ParsePorts(n.DstPorts); err != nil {
			return bad(err.Error())
		}
	}
	if n.ToPort != 0 && n.Protocol == "" {
		return bad("a target port needs protocol tcp or udp")
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
	ip, err := netip.ParseAddr(strings.TrimSpace(a.Address))
	if err != nil {
		return bad("address must be a plain IP address (the prefix length comes from the IPAM prefix)")
	}
	a.Address = ip.String()
	if a.InterfaceID != nil {
		var i models.Interface
		if tx.First(&i, *a.InterfaceID).Error != nil || i.InstanceID != a.InstanceID {
			return bad("interface must belong to the same instance")
		}
	}
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

func prepareDnsZone(tx *gorm.DB, z, _ *models.DnsZone) error {
	if err := instanceExists(tx, z.InstanceID); err != nil {
		return err
	}
	if z.Type == "" {
		z.Type = fwconfig.ZoneForward
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
	default:
		return oneOf("type", z.Type, fwconfig.ZoneForward, fwconfig.ZoneReverse4, fwconfig.ZoneReverse6)
	}
	if z.DnsTemplateID != nil && *z.DnsTemplateID == 0 {
		z.DnsTemplateID = nil
	}
	if z.DnsTemplateID != nil {
		var n int64
		tx.Model(&models.DnsTemplate{}).Where("id = ?", *z.DnsTemplateID).Count(&n)
		if n == 0 {
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
		return bad("records go in forward zones; reverse zones are generated")
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

func prepareDnsSoaTemplate(_ *gorm.DB, s, _ *models.DnsSoaTemplate) error {
	s.Name = strings.TrimSpace(s.Name)
	s.Mname = dnsName(s.Mname)
	// Accept the mailbox written as an e-mail address.
	s.Rname = strings.Replace(dnsName(s.Rname), "@", ".", 1)
	return checkDNS(fwconfig.DNSServer{SOATemplates: []fwconfig.DNSSOATemplate{soaDoc(s)}})
}

func prepareDnsDnssecPolicy(_ *gorm.DB, k, _ *models.DnsDnssecPolicy) error {
	for _, f := range []*string{&k.Name, &k.KskLifetime, &k.KskAlgorithm, &k.ZskLifetime, &k.ZskAlgorithm,
		&k.PurgeKeys, &k.SignaturesValidity, &k.SignaturesValidityDnskey, &k.SignaturesRefresh} {
		*f = strings.TrimSpace(*f)
	}
	return checkDNS(fwconfig.DNSServer{DNSSECPolicies: []fwconfig.DNSSECPolicy{dnssecDoc(k)}})
}

func prepareDnsTemplate(tx *gorm.DB, t, _ *models.DnsTemplate) error {
	t.Name = strings.TrimSpace(t.Name)
	ns := models.StringList{}
	for _, n := range cleanList(t.Nameservers) {
		ns = append(ns, dnsName(n))
	}
	t.Nameservers = ns
	if t.DnssecPolicyID != nil && *t.DnssecPolicyID == 0 {
		t.DnssecPolicyID = nil
	}
	var soa models.DnsSoaTemplate
	if tx.First(&soa, t.SoaTemplateID).Error != nil {
		return bad("pick an SOA template")
	}
	dns := fwconfig.DNSServer{SOATemplates: []fwconfig.DNSSOATemplate{soaDoc(&soa)}}
	zt := fwconfig.DNSZoneTemplate{Name: t.Name, SOA: soa.Name, DefaultTTL: t.DefaultTtl, Nameservers: t.Nameservers}
	if t.DnssecPolicyID != nil {
		var k models.DnsDnssecPolicy
		if tx.First(&k, *t.DnssecPolicyID).Error != nil {
			return bad("DNSSEC policy does not exist")
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
	return usedBy(tx, t.Name, &models.DnsZone{}, "dns_template_id", t.ID, func() []string {
		var names []string
		tx.Model(&models.DnsZone{}).Where("dns_template_id = ?", t.ID).Order("name").Pluck("name", &names)
		for i := range names {
			names[i] = "zone " + names[i]
		}
		return names
	})
}
