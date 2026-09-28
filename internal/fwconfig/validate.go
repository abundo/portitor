// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	// Instance names become netns names ("fw-" + name) and path segments.
	instanceNameRe = regexp.MustCompile(`^[a-z][a-z0-9]{0,11}$`)
	// Linux IFNAMSIZ is 16 including the NUL.
	ifnameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
	// Interface zone and link names.
	zoneNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,23}$`)
	peerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9 _.@-]{0,62}$`)
	dnsLabelRe = regexp.MustCompile(`^(\*|@|[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?)$`)
	hostRe     = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
	macRe      = regexp.MustCompile(`^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$`)
	// DNS template and DNSSEC policy names become dnsmgr2 template keys
	// and a quoted string in named.conf.
	dnsTemplateNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
	// BIND durations: ISO 8601 (P1Y, PT12H) or TTL style (30d, 1w2d).
	durationRe = regexp.MustCompile(`^([0-9]+[smhdwSMHDW]?)+$|^[Pp]([0-9]+[YyMmWwDd])*([Tt]([0-9]+[HhMmSs])+)?$`)
)

// BIND's own dnssec-policy names, which can't be redefined.
var builtinDNSSECPolicies = []string{"default", "insecure", "none"}

// ValidationError collects every problem found, so the GUI can show them
// all at once instead of one per deploy attempt.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return "invalid configuration: " + strings.Join(e.Problems, "; ")
}

type validator struct {
	problems []string
	// lists holds the names of the document's IP lists.
	lists map[string]bool
	// ruleIDs holds the rule IDs seen so far, document wide.
	ruleIDs map[uint32]bool
}

func (v *validator) addf(format string, args ...any) {
	v.problems = append(v.problems, fmt.Sprintf(format, args...))
}

// Validate checks the whole document. It is run by portitor-web before
// sending and again by portitor-agent before rendering; the agent must not
// trust its input, since every string ends up in a root-owned config file.
func (d *Document) Validate() error {
	v := &validator{lists: map[string]bool{}, ruleIDs: map[uint32]bool{}}
	if d.Version != Version {
		v.addf("unsupported document version %d (want %d)", d.Version, Version)
	}
	exp := d.Expand()
	v.ipLists(d.IPLists)
	v.tasks(d.Tasks)

	defaults := 0
	instNames := map[string]bool{}
	ifaceOwner := map[string]string{} // physical interfaces must be in one instance only
	for i := range exp.Instances {
		in := &exp.Instances[i]
		if !instanceNameRe.MatchString(in.Name) {
			v.addf("instance %q: name must match %s", in.Name, instanceNameRe)
		}
		if instNames[in.Name] {
			v.addf("instance %q: duplicate name", in.Name)
		}
		instNames[in.Name] = true
		if in.Default {
			defaults++
		}
		v.instance(in, ifaceOwner)
	}
	if len(exp.Instances) > 0 && defaults != 1 {
		v.addf("exactly one instance must be the default, found %d", defaults)
	}

	linkNames := map[string]bool{}
	for _, l := range d.Links {
		if !zoneNameRe.MatchString(l.Name) {
			v.addf("link %q: name must match %s", l.Name, zoneNameRe)
		}
		if linkNames[l.Name] {
			v.addf("link %q: duplicate name", l.Name)
		}
		linkNames[l.Name] = true
		for _, end := range []LinkEnd{l.A, l.B} {
			if !instNames[end.Instance] {
				v.addf("link %q: unknown instance %q", l.Name, end.Instance)
			}
		}
		if l.A.Instance == l.B.Instance {
			v.addf("link %q: both ends are in instance %q", l.Name, l.A.Instance)
		}
	}

	if len(v.problems) > 0 {
		return &ValidationError{Problems: v.problems}
	}
	return nil
}

func (v *validator) instance(in *Instance, ifaceOwner map[string]string) {
	p := "instance " + in.Name

	ifaces := map[string]*Interface{}
	for i := range in.Interfaces {
		ifc := &in.Interfaces[i]
		ip := fmt.Sprintf("%s: interface %q", p, ifc.Name)
		if !ifnameRe.MatchString(ifc.Name) {
			v.addf("%s: name must match %s", ip, ifnameRe)
		}
		if ifc.Name == "lo" {
			v.addf("%s: loopback is managed automatically", ip)
		}
		if ifaces[ifc.Name] != nil {
			v.addf("%s: duplicate", ip)
		}
		ifaces[ifc.Name] = ifc
		if owner, ok := ifaceOwner[ifc.Name]; ok && ifc.Kind == KindPhysical {
			v.addf("%s: already used by instance %s", ip, owner)
		}
		if ifc.Kind == KindPhysical {
			ifaceOwner[ifc.Name] = in.Name
		}
		checkComment(v, ip, ifc.Description)
		if ifc.MTU != 0 && (ifc.MTU < 576 || ifc.MTU > 65535) {
			v.addf("%s: mtu %d out of range", ip, ifc.MTU)
		}
		switch ifc.IPv4Mode {
		case ModeStatic, ModeNone:
		case ModeDHCP:
			if ifc.Kind == KindWireGuard || ifc.Kind == KindLink {
				v.addf("%s: dhcp client is not supported on %s interfaces", ip, ifc.Kind)
			}
		default:
			v.addf("%s: invalid ipv4 mode %q", ip, ifc.IPv4Mode)
		}
		for _, a := range ifc.Addresses {
			pfx, err := netip.ParsePrefix(a)
			if err != nil {
				v.addf("%s: address %q: %v", ip, a, err)
				continue
			}
			if pfx.Addr().Is4() && ifc.IPv4Mode == ModeDHCP {
				v.addf("%s: static IPv4 address %s together with dhcp", ip, a)
			}
		}
		switch ifc.Kind {
		case KindPhysical, KindLink:
		case KindVLAN:
			if ifc.VLANID < 1 || ifc.VLANID > 4094 {
				v.addf("%s: vlan id %d out of range", ip, ifc.VLANID)
			}
			if !ifnameRe.MatchString(ifc.Parent) {
				v.addf("%s: invalid parent %q", ip, ifc.Parent)
			}
		case KindBridge:
			for _, m := range ifc.Members {
				if !ifnameRe.MatchString(m) {
					v.addf("%s: invalid bridge member %q", ip, m)
				}
			}
		case KindWireGuard:
			v.wireguard(ip, ifc.WireGuard)
		default:
			v.addf("%s: invalid kind %q", ip, ifc.Kind)
		}
	}
	for _, ifc := range in.Interfaces {
		if ifc.Kind == KindVLAN && ifaces[ifc.Parent] == nil {
			v.addf("%s: interface %q: parent %q is not in this instance", p, ifc.Name, ifc.Parent)
		}
		for _, m := range ifc.Members {
			if ifaces[m] == nil {
				v.addf("%s: bridge %q: member %q is not in this instance", p, ifc.Name, m)
			}
		}
	}

	zones := map[string]bool{}
	for _, z := range in.InterfaceZones {
		zp := fmt.Sprintf("%s: interface zone %q", p, z.Name)
		if !zoneNameRe.MatchString(z.Name) {
			v.addf("%s: name must match %s", zp, zoneNameRe)
		}
		if zones[z.Name] {
			v.addf("%s: duplicate", zp)
		}
		if ifaces[z.Name] != nil {
			v.addf("%s: an interface has the same name", zp)
		}
		zones[z.Name] = true
		seen := map[string]bool{}
		for _, m := range z.Interfaces {
			if ifaces[m] == nil {
				v.addf("%s: member %q is not an interface of this instance", zp, m)
			}
			if seen[m] {
				v.addf("%s: member %q listed twice", zp, m)
			}
			seen[m] = true
		}
	}
	// ifaceRefs checks a rule's interface list: interface or zone names.
	ifaceRefs := func(where string, list []string) {
		for _, name := range list {
			if ifaces[name] == nil && !zones[name] {
				v.addf("%s: unknown interface or interface zone %q", where, name)
			}
		}
	}

	for i, r := range in.Rules {
		rp := fmt.Sprintf("%s: rule %d", p, i+1)
		switch r.Chain {
		case ChainInput, ChainForward, ChainOutput:
		default:
			v.addf("%s: invalid chain %q", rp, r.Chain)
		}
		if r.Kind == RuleKindComment {
			if len(r.InInterfaces)+len(r.OutInterfaces)+len(r.SrcAddrs)+len(r.DstAddrs) > 0 ||
				r.Family != "" || r.Protocol != "" || r.DstPorts != "" || r.Action != "" || r.Log || r.ID != 0 {
				v.addf("%s: a comment has only a chain and a description", rp)
			}
			checkComment(v, rp, r.Description)
			continue
		}
		if r.Kind != "" {
			v.addf("%s: invalid kind %q", rp, r.Kind)
		}
		if r.ID != 0 {
			if v.ruleIDs[r.ID] {
				v.addf("%s: duplicate id %d", rp, r.ID)
			}
			v.ruleIDs[r.ID] = true
		}
		if r.Chain == ChainOutput && len(r.InInterfaces) > 0 {
			v.addf("%s: output rules have no incoming interface", rp)
		}
		if r.Chain == ChainInput && len(r.OutInterfaces) > 0 {
			v.addf("%s: input rules have no outgoing interface", rp)
		}
		ifaceRefs(rp, r.InInterfaces)
		ifaceRefs(rp, r.OutInterfaces)
		if !validAction(r.Action) {
			v.addf("%s: invalid action %q", rp, r.Action)
		}
		v.match(rp, r.Family, r.Protocol, r.SrcAddrs, r.DstAddrs, r.DstPorts, true)
		checkComment(v, rp, r.Description)
	}

	for i, n := range in.NAT {
		np := fmt.Sprintf("%s: nat rule %d", p, i+1)
		ifaceRefs(np, n.InInterfaces)
		ifaceRefs(np, n.OutInterfaces)
		v.match(np, "", n.Protocol, n.SrcAddrs, n.DstAddrs, n.DstPorts, false)
		checkComment(v, np, n.Description)
		switch n.Kind {
		case NATMasquerade:
			if n.ToAddr != "" {
				v.addf("%s: masquerade takes no target address", np)
			}
		case NATSNAT, NATDNAT:
			if _, err := netip.ParseAddr(n.ToAddr); err != nil {
				v.addf("%s: invalid target address %q", np, n.ToAddr)
				break
			}
			if len(MatchFamilies(AddrFamily(n.ToAddr), n.Protocol, n.SrcAddrs, n.DstAddrs)) == 0 {
				v.addf("%s: match addresses and target %s differ in family", np, n.ToAddr)
			}
		default:
			v.addf("%s: invalid kind %q", np, n.Kind)
		}
		if n.ToPort < 0 || n.ToPort > 65535 {
			v.addf("%s: invalid target port %d", np, n.ToPort)
		}
		if n.ToPort != 0 && n.Protocol != "tcp" && n.Protocol != "udp" {
			v.addf("%s: a target port needs protocol tcp or udp", np)
		}
		if n.Kind == NATDNAT && len(n.OutInterfaces) > 0 {
			v.addf("%s: dnat matches the incoming interface, not outgoing", np)
		}
		if n.Kind != NATDNAT && len(n.InInterfaces) > 0 {
			v.addf("%s: %s matches the outgoing interface, not incoming", np, n.Kind)
		}
	}

	for i, r := range in.Routes {
		rp := fmt.Sprintf("%s: route %d", p, i+1)
		if r.Destination != "default" {
			if _, err := netip.ParsePrefix(r.Destination); err != nil {
				v.addf("%s: invalid destination %q", rp, r.Destination)
			}
		}
		if r.Gateway != "" {
			if _, err := netip.ParseAddr(r.Gateway); err != nil {
				v.addf("%s: invalid gateway %q", rp, r.Gateway)
			} else if r.Destination != "default" && AddrFamily(r.Destination) != "" && AddrFamily(r.Destination) != AddrFamily(r.Gateway) {
				v.addf("%s: destination %s and gateway %s differ in family", rp, r.Destination, r.Gateway)
			}
		}
		if r.Interface != "" && ifaces[r.Interface] == nil {
			v.addf("%s: unknown interface %q", rp, r.Interface)
		}
		if r.Gateway == "" && r.Interface == "" {
			v.addf("%s: needs a gateway or an interface", rp)
		}
		if r.Metric < 0 {
			v.addf("%s: negative metric", rp)
		}
	}

	raOn := map[string]bool{}
	for _, ra := range in.RA {
		rp := fmt.Sprintf("%s: router advertisements on %q", p, ra.Interface)
		if ifaces[ra.Interface] == nil {
			v.addf("%s: unknown interface", rp)
		}
		if raOn[ra.Interface] {
			v.addf("%s: duplicate", rp)
		}
		raOn[ra.Interface] = true
		for _, rpfx := range ra.Prefixes {
			pfx, err := netip.ParsePrefix(rpfx.Prefix)
			if err != nil || !pfx.Addr().Is6() || pfx != pfx.Masked() {
				v.addf("%s: invalid IPv6 prefix %q", rp, rpfx.Prefix)
				continue
			}
			if rpfx.Autonomous && pfx.Bits() != 64 {
				v.addf("%s: SLAAC on %s needs a /64", rp, rpfx.Prefix)
			}
		}
		for _, a := range ra.RDNSS {
			if addr, err := netip.ParseAddr(a); err != nil || !addr.Is6() {
				v.addf("%s: invalid IPv6 dns server %q", rp, a)
			}
		}
		for _, d := range ra.DNSSL {
			if !validDomain(d) {
				v.addf("%s: invalid search domain %q", rp, d)
			}
		}
	}

	if in.DHCP.DomainName != "" && !validDomain(in.DHCP.DomainName) {
		v.addf("%s: dhcp: invalid domain name %q", p, in.DHCP.DomainName)
	}
	for _, s := range in.DHCP.Subnets {
		sp := fmt.Sprintf("%s: dhcp subnet %s", p, s.Prefix)
		pfx, err := netip.ParsePrefix(s.Prefix)
		if err != nil {
			v.addf("%s: %v", sp, err)
			continue
		}
		if ifaces[s.Interface] == nil {
			v.addf("%s: unknown interface %q", sp, s.Interface)
		}
		for _, a := range []string{s.RangeStart, s.RangeEnd, s.Gateway} {
			if a == "" {
				continue
			}
			addr, err := netip.ParseAddr(a)
			if err != nil || !pfx.Contains(addr) {
				v.addf("%s: address %q is not inside the prefix", sp, a)
			}
		}
		if (s.RangeStart == "") != (s.RangeEnd == "") {
			v.addf("%s: range needs both start and end", sp)
		}
		for _, a := range s.DNSServers {
			if addr, err := netip.ParseAddr(a); err != nil {
				v.addf("%s: invalid dns server %q", sp, a)
			} else if addr.Is4() != pfx.Addr().Is4() {
				v.addf("%s: dns server %s is not of the prefix's IP version", sp, a)
			}
		}
		if pfx.Addr().Is6() {
			if s.Gateway != "" {
				v.addf("%s: IPv6 clients learn the gateway from router advertisements, not DHCP", sp)
			}
			if !raOn[s.Interface] {
				v.addf("%s: DHCPv6 needs router advertisements on %s", sp, s.Interface)
			}
		}
	}

	v.dyndns(p, in, ifaces)

	switch in.DNS.ForwardMode {
	case "", ForwardFirst, ForwardOnly, ForwardOff:
	default:
		v.addf("%s: dns: invalid forward mode %q", p, in.DNS.ForwardMode)
	}
	for _, a := range in.DNS.Forwarders {
		if _, err := netip.ParseAddr(a); err != nil {
			v.addf("%s: dns: invalid forwarder %q", p, a)
		}
	}
	for _, a := range in.DNS.AllowRecursion {
		if _, err := netip.ParsePrefix(a); err != nil {
			v.addf("%s: dns: invalid allow-recursion prefix %q", p, a)
		}
	}
	for _, name := range in.DNS.ListenInterfaces {
		if ifaces[name] == nil {
			v.addf("%s: dns: unknown listen interface %q", p, name)
		}
	}
	zoneNames := map[string]bool{}
	for _, z := range in.DNS.Zones {
		zp := fmt.Sprintf("%s: dns zone %q", p, z.Name)
		if zoneNames[z.Name] {
			v.addf("%s: duplicate", zp)
		}
		zoneNames[z.Name] = true
		switch z.Type {
		case ZoneForward:
			if !validDomain(z.Name) {
				v.addf("%s: invalid domain name", zp)
			}
		case ZoneReverse4, ZoneReverse6:
			pfx, err := netip.ParsePrefix(z.Name)
			if err != nil || pfx.Addr().Is4() != (z.Type == ZoneReverse4) {
				v.addf("%s: reverse zone name must be a matching CIDR", zp)
			}
			if len(z.Records) > 0 {
				v.addf("%s: reverse zones are generated from forward records", zp)
			}
		default:
			v.addf("%s: invalid type %q", zp, z.Type)
		}
		for _, r := range z.Records {
			v.dnsRecord(zp, r)
		}
		if z.Template != "" && in.DNS.ZoneTemplate(z.Template) == nil {
			v.addf("%s: unknown template %q", zp, z.Template)
		}
	}
	v.dnsTemplates(p, &in.DNS)
}

func (v *validator) dnsTemplates(p string, d *DNSServer) {
	name := func(what, n string, seen map[string]bool) {
		if !dnsTemplateNameRe.MatchString(n) {
			v.addf("%s: dns %s %q: name must match %s", p, what, n, dnsTemplateNameRe)
		}
		if seen[n] {
			v.addf("%s: dns %s %q: duplicate", p, what, n)
		}
		seen[n] = true
	}
	ttl := func(tp, field string, n, lo int64) {
		if n < lo || n > 2147483647 {
			v.addf("%s: %s must be between %d and 2147483647", tp, field, lo)
		}
	}

	soas := map[string]bool{}
	for _, s := range d.SOATemplates {
		sp := fmt.Sprintf("%s: dns soa template %q", p, s.Name)
		name("soa template", s.Name, soas)
		if !validDomain(s.MName) {
			v.addf("%s: invalid primary nameserver %q", sp, s.MName)
		}
		if !validDomain(s.RName) {
			v.addf("%s: invalid mailbox %q (write hostmaster.example.com)", sp, s.RName)
		}
		ttl(sp, "refresh", s.Refresh, 1)
		ttl(sp, "retry", s.Retry, 1)
		ttl(sp, "expire", s.Expire, 1)
		ttl(sp, "minimum", s.Minimum, 0)
	}

	policies := map[string]bool{}
	for _, k := range d.DNSSECPolicies {
		kp := fmt.Sprintf("%s: dnssec policy %q", p, k.Name)
		name("dnssec policy", k.Name, policies)
		if slices.Contains(builtinDNSSECPolicies, strings.ToLower(k.Name)) {
			v.addf("%s: %q is a built-in BIND policy name", kp, k.Name)
		}
		for field, alg := range map[string]string{"ksk algorithm": k.KSKAlgorithm, "zsk algorithm": k.ZSKAlgorithm} {
			if !slices.Contains(DNSSECAlgorithms, alg) {
				v.addf("%s: %s must be one of %s", kp, field, strings.Join(DNSSECAlgorithms, ", "))
			}
		}
		for field, dur := range map[string]string{
			"ksk lifetime": k.KSKLifetime, "zsk lifetime": k.ZSKLifetime, "purge-keys": k.PurgeKeys,
			"signatures-validity": k.SignaturesValidity, "signatures-validity-dnskey": k.SignaturesValidityDNSKEY,
			"signatures-refresh": k.SignaturesRefresh,
		} {
			if dur == "" || (strings.HasSuffix(field, "lifetime") && dur == "unlimited") {
				continue
			}
			if !durationRe.MatchString(dur) || strings.EqualFold(dur, "P") {
				v.addf("%s: invalid %s %q (want e.g. P1Y or 30d)", kp, field, dur)
			}
		}
	}

	templates := map[string]bool{}
	for _, t := range d.ZoneTemplates {
		tp := fmt.Sprintf("%s: dns template %q", p, t.Name)
		name("template", t.Name, templates)
		if !soas[t.SOA] {
			v.addf("%s: unknown soa template %q", tp, t.SOA)
		}
		if t.DNSSECPolicy != "" && !policies[t.DNSSECPolicy] {
			v.addf("%s: unknown dnssec policy %q", tp, t.DNSSECPolicy)
		}
		ttl(tp, "default ttl", t.DefaultTTL, 1)
		if len(t.Nameservers) == 0 {
			v.addf("%s: needs at least one nameserver", tp)
		}
		for _, ns := range t.Nameservers {
			if !validDomain(ns) {
				v.addf("%s: invalid nameserver %q", tp, ns)
			}
		}
	}
}

func (v *validator) wireguard(p string, wg *WireGuard) {
	if wg == nil {
		v.addf("%s: wireguard settings missing", p)
		return
	}
	if !validWGKey(wg.PrivateKey) {
		v.addf("%s: invalid private key", p)
	}
	if wg.ListenPort < 0 || wg.ListenPort > 65535 {
		v.addf("%s: invalid listen port %d", p, wg.ListenPort)
	}
	keys := map[string]bool{}
	for _, peer := range wg.Peers {
		pp := fmt.Sprintf("%s: peer %q", p, peer.Name)
		if !peerNameRe.MatchString(peer.Name) {
			v.addf("%s: invalid name", pp)
		}
		if !validWGKey(peer.PublicKey) {
			v.addf("%s: invalid public key", pp)
		}
		if keys[peer.PublicKey] {
			v.addf("%s: duplicate public key", pp)
		}
		keys[peer.PublicKey] = true
		if peer.PresharedKey != "" && !validWGKey(peer.PresharedKey) {
			v.addf("%s: invalid preshared key", pp)
		}
		if peer.Endpoint != "" && !validEndpoint(peer.Endpoint) {
			v.addf("%s: invalid endpoint %q (want host:port)", pp, peer.Endpoint)
		}
		for _, a := range peer.AllowedIPs {
			if _, err := netip.ParsePrefix(a); err != nil {
				v.addf("%s: invalid allowed ip %q", pp, a)
			}
		}
		if peer.Keepalive < 0 || peer.Keepalive > 65535 {
			v.addf("%s: invalid keepalive %d", pp, peer.Keepalive)
		}
	}
}

// match checks a rule's match fields; with lists, addresses may refer to
// IP lists.
func (v *validator) match(p, family, proto string, src, dst []string, ports string, lists bool) {
	switch family {
	case "", "ipv4", "ipv6":
	default:
		v.addf("%s: invalid family %q", p, family)
	}
	switch proto {
	case "", "tcp", "udp", "icmp", "icmpv6":
	default:
		v.addf("%s: invalid protocol %q", p, proto)
	}
	valid := true
	for _, list := range [][]string{src, dst} {
		for _, a := range list {
			if name, ok := IPListName(a); ok {
				if !lists {
					v.addf("%s: ip list %q: only filter rules can use ip lists", p, name)
					valid = false
				} else if !v.lists[name] {
					v.addf("%s: unknown ip list %q", p, name)
					valid = false
				}
			} else if _, err := ParseAddrOrPrefix(a); err != nil {
				v.addf("%s: invalid address %q", p, a)
				valid = false
			}
		}
	}
	if (family == "ipv4" && proto == "icmpv6") || (family == "ipv6" && proto == "icmp") {
		v.addf("%s: protocol %s does not match family %s", p, proto, family)
	} else if valid && len(MatchFamilies(family, proto, src, dst)) == 0 {
		v.addf("%s: no IP version fits the source and destination addresses, family and protocol together", p)
	}
	if ports != "" {
		if proto != "tcp" && proto != "udp" {
			v.addf("%s: ports need protocol tcp or udp", p)
		}
		if _, err := ParsePorts(ports); err != nil {
			v.addf("%s: %v", p, err)
		}
	}
}

func (v *validator) dnsRecord(p string, r DNSRecord) {
	rp := fmt.Sprintf("%s: record %s %s", p, r.Name, r.Type)
	for _, label := range strings.Split(strings.TrimSuffix(r.Name, "."), ".") {
		if !dnsLabelRe.MatchString(label) {
			v.addf("%s: invalid name", rp)
			break
		}
	}
	if r.TTL < 0 {
		v.addf("%s: negative ttl", rp)
	}
	if strings.ContainsAny(r.Value, "\n\r") {
		v.addf("%s: value contains a newline", rp)
	}
	switch r.Type {
	case "A":
		if a, err := netip.ParseAddr(r.Value); err != nil || !a.Is4() {
			v.addf("%s: invalid IPv4 address", rp)
		}
	case "AAAA":
		if a, err := netip.ParseAddr(r.Value); err != nil || !a.Is6() {
			v.addf("%s: invalid IPv6 address", rp)
		}
	case "CNAME", "NS", "PTR":
		if !validDomain(strings.TrimSuffix(r.Value, ".")) && !dnsLabelRe.MatchString(r.Value) {
			v.addf("%s: invalid target", rp)
		}
	case "MX", "TXT", "SRV", "CAA", "SSHFP", "TLSA":
		if r.Value == "" {
			v.addf("%s: empty value", rp)
		}
	default:
		v.addf("%s: unsupported type", rp)
	}
	if r.MAC != "" {
		if r.Type != "A" && r.Type != "AAAA" {
			v.addf("%s: mac only applies to A/AAAA", rp)
		}
		if !macRe.MatchString(r.MAC) {
			v.addf("%s: invalid mac %q", rp, r.MAC)
		}
	}
}

func checkComment(v *validator, p, s string) {
	if len(s) > 128 {
		v.addf("%s: description longer than 128 characters", p)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			v.addf("%s: description contains control characters", p)
			return
		}
	}
}

func validAction(a string) bool {
	return a == ActionAccept || a == ActionDrop || a == ActionReject
}

func validDomain(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "@" || label == "*" || !dnsLabelRe.MatchString(label) {
			return false
		}
	}
	return true
}

func validWGKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}

func validEndpoint(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	return hostRe.MatchString(host)
}

// ParseAddrOrPrefix accepts "192.0.2.1" or "192.0.2.0/24".
func ParseAddrOrPrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// PortRange is an inclusive port range; Lo == Hi for a single port.
type PortRange struct{ Lo, Hi int }

// ParsePorts parses "22", "80,443", "1000-2000,3000".
func ParsePorts(s string) ([]PortRange, error) {
	var out []PortRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
		}
		if a < 1 || b > 65535 || a > b {
			return nil, fmt.Errorf("invalid port range %q", part)
		}
		out = append(out, PortRange{a, b})
	}
	if len(out) == 0 {
		return nil, errors.New("empty port list")
	}
	return out, nil
}

// Name checks shared with portitor-web, so bad names are rejected when
// entered rather than at deploy time.

func ValidInstanceName(s string) bool { return instanceNameRe.MatchString(s) }
func ValidIfname(s string) bool       { return ifnameRe.MatchString(s) }
func ValidZoneName(s string) bool     { return zoneNameRe.MatchString(s) }
func ValidDomain(s string) bool       { return validDomain(s) }
func ValidWGKey(s string) bool        { return validWGKey(s) }
func ValidMAC(s string) bool          { return macRe.MatchString(s) }
func ValidEndpoint(s string) bool     { return validEndpoint(s) }
