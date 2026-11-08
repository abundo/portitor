// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package confcheck

import (
	"net/netip"
	"strconv"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/netobj"
)

// Filter and NAT rules, IPAM and DNS zones.

func init() {
	register("/instance/rule", hook{normalize: normalizeRule, check: checkRule})
	register("/instance/nat-rule", hook{normalize: normalizeNAT, check: checkNAT})
	register("/instance/ipam-prefix", hook{normalize: normalizeIpamPrefix, check: checkIpamPrefix})
	register("/instance/ipam-address", hook{check: checkIpamAddress})
	register("/instance/dns-zone", hook{normalize: normalizeDNSZone, check: checkDNSZone})
}

// predefined are the predefined services' names.
var predefined = func() map[string]bool {
	out := map[string]bool{}
	for _, s := range netobj.Predefined {
		out[s.Name] = true
	}
	return out
}()

func normalizeRule(c *Ctx, r *datastore.Node) error {
	if r.Leaf("kind") != "" {
		// A comment or group keeps only its chain, place and text.
		for name := range r.Leaves {
			switch name {
			case "id", "kind", "chain", "description":
			default:
				delete(r.Leaves, name)
			}
		}
		clear(r, "in-interfaces", "out-interfaces", "src-addrs", "dst-addrs", "services")
		return nil
	}
	for _, l := range []string{"in-interfaces", "out-interfaces", "services"} {
		if vs := r.LeafLists[l]; vs != nil {
			r.LeafLists[l] = dedupe(vs)
		}
	}
	switch r.Leaf("chain") {
	case fwconfig.ChainInput:
		clear(r, "out-interfaces")
	case fwconfig.ChainOutput:
		clear(r, "in-interfaces")
	}
	return nil
}

func checkRule(c *Ctx, r *datastore.Node) []error {
	if r.Leaf("kind") != "" {
		return nil
	}
	in := instanceOf(r)
	errs := checkIfaceList(c, in, "in-interfaces", r.LeafLists["in-interfaces"])
	errs = append(errs, checkIfaceList(c, in, "out-interfaces", r.LeafLists["out-interfaces"])...)
	errs = append(errs, checkServices(c, r)...)
	errs = append(errs, checkIPListRefs(c, r, "src-addrs", "dst-addrs")...)
	action := r.Leaf("action")
	var limit *datastore.Node
	if name := r.Leaf("rate-limit"); name != "" {
		limit = in.Entry("rate-limit", []string{name})
		if limit != nil && (on(limit, "connections") || on(limit, "shape")) && action != fwconfig.ActionAccept {
			errs = append(errs, fail("rate-limit: %s limits or shapes connections, which only an accept rule has", name))
		}
	}
	if on(r, "syn-proxy") {
		if r.Leaf("chain") != fwconfig.ChainForward || action != fwconfig.ActionAccept {
			errs = append(errs, fail("syn-proxy: only a forward rule that accepts can have one"))
		}
		if len(r.LeafLists["out-interfaces"]) > 0 {
			errs = append(errs, fail("syn-proxy: a rule with one can't match outgoing interfaces (the handshake is answered before routing)"))
		}
		if !hasTCP(c, r.LeafLists["services"]) {
			errs = append(errs, fail("syn-proxy: the rule needs a TCP service"))
		}
		if limit != nil && !on(limit, "connections") && !on(limit, "shape") {
			errs = append(errs, fail("syn-proxy: the rule's rate limit must limit or shape connections"))
		}
		if m := num(r, "syn-proxy-mss"); m != 0 && (m < fwconfig.MinSynProxyMSS || m > fwconfig.MaxSynProxyMSS) {
			errs = append(errs, fail("syn-proxy-mss: 0 (default) or %d-%d", fwconfig.MinSynProxyMSS, fwconfig.MaxSynProxyMSS))
		}
		if w := num(r, "syn-proxy-wscale"); w < 0 || w > fwconfig.MaxSynProxyWScale {
			errs = append(errs, fail("syn-proxy-wscale: 0-%d", fwconfig.MaxSynProxyWScale))
		}
	}
	return errs
}

// checkServices refuses a service name that is neither a custom service
// (a leafref) nor a predefined one.
func checkServices(c *Ctx, r *datastore.Node) []error {
	var errs []error
	for _, s := range r.LeafLists["services"] {
		if !predefined[s] && c.T.Root.Entry("service", []string{s}) == nil {
			errs = append(errs, fail("services: no service %q", s))
		}
	}
	return errs
}

// hasTCP reports whether one of the services matches TCP.
func hasTCP(c *Ctx, names []string) bool {
	pre := netobj.NewServices(nil)
	for _, n := range names {
		if svc := c.T.Root.Entry("service", []string{n}); svc != nil {
			for _, p := range svc.Lists["port"] {
				if p.Leaf("protocol") == fwconfig.ProtoTCP {
					return true
				}
			}
			continue
		}
		if ms, err := pre.Expand([]string{n}); err == nil {
			for _, m := range ms {
				if m.Protocol == fwconfig.ProtoTCP {
					return true
				}
			}
		}
	}
	return false
}

// checkIPListRefs refuses an @name of no IP list.
func checkIPListRefs(c *Ctx, e *datastore.Node, leaves ...string) []error {
	var errs []error
	for _, l := range leaves {
		for _, v := range e.LeafLists[l] {
			if name, ok := fwconfig.IPListName(v); ok && c.T.Root.Entry("ip-list", []string{name}) == nil {
				errs = append(errs, fail("%s: no IP list %s", l, name))
			}
		}
	}
	return errs
}

func normalizeNAT(c *Ctx, n *datastore.Node) error {
	for _, l := range []string{"in-interfaces", "out-interfaces"} {
		if vs := n.LeafLists[l]; vs != nil {
			n.LeafLists[l] = dedupe(vs)
		}
	}
	kind := n.Leaf("kind")
	if kind == fwconfig.NATDNAT {
		clear(n, "out-interfaces")
	} else {
		clear(n, "in-interfaces", "hairpin")
	}
	if kind == fwconfig.NATMasquerade {
		clear(n, "to-addr", "to-port")
	}
	return nil
}

func checkNAT(c *Ctx, n *datastore.Node) []error {
	in := instanceOf(n)
	errs := checkIfaceList(c, in, "in-interfaces", n.LeafLists["in-interfaces"])
	errs = append(errs, checkIfaceList(c, in, "out-interfaces", n.LeafLists["out-interfaces"])...)
	kind, proto := n.Leaf("kind"), n.Leaf("protocol")
	if kind != fwconfig.NATMasquerade && n.Leaf("to-addr") == "" {
		errs = append(errs, fail("to-addr: the target address is missing"))
	}
	if ports := n.Leaf("dst-ports"); ports != "" {
		if proto == "" {
			errs = append(errs, fail("dst-ports: ports need protocol tcp, udp or tcp,udp"))
		} else if _, err := fwconfig.ParsePortsNamed(ports, portNames(c)); err != nil {
			errs = append(errs, fail("dst-ports: %v; use ports (22), ranges (8000-8080) or port names (https)", err))
		}
	}
	if on(n, "hairpin") && len(n.LeafLists["in-interfaces"]) == 0 {
		errs = append(errs, fail("hairpin: it needs incoming interfaces (the WAN)"))
	}
	if n.Leaf("to-port") != "" && num(n, "to-port") != 0 && proto == "" {
		errs = append(errs, fail("to-port: a target port needs protocol tcp, udp or tcp,udp"))
	}
	return errs
}

// portNames are the port names (port-name) by name.
func portNames(c *Ctx) map[string]int {
	out := map[string]int{}
	for _, p := range c.T.Root.Lists["port-name"] {
		port, _ := strconv.Atoi(p.Leaf("port"))
		out[p.Leaf("name")] = port
	}
	return out
}

func normalizeIpamPrefix(c *Ctx, p *datastore.Node) error {
	if pfx, err := netip.ParsePrefix(p.Leaf("prefix")); err == nil && !pfx.Addr().Is4() && !on(p, "ra-enabled") {
		clear(p, "ra-slaac")
	}
	return nil
}

func checkIpamPrefix(c *Ctx, p *datastore.Node) []error {
	var errs []error
	pfx := netip.MustParsePrefix(p.Leaf("prefix"))
	if pfx.Addr().Is4() {
		if on(p, "ra-enabled") || on(p, "ra-slaac") {
			errs = append(errs, fail("router advertisements are for IPv6 prefixes"))
		}
	} else {
		if on(p, "ra-slaac") && pfx.Bits() != 64 {
			errs = append(errs, fail("ra-slaac: SLAAC needs a /64 prefix"))
		}
		if on(p, "dhcp-enabled") && !on(p, "ra-enabled") {
			errs = append(errs, fail("dhcp-enabled: DHCPv6 needs router advertisements on the prefix: clients learn the default router from them"))
		}
		if p.Leaf("dhcp-gateway") != "" {
			errs = append(errs, fail("dhcp-gateway: IPv6 clients learn the gateway from router advertisements; leave it empty"))
		}
	}
	if !on(p, "dhcp-enabled") {
		return errs
	}
	start, end := p.Leaf("dhcp-range-start"), p.Leaf("dhcp-range-end")
	if (start == "") != (end == "") {
		errs = append(errs, fail("the DHCP range needs both start and end"))
	}
	for _, a := range []string{start, end, p.Leaf("dhcp-gateway")} {
		if a != "" && !pfx.Contains(netip.MustParseAddr(a)) {
			errs = append(errs, fail("%s is not inside %s", a, pfx))
		}
	}
	if start != "" && end != "" && netip.MustParseAddr(start).Compare(netip.MustParseAddr(end)) > 0 {
		errs = append(errs, fail("dhcp-range-start is after its end"))
	}
	return errs
}

func checkIpamAddress(c *Ctx, a *datastore.Node) []error {
	if a.Leaf("mac") != "" && a.Leaf("dns-name") == "" {
		return []error{fail("dns-name: a DHCP reservation needs a DNS name (reservations are made from DNS records)")}
	}
	return nil
}

func normalizeDNSZone(c *Ctx, z *datastore.Node) error {
	typ := z.Leaf("type")
	if old := c.old(z); old != nil && old.Leaf("type") != typ {
		return fail("the type of a zone can't change; make a new one")
	}
	if typ == fwconfig.ZoneForwardOnly {
		clear(z, "dns-template") // no SOA or NS: nothing is served
	} else {
		clear(z, "forwarders")
	}
	if typ != fwconfig.ZoneForward && len(z.Lists["record"]) > 0 {
		return fail("records go in forward zones; reverse zones are generated, forward-only zones are forwarded")
	}
	return nil
}

func checkDNSZone(c *Ctx, z *datastore.Node) []error {
	name, typ := z.Leaf("name"), z.Leaf("type")
	switch typ {
	case fwconfig.ZoneForward, fwconfig.ZoneForwardOnly:
		if !fwconfig.ValidDomain(name) {
			return []error{fail("name: a domain, e.g. home.arpa")}
		}
	case fwconfig.ZoneReverse4, fwconfig.ZoneReverse6:
		p, err := netip.ParsePrefix(name)
		if err != nil || p.Addr().Is4() != (typ == fwconfig.ZoneReverse4) || p != p.Masked() {
			return []error{fail("name: a reverse zone is named by its prefix, e.g. 192.168.1.0/24")}
		}
	}
	if typ == fwconfig.ZoneForwardOnly && len(z.LeafLists["forwarders"]) == 0 {
		return []error{fail("forwarders: enter at least one DNS server")}
	}
	return nil
}

