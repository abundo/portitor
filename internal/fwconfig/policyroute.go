// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
	"net/netip"
	"slices"
)

// PolicyRoute routes the forwarded packets it matches (incoming interface,
// addresses, services) by a route of its own instead of the main table:
// policy-based routing (Routing → Policy). An instance's policy routes are
// tried in order and the first that matches decides; one without Gateways
// and Interface is an exception, whose packets take the main table as
// without policy routes.
//
// The ruleset's prerouting chain (after the NAT64 chain) gives the packets
// of the i-th the mark PolicyRouteMark(i), and a rule (proto 99,
// preference PolicyRouteTable(i)) looks the packets with that mark up in
// table PolicyRouteTable(i), which holds the policy's default route. When
// the route is missing (its interface down, say), the lookup finds nothing
// and the packet takes the main table; so does a route whose interface
// lost its carrier, as the agent sets ignore_routes_with_linkdown on the
// interfaces the routes leave by (PolicyRouteDevices). The forward chain
// clears the mark again, before the shapers mark the packets.
//
// Policy routes are the main table's: their interfaces are in no VRF. What
// the firewall itself sends isn't policy-routed, and the destination is
// the packet's before DNAT.
type PolicyRoute struct {
	// InInterfaces, Family, SrcAddrs, DstAddrs and Services match as a
	// forward rule's do.
	InInterfaces []string       `json:"in_interfaces,omitempty"`
	Family       string         `json:"family,omitempty"` // "", ipv4, ipv6
	SrcAddrs     []string       `json:"src_addrs,omitempty"`
	DstAddrs     []string       `json:"dst_addrs,omitempty"`
	Services     []ServiceMatch `json:"services,omitempty"`
	// Gateways (at most one per IP version) and Interface make the route.
	// With gateways, only their IP versions are policy-routed; with an
	// interface alone (a tunnel), both.
	Gateways    []string `json:"gateways,omitempty"`
	Interface   string   `json:"interface,omitempty"`
	Description string   `json:"description,omitempty"`
}

// MaxPolicyRoutes is the most policy routes an instance may have: their
// marks lie between NAT64's and the shapers'.
const MaxPolicyRoutes = 256

// PolicyRouteMarkBase is the packet mark of the first policy route.
const PolicyRouteMarkBase = 0x5100

// PolicyRouteTableBase is the routing table, and the preference of the rule
// that looks it up, of the first policy route: above NAT64's tables, and
// above the tables a VRF may have (MaxVRFTable).
const PolicyRouteTableBase = NAT64TableBase + 100

// PolicyRouteMark is the packet mark of the instance's i-th policy route.
func PolicyRouteMark(i int) int { return PolicyRouteMarkBase + i }

// PolicyRouteTable is the routing table, and rule preference, of the
// instance's i-th policy route.
func PolicyRouteTable(i int) int { return PolicyRouteTableBase + i }

// IsPolicyRoutePref reports whether a rule preference is a policy route's.
func IsPolicyRoutePref(pref int) bool {
	return pref >= PolicyRouteTableBase && pref < PolicyRouteTableBase+MaxPolicyRoutes
}

// Routed reports whether the policy route has a route of its own; one
// without is an exception that leaves its packets to the main table.
func (p PolicyRoute) Routed() bool { return len(p.Gateways) > 0 || p.Interface != "" }

// RouteFamilies are the IP versions the policy route routes: its
// gateways', or both.
func (p PolicyRoute) RouteFamilies() []string {
	if len(p.Gateways) == 0 {
		return []string{"ipv4", "ipv6"}
	}
	var out []string
	for _, g := range p.Gateways {
		if fam := AddrFamily(g); !slices.Contains(out, fam) {
			out = append(out, fam)
		}
	}
	return out
}

// Gateway is the policy route's gateway of an IP version, "" for none.
func (p PolicyRoute) Gateway(fam string) string {
	for _, g := range p.Gateways {
		if AddrFamily(g) == fam {
			return g
		}
	}
	return ""
}

// Matches splits the policy route's match as a rule's (Rule.Matches), for
// the IP versions it routes.
func (p PolicyRoute) Matches() []RuleMatch {
	fams := p.RouteFamilies()
	r := Rule{Chain: ChainForward, InInterfaces: p.InInterfaces, Family: p.Family,
		SrcAddrs: p.SrcAddrs, DstAddrs: p.DstAddrs, Services: p.Services, Action: ActionAccept}
	if r.Family == "" && len(fams) == 1 {
		r.Family = fams[0]
	}
	var out []RuleMatch
	for _, m := range r.Matches() {
		if m.Family == "" || slices.Contains(fams, m.Family) {
			out = append(out, m)
		}
	}
	return out
}

// MarkedFamilies are the IP versions whose packets the policy route marks:
// those of its matches, within the ones it routes.
func (p PolicyRoute) MarkedFamilies() []string {
	var out []string
	for _, m := range p.Matches() {
		if m.Family == "" {
			return p.RouteFamilies()
		}
		if !slices.Contains(out, m.Family) {
			out = append(out, m.Family)
		}
	}
	return out
}

// PolicyRouteDevices are the interfaces the policy routes' routes leave by:
// their Interface, or else the one with an address in a gateway's prefix.
// A gateway on an interface with a DHCP address alone is known only on
// the firewall, so it isn't found.
func (in *Instance) PolicyRouteDevices() map[string]bool {
	out := map[string]bool{}
	for _, p := range in.PolicyRoutes {
		if p.Interface != "" {
			out[p.Interface] = true
			continue
		}
		for _, g := range p.Gateways {
			gw, err := netip.ParseAddr(g)
			if err != nil {
				continue
			}
			for _, ifc := range in.Interfaces {
				for _, a := range ifc.Addresses {
					if pfx, err := netip.ParsePrefix(a); err == nil && pfx.Contains(gw) {
						out[ifc.Name] = true
					}
				}
			}
		}
	}
	return out
}

// policyRoutes checks the instance's policy routes; ifaceRefs checks an
// interface list.
func (v *validator) policyRoutes(p string, in *Instance, ifaces map[string]*Interface, ifaceRefs func(string, []string)) {
	if len(in.PolicyRoutes) > MaxPolicyRoutes {
		v.addf("%s: at most %d policy routes", p, MaxPolicyRoutes)
	}
	for i, pr := range in.PolicyRoutes {
		pp := fmt.Sprintf("%s: policy route %d", p, i+1)
		checkComment(v, pp, pr.Description)
		ifaceRefs(pp, pr.InInterfaces)
		for _, name := range in.MatchInterfaces(pr.InInterfaces) {
			if vrf := in.IfaceVRF(name); vrf != "" {
				v.addf("%s: interface %s is in vrf %s; policy routes are the main table's", pp, name, vrf)
			}
		}
		fams := map[string]bool{}
		gwOK := true
		for _, g := range pr.Gateways {
			a, err := ParseAddr(g)
			if err != nil || a.IsUnspecified() || a.IsMulticast() || a.Is4In6() || a.Zone() != "" {
				v.addf("%s: invalid gateway %q", pp, g)
				gwOK = false
				continue
			}
			fam := AddrFamily(g)
			if fams[fam] {
				v.addf("%s: one gateway per ip version", pp)
			}
			fams[fam] = true
			if a.IsLinkLocalUnicast() && pr.Interface == "" {
				v.addf("%s: a link-local gateway needs an interface", pp)
			}
		}
		if pr.Interface != "" {
			if ifc := ifaces[pr.Interface]; ifc == nil {
				v.addf("%s: unknown interface %q", pp, pr.Interface)
			} else if ifc.Kind == KindVRF || ifc.VRF != "" {
				v.addf("%s: interface %s is in a vrf; policy routes are the main table's", pp, pr.Interface)
			}
		}
		if pr.Family != "" && pr.Routed() && len(pr.Gateways) > 0 && !fams[pr.Family] {
			v.addf("%s: no %s gateway", pp, pr.Family)
		}
		if v.match(pp, pr.Family, "", pr.SrcAddrs, pr.DstAddrs, "", true) && gwOK {
			valid := true
			for j, sm := range pr.Services {
				valid = v.service(fmt.Sprintf("%s: service %d", pp, j+1), sm) && valid
			}
			if valid && len(pr.Matches()) == 0 {
				v.addf("%s: its addresses, services and ip version don't fit its gateways", pp)
			}
		}
	}
}
