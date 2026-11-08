// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package confcheck

import (
	"net/netip"
	"strings"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
)

// VRFs and the routing protocols. Their objects (prefix lists, route maps,
// BGP, OSPF, IS-IS) are checked as a whole by fwconfig.Validate when the
// document is built (fwconfig.Check*): a save's warnings, a commit's
// errors. Here: what the GUI normalized, and what refers across rows.

func init() {
	register("/instance/vrf", hook{check: checkVRF})
	register("/instance/community-list", hook{normalize: normalizeCommunityList})
	register("/instance/route-map", hook{normalize: normalizeRouteMap})
	register("/instance/bgp", hook{normalize: normalizeBGP, check: checkBGP})
	register("/instance/bgp-neighbor", hook{normalize: normalizeNeighbor, check: checkNeighbor})
}

// vrfOf is a routing row's VRF, "" for the main table.
func vrfOf(e *datastore.Node) string {
	if v := e.Leaf("vrf"); v != "main" {
		return v
	}
	return ""
}

func vrfText(v string) string {
	if v == "" {
		return "the main table"
	}
	return "VRF " + v
}

func checkVRF(c *Ctx, v *datastore.Node) []error {
	var errs []error
	in, name := instanceOf(v), v.Leaf("name")
	if name == "lo" || strings.HasPrefix(name, fwconfig.IFBPrefix) || strings.HasPrefix(name, fwconfig.NAT64DevicePrefix) ||
		strings.HasPrefix(name, "vrrp4-") || strings.HasPrefix(name, "vrrp6-") || fwconfig.IsL3VNIName(name) {
		errs = append(errs, fail("name: that prefix is for the firewall's own devices"))
	}
	if ifaceNames(c, in)[name] {
		errs = append(errs, fail("name: %s is an interface of this virtual firewall", name))
	}
	if in.Entry("interface-zone", []string{name}) != nil {
		errs = append(errs, fail("name: an interface zone is named %s", name))
	}
	if msg := fwconfig.CheckVRFTable(num(v, "route-table")); msg != "" {
		errs = append(errs, fail("route-table: %s", msg))
	}
	for _, o := range in.Lists["vrf"] {
		if o != v && o.Leaf("route-table") == v.Leaf("route-table") {
			errs = append(errs, fail("route-table: %s is VRF %s's", v.Leaf("route-table"), o.Leaf("name")))
		}
	}
	return errs
}

// words writes a list of words with one space between them.
func words(e *datastore.Node, leaves ...string) {
	for _, l := range leaves {
		if v, ok := e.Leaves[l]; ok {
			e.Leaves[l] = strings.Join(strings.Fields(v), " ")
		}
	}
}

func normalizeCommunityList(c *Ctx, l *datastore.Node) error {
	if k := l.Leaf("kind"); k == fwconfig.CommunityStandard || k == fwconfig.CommunityLargeStandard {
		for _, e := range l.Lists["entry"] {
			words(e, "value")
		}
	}
	return nil
}

func normalizeRouteMap(c *Ctx, m *datastore.Node) error {
	for _, e := range m.Lists["entry"] {
		words(e, "set-as-path-prepend", "set-community", "set-large-community")
		if e.Leaf("action") == fwconfig.Deny {
			// A deny sets nothing: it keeps its matches.
			for name := range e.Leaves {
				if strings.HasPrefix(name, "set-") || name == "on-match-next" {
					delete(e.Leaves, name)
				}
			}
		}
	}
	return nil
}

func normalizeBGP(c *Ctx, b *datastore.Node) error {
	for _, r := range []string{"connected-v4", "static-v4", "connected-v6", "static-v6", "ospf-v4", "ospf-v6", "isis-v4", "isis-v6"} {
		if !on(b, "redist-"+r) {
			clear(b, "redist-"+r+"-map")
		}
	}
	return nil
}

func checkBGP(c *Ctx, b *datastore.Node) []error {
	var errs []error
	if on(b, "evpn") && vrfOf(b) != "" {
		errs = append(errs, fail("evpn: EVPN is for the main table's BGP only"))
	}
	if on(b, "enabled") && num(b, "asn") == 0 {
		errs = append(errs, fail("asn: the local AS is missing (1-4294967295)"))
	}
	return errs
}

func normalizeNeighbor(c *Ctx, n *datastore.Node) error {
	if a, err := netip.ParseAddr(n.Leaf("address")); err == nil && !a.IsLinkLocalUnicast() {
		clear(n, "interface") // only a link-local neighbour has one
	}
	return nil
}

func checkNeighbor(c *Ctx, n *datastore.Node) []error {
	var errs []error
	in, vrf := instanceOf(n), vrfOf(n)
	var group *datastore.Node
	if g := n.Leaf("peer-group"); g != "" {
		if group = in.Entry("bgp-peer-group", []string{g}); group != nil && vrfOf(group) != vrf {
			errs = append(errs, fail("peer-group: %s is %s's, not %s's", g, vrfText(vrfOf(group)), vrfText(vrf)))
		}
	}
	if i := n.Leaf("interface"); i != "" {
		if ifc := in.Entry("interface", []string{i}); ifc != nil && ifc.Leaf("vrf") != vrf {
			errs = append(errs, fail("interface: %s is in %s, the neighbour in %s", i, vrfText(ifc.Leaf("vrf")), vrfText(vrf)))
		}
	}
	if n.Leaf("remote-as") == "" && (group == nil || group.Leaf("remote-as") == "") {
		errs = append(errs, fail("remote-as: missing, on the neighbour or its peer group"))
	}
	return errs
}
