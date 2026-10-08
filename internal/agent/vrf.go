// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"

	"github.com/abundo/portitor/internal/fwconfig"
)

// The firewall's own services (DNS, NTP, SNMP, DHCP...) run in the default
// VRF and answer on the VRFs' interfaces too (tcp_l3mdev_accept,
// udp_l3mdev_accept). A TCP connection is the VRF's; a UDP answer is not,
// so it would be routed by the main table, which doesn't know the VRF's
// networks. Two things send it back through the VRF:
//
//   - a rule per address of a VRF's interfaces (VRRP devices included),
//     "from <address> iif lo lookup <the VRF's table>", for what the
//     firewall sends from it (vrfSourceRules);
//   - ip_nonlocal_bind, so a daemon in the default VRF may bind such an
//     address (named binds each address it listens on), which the kernel
//     otherwise refuses: the address is local in the VRF's table only.
//
// A daemon that answers from a socket bound to no address replies with the
// interface it heard the request on (IP_PKTINFO: chrony, snmpd), which
// takes the VRF's table without a rule.

// VRFSourcePref is the preference of those rules: after the kernel's
// l3mdev rule (1000), before main.
const VRFSourcePref = 1100

// vrfSysctls are the settings an instance with VRFs needs.
func vrfSysctls(in *fwconfig.Instance) []string {
	if !in.HasVRF() {
		return nil
	}
	return []string{
		"net.ipv4.tcp_l3mdev_accept=1", "net.ipv4.udp_l3mdev_accept=1",
		"net.ipv4.ip_nonlocal_bind=1", "net.ipv6.ip_nonlocal_bind=1",
	}
}

// vrfSourceRules are the rules wanted for the addresses the links have
// (ip -j addr) on the instance's VRF interfaces, per IP version ("-4",
// "-6"). Link-local addresses are left out: an answer to one goes out of
// the interface it names.
func vrfSourceRules(in *fwconfig.Instance, links map[string]ipLink) map[string][]ipRule {
	out := map[string][]ipRule{}
	for _, name := range slices.Sorted(maps.Keys(links)) {
		vrf := in.VRFOf(name)
		if vrf == nil {
			continue
		}
		for _, a := range links[name].AddrInfo {
			addr, err := netip.ParseAddr(a.Local)
			if err != nil || addr.IsLinkLocalUnicast() || a.Scope == "host" {
				continue
			}
			fam := "-4"
			if addr.Is6() {
				fam = "-6"
			}
			out[fam] = append(out[fam], ipRule{Priority: VRFSourcePref, Src: addr.String(), Iif: "lo", Table: strconv.Itoa(vrf.Table), Protocol: RouteProto})
		}
	}
	return out
}

// planVRFRules removes the agent's rules at VRFSourcePref that aren't
// wanted and adds the missing ones, of one IP version.
func planVRFRules(ns, fam string, want, have []ipRule) []command {
	key := func(r ipRule) string { return fmt.Sprintf("%s|%s|%s", r.Src, r.Iif, r.Table) }
	wanted := map[string]bool{}
	for _, r := range want {
		wanted[key(r)] = true
	}
	var cmds []command
	present := map[string]bool{}
	for _, r := range have {
		if r.Protocol != RouteProto || r.Priority != VRFSourcePref {
			continue
		}
		if k := key(r); wanted[k] && !present[k] {
			present[k] = true
			continue
		}
		args := []string{fam, "rule", "del", "pref", strconv.Itoa(VRFSourcePref)}
		if r.Src != "" && r.Src != "all" {
			args = append(args, "from", r.Src)
		}
		if r.Iif != "" {
			args = append(args, "iif", r.Iif)
		}
		cmds = append(cmds, ipCmd(ns, append(args, "lookup", r.Table, "proto", RouteProto)...))
	}
	for _, r := range want {
		if k := key(r); !present[k] {
			present[k] = true
			cmds = append(cmds, ipCmd(ns, fam, "rule", "add", "pref", strconv.Itoa(VRFSourcePref), "from", r.Src, "iif", "lo", "lookup", r.Table, "proto", RouteProto))
		}
	}
	return cmds
}

// applyVRFRules keeps the VRF source rules in step with the addresses the
// instance's VRF interfaces have now.
func (a *Agent) applyVRFRules(ctx context.Context, in *fwconfig.Instance, ns string) error {
	links, err := a.links(ctx, ns)
	if err != nil {
		return err
	}
	want := vrfSourceRules(in, links)
	for _, fam := range []string{"-4", "-6"} {
		out, err := a.run.Run(ctx, ns, "ip", "-N", "-j", fam, "rule", "show")
		if err != nil {
			return err
		}
		have, err := parseRules(out)
		if err != nil {
			return err
		}
		if err := a.doAll(ctx, planVRFRules(ns, fam, want[fam], have)); err != nil {
			return err
		}
	}
	return nil
}

// vrfSourceRuleArgs are the ip arguments (after "rule add" or "rule del")
// of the rule for a DHCP address in a VRF's table, which the DHCP client
// keeps between applies.
func vrfSourceRuleArgs(addr, table string) []string {
	return []string{"pref", strconv.Itoa(VRFSourcePref), "from", addr, "iif", "lo", "lookup", table, "proto", RouteProto}
}
