// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"

	"github.com/abundo/portitor/internal/fwconfig"
)

// RouteProto tags routes the agent installs (ip route ... proto 99), so it
// can find and remove its own stale routes without touching kernel,
// DHCP or RA routes.
const RouteProto = "99"

// DHCPRouteMetric is the metric of default routes learned by the DHCP
// client. Static routes default to metric 0 and so take precedence.
const DHCPRouteMetric = 100

// ipLink is the subset of `ip -j -d addr show` the agent reads.
type ipLink struct {
	Ifname   string   `json:"ifname"`
	Link     string   `json:"link"` // vlan parent / veth peer, when in the same netns
	Master   string   `json:"master"`
	Address  string   `json:"address"` // MAC address
	MTU      int      `json:"mtu"`
	Flags    []string `json:"flags"`
	LinkInfo *struct {
		InfoKind string `json:"info_kind"`
		InfoData struct {
			ID int `json:"id"`
			// A tunnel's endpoints (sit): addresses, or "any".
			Local  string `json:"local"`
			Remote string `json:"remote"`
		} `json:"info_data"`
	} `json:"linkinfo"`
	AddrInfo []ipAddr `json:"addr_info"`
}

type ipAddr struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	Prefixlen int    `json:"prefixlen"`
	Scope     string `json:"scope"`
	Dynamic   bool   `json:"dynamic"`
}

// foreignDHCPAddrs returns the interface's dynamic global IPv4 addresses
// other than own (the agent's lease, invalid when it has none). The agent
// adds a lease with a lifetime, so such an address that is not its own was
// most likely added by another DHCP client (systemd-networkd, NetworkManager,
// dhclient) on the same interface, which also keeps the ISP from answering
// the agent.
func foreignDHCPAddrs(have ipLink, own netip.Prefix) []string {
	var out []string
	for _, a := range have.AddrInfo {
		if a.Family != "inet" || !a.Dynamic || a.Scope != "global" {
			continue
		}
		if p, err := a.prefix(); err == nil && p != own {
			out = append(out, p.String())
		}
	}
	return out
}

func (l ipLink) kind() string {
	if l.LinkInfo == nil {
		return ""
	}
	return l.LinkInfo.InfoKind
}

// fallbackDevices are the devices a tunnel module adds to every network
// namespace once loaded (sit0 with the sit module); they can't be deleted.
var fallbackDevices = map[string]string{
	"sit0": "sit", "tunl0": "ipip", "ip6tnl0": "ip6tnl", "gre0": "gre",
	"gretap0": "gretap", "erspan0": "erspan", "ip6gre0": "ip6gre",
	"ip_vti0": "vti", "ip6_vti0": "vti6",
}

func fallbackDevice(l ipLink) bool {
	k, ok := fallbackDevices[l.Ifname]
	return ok && l.kind() == k
}

func (l ipLink) up() bool {
	for _, f := range l.Flags {
		if f == "UP" {
			return true
		}
	}
	return false
}

func (a ipAddr) prefix() (netip.Prefix, error) {
	addr, err := netip.ParseAddr(a.Local)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, a.Prefixlen), nil
}

type ipRoute struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	Metric  int    `json:"metric"`
}

func parseLinks(data []byte) ([]ipLink, error) {
	var links []ipLink
	if len(data) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(data, &links); err != nil {
		return nil, fmt.Errorf("parse ip -j output: %w", err)
	}
	return links, nil
}

func parseRoutes(data []byte) ([]ipRoute, error) {
	var routes []ipRoute
	if len(data) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(data, &routes); err != nil {
		return nil, fmt.Errorf("parse ip -j route output: %w", err)
	}
	return routes, nil
}

// command is one command to run in a namespace.
type command struct {
	Netns string
	Name  string
	Args  []string
	Stdin []byte
}

func ipCmd(ns string, args ...string) command {
	return command{Netns: ns, Name: "ip", Args: args}
}

// virtualSpec reports whether an observed link matches the desired
// virtual interface, or must be recreated.
func virtualMatches(want fwconfig.Interface, have ipLink) bool {
	switch want.Kind {
	case fwconfig.KindVLAN:
		return have.kind() == "vlan" && have.LinkInfo.InfoData.ID == want.VLANID && (have.Link == "" || have.Link == want.Parent)
	case fwconfig.KindBridge:
		return have.kind() == "bridge"
	case fwconfig.KindWireGuard:
		return have.kind() == "wireguard"
	case fwconfig.KindLoopback:
		return have.kind() == "dummy"
	case fwconfig.Kind6in4:
		return have.kind() == "sit" && want.Tunnel != nil &&
			have.LinkInfo.InfoData.Remote == want.Tunnel.Remote &&
			have.LinkInfo.InfoData.Local == sitLocal(want.Tunnel)
	case fwconfig.KindLink:
		return have.kind() == "veth"
	}
	return true
}

// sitLocal is a 6in4 tunnel's local address as ip(8) takes and shows it.
func sitLocal(t *fwconfig.Tunnel6in4) string {
	if t.Local == "" {
		return "any"
	}
	return t.Local
}

// planCreate returns commands creating the virtual interfaces of one
// instance that are missing or have the wrong type. Physical interfaces
// and veth link ends are handled elsewhere (moving between namespaces).
func planCreate(ns string, want []fwconfig.Interface, have map[string]ipLink) []command {
	var cmds []command
	// Bridges and wireguard first, VLANs after (a VLAN parent may be a
	// bridge).
	order := append([]fwconfig.Interface(nil), want...)
	sort.SliceStable(order, func(i, j int) bool {
		return order[i].Kind != fwconfig.KindVLAN && order[j].Kind == fwconfig.KindVLAN
	})
	for _, ifc := range order {
		switch ifc.Kind {
		case fwconfig.KindVLAN, fwconfig.KindBridge, fwconfig.KindWireGuard, fwconfig.KindLoopback, fwconfig.Kind6in4:
		default:
			continue
		}
		if l, ok := have[ifc.Name]; ok {
			if virtualMatches(ifc, l) {
				continue
			}
			cmds = append(cmds, ipCmd(ns, "link", "del", "dev", ifc.Name))
		}
		switch ifc.Kind {
		case fwconfig.KindVLAN:
			cmds = append(cmds, ipCmd(ns, "link", "add", "link", ifc.Parent, "name", ifc.Name, "type", "vlan", "id", strconv.Itoa(ifc.VLANID)))
		case fwconfig.KindBridge:
			cmds = append(cmds, ipCmd(ns, "link", "add", "name", ifc.Name, "type", "bridge"))
		case fwconfig.KindWireGuard:
			cmds = append(cmds, ipCmd(ns, "link", "add", "name", ifc.Name, "type", "wireguard"))
		case fwconfig.KindLoopback:
			cmds = append(cmds, ipCmd(ns, "link", "add", "name", ifc.Name, "type", "dummy"))
		case fwconfig.Kind6in4:
			if ifc.Tunnel == nil {
				continue
			}
			cmds = append(cmds, ipCmd(ns, "link", "add", "name", ifc.Name, "type", "sit", "remote", ifc.Tunnel.Remote, "local", sitLocal(ifc.Tunnel), "ttl", "255"))
		}
	}
	return cmds
}

// planLinkSettings sets bridge membership, MTU and admin state.
func planLinkSettings(ns string, want []fwconfig.Interface, have map[string]ipLink) []command {
	var cmds []command
	master := map[string]string{}
	for _, ifc := range want {
		if ifc.Kind == fwconfig.KindBridge {
			for _, m := range ifc.Members {
				master[m] = ifc.Name
			}
		}
	}
	for _, ifc := range want {
		l, exists := have[ifc.Name]
		if m := master[ifc.Name]; m != "" && (!exists || l.Master != m) {
			cmds = append(cmds, ipCmd(ns, "link", "set", "dev", ifc.Name, "master", m))
		} else if m == "" && exists && l.Master != "" && have[l.Master].kind() == "bridge" {
			if isOurBridge(want, l.Master) {
				cmds = append(cmds, ipCmd(ns, "link", "set", "dev", ifc.Name, "nomaster"))
			}
		}
		if ifc.MTU > 0 && (!exists || l.MTU != ifc.MTU) {
			cmds = append(cmds, ipCmd(ns, "link", "set", "dev", ifc.Name, "mtu", strconv.Itoa(ifc.MTU)))
		}
		state := "down"
		if ifc.Enabled {
			state = "up"
		}
		if !exists || l.up() != ifc.Enabled {
			cmds = append(cmds, ipCmd(ns, "link", "set", "dev", ifc.Name, state))
		}
	}
	return cmds
}

func isOurBridge(want []fwconfig.Interface, name string) bool {
	for _, ifc := range want {
		if ifc.Name == name && ifc.Kind == fwconfig.KindBridge {
			return true
		}
	}
	return false
}

// planAddresses reconciles static addresses on one interface. IPv4 is left
// alone in DHCP mode (the DHCP client owns it); dynamic (SLAAC/DHCP) and
// link-local addresses are never removed.
func planAddresses(ns string, ifc fwconfig.Interface, have ipLink) []command {
	want := map[netip.Prefix]bool{}
	for _, a := range ifc.Addresses {
		if p, err := netip.ParsePrefix(a); err == nil {
			want[p] = true
		}
	}
	var cmds []command
	present := map[netip.Prefix]bool{}
	for _, a := range have.AddrInfo {
		p, err := a.prefix()
		if err != nil {
			continue
		}
		present[p] = true
		if want[p] || a.Dynamic || a.Scope == "link" || a.Scope == "host" {
			continue
		}
		if p.Addr().Is4() && ifc.IPv4Mode == fwconfig.ModeDHCP {
			continue
		}
		cmds = append(cmds, ipCmd(ns, "addr", "del", p.String(), "dev", ifc.Name))
	}
	var add []string
	for p := range want {
		if !present[p] {
			add = append(add, p.String())
		}
	}
	sort.Strings(add)
	for _, p := range add {
		cmds = append(cmds, ipCmd(ns, "addr", "add", p, "dev", ifc.Name))
	}
	return cmds
}

// planRoutes reconciles the agent's own (proto 99) routes.
func planRoutes(ns string, want []fwconfig.Route, have []ipRoute) []command {
	key := func(dst, gw, dev string, metric int) string {
		return fmt.Sprintf("%s|%s|%s|%d", dst, gw, dev, metric)
	}
	wantKeys := map[string]bool{}
	var cmds []command
	for _, r := range want {
		dst := r.Destination
		if p, err := netip.ParsePrefix(dst); err == nil {
			dst = p.Masked().String()
			if p.Bits() == 0 {
				dst = "default"
			}
		}
		wantKeys[key(dst, r.Gateway, r.Interface, r.Metric)] = true
	}
	for _, r := range have {
		dst := r.Dst
		if p, err := netip.ParsePrefix(dst); err == nil {
			dst = p.String()
		} else if a, err := netip.ParseAddr(dst); err == nil {
			dst = netip.PrefixFrom(a, a.BitLen()).String()
		}
		if wantKeys[key(dst, r.Gateway, r.Dev, r.Metric)] {
			continue
		}
		// A route whose dev isn't in the desired set still matches when
		// the desired route didn't name an interface.
		if wantKeys[key(dst, r.Gateway, "", r.Metric)] {
			continue
		}
		args := []string{"route", "del", dst}
		if r.Gateway != "" {
			args = append(args, "via", r.Gateway)
		}
		if r.Dev != "" {
			args = append(args, "dev", r.Dev)
		}
		args = append(args, "metric", strconv.Itoa(r.Metric), "proto", RouteProto)
		if isV6(dst, r.Gateway) {
			args = append([]string{"-6"}, args...)
		}
		cmds = append(cmds, ipCmd(ns, args...))
	}
	for _, r := range want {
		args := []string{"route", "replace", r.Destination}
		if r.Gateway != "" {
			args = append(args, "via", r.Gateway)
		}
		if r.Interface != "" {
			args = append(args, "dev", r.Interface)
		}
		args = append(args, "metric", strconv.Itoa(r.Metric), "proto", RouteProto)
		if isV6(r.Destination, r.Gateway) {
			args = append([]string{"-6"}, args...)
		}
		cmds = append(cmds, ipCmd(ns, args...))
	}
	return cmds
}

func isV6(dst, gw string) bool {
	if p, err := netip.ParsePrefix(dst); err == nil {
		return p.Addr().Is6()
	}
	if a, err := netip.ParseAddr(gw); err == nil {
		return a.Is6()
	}
	return false
}
