// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package confcheck

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/wgkeys"
)

// The virtual firewalls, their interfaces and links, routes and static
// neighbours: the checks of web/resources.go's prepare functions that the
// schema doesn't make.

func init() {
	register("/instance", hook{normalize: normalizeInstance, check: checkInstance})
	register("/instance/interface", hook{normalize: normalizeInterface, check: checkInterface})
	register("/instance/interface/wireguard-peer", hook{normalize: normalizeWgPeer, check: checkWgPeer})
	register("/instance/interface-zone", hook{check: checkInterfaceZone})
	register("/instance/static-neighbour", hook{check: checkStaticNeighbour})
	register("/instance/route", hook{check: checkRoute})
	register("/instance/policy-route", hook{check: checkPolicyRoute})
	register("/link", hook{check: checkLink})
}

// set sets a leaf of e that the schema knows to take v.
func set(e *datastore.Node, leaf, v string) { e.Leaves[leaf] = v }

// clear deletes leaves of e.
func clear(e *datastore.Node, leaves ...string) {
	for _, l := range leaves {
		delete(e.Leaves, l)
		delete(e.LeafLists, l)
	}
}

func on(e *datastore.Node, leaf string) bool { return e.Leaf(leaf) == "true" }

func num(e *datastore.Node, leaf string) int {
	n, _ := strconv.Atoi(e.Leaf(leaf))
	return n
}

func normalizeInstance(c *Ctx, in *datastore.Node) error {
	if c.old(in) == nil {
		if _, ok := in.Leaves["dns-upstream"]; !ok {
			set(in, "dns-upstream", fwconfig.UpstreamRoot)
		}
		if err := seedInstance(c, in); err != nil {
			return err
		}
	}
	if err := ensureServiceRateLimits(c, in); err != nil {
		return err
	}
	normalizeInstanceServices(c, in)
	if ts := in.LeafLists["dns-query-log-types"]; ts != nil {
		for i, t := range ts {
			ts[i] = strings.ToUpper(t)
		}
		in.LeafLists["dns-query-log-types"] = dedupe(ts)
	}
	return nil
}

func checkInstance(c *Ctx, in *datastore.Node) []error {
	var errs []error
	name := in.Leaf("name")
	if on(in, "is-default") {
		if !fwconfig.ValidDefaultInstanceName(name) {
			errs = append(errs, fail("name: letters, digits, '-', '_' and '.', starting with a letter or digit, at most 63 characters"))
		}
	} else if !fwconfig.ValidInstanceName(name) {
		errs = append(errs, fail("name: lowercase letters and digits, starting with a letter, at most 12 characters"))
	}
	for _, s := range in.LeafLists["log-auto"] {
		if !fwconfig.ValidAutoService(s) {
			errs = append(errs, fail("log-auto: no automatic rule %q", s))
		}
	}
	if p := in.Leaf("nat64-prefix"); p != "" {
		if err := fwconfig.CheckNAT64Prefix(p); err != nil {
			errs = append(errs, fail("nat64-prefix: %v", err))
		}
	}
	for _, s := range in.LeafLists["nat64-pool4"] {
		if !netip.MustParsePrefix(s).Addr().Is4() {
			errs = append(errs, fail("nat64-pool4: %s is not an IPv4 prefix", s))
		}
	}
	if on(in, "ntp-enabled") && len(in.Lists["ntp-server"]) == 0 {
		errs = append(errs, fail("ntp-server: enter at least one server"))
	}
	for _, t := range in.LeafLists["dns-query-log-types"] {
		if !fwconfig.ValidQueryType(t) {
			errs = append(errs, fail("dns-query-log-types: %q is not a DNS query type", t))
		}
	}
	if lt := in.Leaf("dhcp-lease-time"); lt != "" && num(in, "dhcp-lease-time") < 300 {
		errs = append(errs, fail("dhcp-lease-time: at least 300 seconds"))
	}
	return append(errs, checkInstanceServices(c, in)...)
}

func normalizeInterface(c *Ctx, i *datastore.Node) error {
	kind := i.Leaf("kind")
	if old := c.old(i); old != nil && old.Leaf("kind") != kind {
		return fail("the kind of an interface can't change; make a new one")
	}
	if i.Leaf("ipv4-mode") != fwconfig.ModeDHCP {
		clear(i, "dns-from-dhcp")
	}
	if on(i, "dns-from-dhcp") {
		// One per instance: taking the flag moves it here.
		for _, o := range instanceOf(i).Lists["interface"] {
			if o != i {
				clear(o, "dns-from-dhcp")
			}
		}
	}
	if kind != fwconfig.KindVLAN {
		clear(i, "parent", "vlan-id")
	}
	if kind != fwconfig.KindBridge {
		clear(i, "members")
	}
	if kind == fwconfig.KindWireGuard {
		if i.Leaves["wg-private-key"] == "" {
			priv, pub, err := wgkeys.Generate()
			if err != nil {
				return err
			}
			set(i, "wg-private-key", priv)
			set(i, "wg-public-key", pub)
		}
	} else if kind != fwconfig.KindOpenVPN {
		clear(i, "wg-endpoint", "wg-keepalive")
	}
	switch kind {
	case fwconfig.KindWireGuard, fwconfig.KindLoopback, fwconfig.Kind6in4, fwconfig.KindOpenVPN:
		clear(i, "lldp")
	}
	if kind == fwconfig.KindLoopback {
		clear(i, "shape-egress", "shape-ingress", "mss-clamp", "rpf")
	}
	if !on(i, "mss-clamp") {
		clear(i, "mss-clamp-value")
	}
	if kind != fwconfig.Kind6in4 {
		clear(i, "tunnel-remote", "tunnel-local", "he-tunnel-id", "he-username", "he-update-key", "tunnel-default-route")
	} else if i.Leaf("he-tunnel-id") == "" {
		clear(i, "he-username", "he-update-key")
	}
	if kind != fwconfig.KindVXLAN {
		clear(i, "vxlan-vni", "vxlan-local", "vxlan-device", "vxlan-port", "vxlan-remotes")
	}
	switch i.Leaf("ha-role") {
	case "":
		clear(i, "ha-gateway", "peer-addresses")
	case fwconfig.HARoleLink:
		clear(i, "ha-gateway")
	}
	if !on(i, "dhcpv6") {
		clear(i, "dhcpv6-pd")
	}
	if kind == fwconfig.KindOpenVPN {
		if err := normalizeOpenVPN(i); err != nil {
			return err
		}
	}
	if !on(i, "dhcpv6-pd") {
		clear(i, "dhcpv6-pd-length")
	}
	return nil
}

func checkInterface(c *Ctx, i *datastore.Node) []error {
	var errs []error
	in := instanceOf(i)
	name, kind, mode := i.Leaf("name"), i.Leaf("kind"), i.Leaf("ipv4-mode")
	switch {
	case name == "lo":
		errs = append(errs, fail("name: lo is the loopback device; make a loopback interface of another name"))
	case strings.HasPrefix(name, fwconfig.IFBPrefix):
		errs = append(errs, fail("name: %s names are for the shaping devices", fwconfig.IFBPrefix))
	case strings.HasPrefix(name, fwconfig.NAT64DevicePrefix):
		errs = append(errs, fail("name: %s names are for the NAT64 devices", fwconfig.NAT64DevicePrefix))
	case fwconfig.IsL3VNIName(name):
		errs = append(errs, fail("name: %s and %s names are for the VRFs' L3VNI devices", fwconfig.L3VNIDevicePrefix, fwconfig.L3VNIBridgePrefix))
	}
	if in.Entry("interface-zone", []string{name}) != nil {
		errs = append(errs, fail("name: an interface zone is named %s", name))
	}
	if in.Entry("vrf", []string{name}) != nil {
		errs = append(errs, fail("name: a VRF is named %s", name))
	}
	if mode == fwconfig.ModeDHCP {
		switch kind {
		case fwconfig.KindLoopback, fwconfig.KindWireGuard, fwconfig.Kind6in4:
			errs = append(errs, fail("%s interfaces have static addresses", kind))
		}
	}
	for _, a := range i.LeafLists["addresses"] {
		if fwconfig.IsDelegated(a) {
			d, _ := fwconfig.ParseDelegated(a)
			if d.Interface == name {
				if !on(i, "dhcpv6-pd") {
					errs = append(errs, fail("addresses: %s needs prefix delegation on this interface", a))
				}
			} else if o := in.Entry("interface", []string{d.Interface}); o == nil || !on(o, "dhcpv6-pd") {
				errs = append(errs, fail("addresses: %s: %s is not an interface of this virtual firewall with DHCPv6 prefix delegation", a, d.Interface))
			}
			for _, o := range in.Lists["interface"] {
				if o != i && slices.Contains(o.LeafLists["addresses"], a) {
					errs = append(errs, fail("addresses: %s is already on %s", a, o.Leaf("name")))
				}
			}
			continue
		}
		ip := netip.MustParsePrefix(a).Addr()
		if mode == fwconfig.ModeDHCP && ip.Is4() {
			errs = append(errs, fail("addresses: %s is an IPv4 address, and IPv4 comes from the DHCP client; remove it or make IPv4 static", a))
		}
		for _, o := range in.Lists["interface"] {
			if o == i {
				continue
			}
			for _, b := range o.LeafLists["addresses"] {
				if p, err := netip.ParsePrefix(b); err == nil && p.Addr() == ip {
					errs = append(errs, fail("addresses: %s is already on %s", ip, o.Leaf("name")))
				}
			}
		}
	}
	if on(i, "dhcpv6") {
		switch kind {
		case fwconfig.KindWireGuard, fwconfig.KindLoopback, fwconfig.Kind6in4, fwconfig.KindOpenVPN:
			errs = append(errs, fail("%s interfaces have no DHCPv6 client", kind))
		}
		if i.Leaf("ipv6-accept-ra") != "true" {
			errs = append(errs, fail("the DHCPv6 client needs router advertisements accepted: the default route comes from them"))
		}
	}
	if l := num(i, "dhcpv6-pd-length"); l != 0 && (l < 32 || l > 64) {
		errs = append(errs, fail("dhcpv6-pd-length: 32-64, or none to let the server choose"))
	}
	if kind == fwconfig.KindVLAN {
		if v := num(i, "vlan-id"); v < 1 || v > 4094 {
			errs = append(errs, fail("vlan-id: 1-4094"))
		}
		if i.Leaf("parent") == "" {
			errs = append(errs, fail("parent: a VLAN needs its parent interface"))
		}
	}
	if m := num(i, "mss-clamp-value"); m != 0 && (m < fwconfig.MinMSS || m > fwconfig.MaxMSS) {
		errs = append(errs, fail("mss-clamp-value: 0 or %d-%d", fwconfig.MinMSS, fwconfig.MaxMSS))
	}
	for _, l := range []string{"shape-egress", "shape-ingress"} {
		if v := num(i, l); v < 0 || v > fwconfig.MaxShapeMbit {
			errs = append(errs, fail("%s: 0-%d Mbit/s", l, fwconfig.MaxShapeMbit))
		}
	}
	if kind == fwconfig.Kind6in4 {
		if mode == fwconfig.ModeDHCP {
			errs = append(errs, fail("6in4 tunnels have static addresses"))
		}
		if i.Leaf("tunnel-remote") == "" {
			errs = append(errs, fail("tunnel-remote: the server's IPv4 address (Server IPv4 Address at tunnelbroker.net)"))
		}
		if id := i.Leaf("he-tunnel-id"); id != "" {
			if !fwconfig.ValidTunnelID(id) {
				errs = append(errs, fail("he-tunnel-id: the number tunnelbroker.net shows as Tunnel ID"))
			}
			if !fwconfig.ValidTunnelUser(i.Leaf("he-username")) {
				errs = append(errs, fail("he-username: the tunnelbroker.net account's user name"))
			}
			if k := i.Leaf("he-update-key"); k == "" || !fwconfig.ValidUpdateKey(k) {
				errs = append(errs, fail("he-update-key: the tunnel's Update Key (Advanced tab at tunnelbroker.net), at most 128 characters"))
			}
		}
	}
	if kind == fwconfig.KindVXLAN {
		port, _ := strconv.Atoi(i.Leaf("vxlan-port"))
		x := &fwconfig.VXLAN{VNI: uint32(num(i, "vxlan-vni")), Local: i.Leaf("vxlan-local"), Device: i.Leaf("vxlan-device"), Port: port, Remotes: i.LeafLists["vxlan-remotes"]}
		for _, p := range fwconfig.CheckVXLAN(name, x) {
			errs = append(errs, fail("%s", p))
		}
	}
	if vrf := i.Leaf("vrf"); vrf != "" {
		for _, b := range in.Lists["interface"] {
			if b.Leaf("kind") == fwconfig.KindBridge && slices.Contains(b.LeafLists["members"], name) {
				errs = append(errs, fail("vrf: %s is a member of bridge %s; put the bridge in the VRF", name, b.Leaf("name")))
			}
		}
	}
	if kind == fwconfig.KindOpenVPN {
		errs = append(errs, checkOpenVPN(c, i)...)
	}
	if role := i.Leaf("ha-role"); role != "" {
		switch {
		case role == fwconfig.HARoleManagement && i.Leaf("ha-gateway") == "":
			errs = append(errs, fail("ha-gateway: the management interface needs its gateway"))
		case kind != fwconfig.KindPhysical:
			errs = append(errs, fail("ha-role: a physical interface only"))
		case mode == fwconfig.ModeDHCP:
			errs = append(errs, fail("ha-role: the pair's links have static addresses"))
		case i.Leaf("vrf") != "":
			errs = append(errs, fail("ha-role: not on an interface in a VRF"))
		case !on(in, "is-default"):
			errs = append(errs, fail("ha-role: on an interface of the firewall itself, not of a virtual firewall"))
		}
		for _, o := range in.Lists["interface"] {
			if o != i && o.Leaf("ha-role") == role {
				errs = append(errs, fail("ha-role: %s has it", o.Leaf("name")))
			}
		}
	}
	return errs
}

func normalizeWgPeer(c *Ctx, p *datastore.Node) error {
	old := c.old(p)
	if p.Leaves["public-key"] == "" && old == nil {
		// No key given: the client's key pair is made here, so the GUI can
		// hand out a complete client config.
		priv, pub, err := wgkeys.Generate()
		if err != nil {
			return err
		}
		psk, err := wgkeys.PresharedKey()
		if err != nil {
			return err
		}
		set(p, "client-private-key", priv)
		set(p, "public-key", pub)
		set(p, "preshared-key", psk)
	}
	if old != nil && old.Leaf("public-key") != p.Leaf("public-key") {
		clear(p, "client-private-key") // a pasted key replaces the generated pair
	}
	return nil
}

func checkWgPeer(c *Ctx, p *datastore.Node) []error {
	var errs []error
	if p.Parent.Leaf("kind") != fwconfig.KindWireGuard {
		errs = append(errs, fail("a peer belongs to a WireGuard interface"))
	}
	if k := p.Leaf("public-key"); k == "" {
		errs = append(errs, fail("public-key: missing"))
	} else {
		for _, o := range p.Parent.Lists["wireguard-peer"] {
			if o != p && o.Leaf("public-key") == k {
				errs = append(errs, fail("public-key: peer %s has it", o.Leaf("name")))
			}
		}
	}
	if len(p.LeafLists["allowed-ips"]) == 0 {
		errs = append(errs, fail("allowed-ips: at least one CIDR (the peer's tunnel address, e.g. 10.99.0.2/32)"))
	}
	for _, n := range p.LeafLists["networks"] {
		if pfx, err := netip.ParsePrefix(n); err == nil && pfx.Bits() == 0 {
			errs = append(errs, fail("networks: %s would be a default route; add a static route through the interface instead", n))
		}
	}
	return errs
}

// ifaceNames are the names a rule may use for an interface of in: its
// interfaces and the ends of its links.
func ifaceNames(c *Ctx, in *datastore.Node) map[string]bool {
	out := map[string]bool{}
	for _, i := range in.Lists["interface"] {
		out[i.Leaf("name")] = true
	}
	name := in.Leaf("name")
	for _, l := range c.T.Root.Lists["link"] {
		if l.Leaf("instance-a") == name {
			out[l.Leaf("interface-a")] = true
		}
		if l.Leaf("instance-b") == name {
			out[l.Leaf("interface-b")] = true
		}
	}
	return out
}

// checkIfaceList checks a list of interface and interface zone names of
// in.
func checkIfaceList(c *Ctx, in *datastore.Node, leaf string, list []string) []error {
	var errs []error
	names := ifaceNames(c, in)
	for _, s := range list {
		if !names[s] && in.Entry("interface-zone", []string{s}) == nil {
			errs = append(errs, fail("%s: %q is not an interface or interface zone of this virtual firewall", leaf, s))
		}
	}
	return errs
}

func checkInterfaceZone(c *Ctx, z *datastore.Node) []error {
	in := instanceOf(z)
	var errs []error
	names := ifaceNames(c, in)
	if names[z.Leaf("name")] {
		errs = append(errs, fail("name: %s is an interface of this virtual firewall", z.Leaf("name")))
	}
	for _, s := range z.LeafLists["interfaces"] {
		if !names[s] {
			errs = append(errs, fail("interfaces: %q is not an interface of this virtual firewall", s))
		}
	}
	return errs
}

func checkStaticNeighbour(c *Ctx, n *datastore.Node) []error {
	a := netip.MustParseAddr(n.Leaf("address"))
	if a.IsMulticast() || a.IsUnspecified() {
		return []error{fail("address: %s is not a host's address", a)}
	}
	return nil
}

func checkRoute(c *Ctx, r *datastore.Node) []error {
	var errs []error
	gw, bfd := r.Leaf("gateway"), on(r, "bfd")
	if gw == "" && r.Leaf("interface") == "" {
		errs = append(errs, fail("a route needs a gateway or an interface"))
	}
	if bfd {
		if gw == "" {
			errs = append(errs, fail("bfd: BFD watches the gateway; a route with BFD needs one"))
		}
		if num(r, "metric") > 255 {
			errs = append(errs, fail("metric: with BFD, the metric is FRR's administrative distance: 0-255"))
		}
		if v := r.Leaf("vrf"); v != "" && v != "main" {
			errs = append(errs, fail("bfd: a route with BFD can't be in a VRF"))
		}
	}
	return errs
}

func checkPolicyRoute(c *Ctx, r *datastore.Node) []error {
	in := instanceOf(r)
	errs := checkIfaceList(c, in, "in-interfaces", r.LeafLists["in-interfaces"])
	if name := r.Leaf("interface"); name != "" {
		if i := in.Entry("interface", []string{name}); i != nil && i.Leaf("vrf") != "" {
			errs = append(errs, fail("interface: %s is in VRF %s; policy routes use the main table", name, i.Leaf("vrf")))
		}
	}
	return errs
}

func checkLink(c *Ctx, l *datastore.Node) []error {
	var errs []error
	a, b := l.Leaf("instance-a"), l.Leaf("instance-b")
	if a == b {
		return []error{fail("a link connects two different virtual firewalls")}
	}
	ia, ib := c.T.Root.Entry("instance", []string{a}), c.T.Root.Entry("instance", []string{b})
	if ia != nil && ib != nil && ia.Leaf("firewall") != ib.Leaf("firewall") {
		errs = append(errs, fail("a link connects virtual firewalls on one firewall; %s is on %s, %s on %s", a, ia.Leaf("firewall"), b, ib.Leaf("firewall")))
	}
	for _, end := range []struct {
		in    *datastore.Node
		iface string
		side  string
	}{{ia, l.Leaf("interface-a"), "interface-a"}, {ib, l.Leaf("interface-b"), "interface-b"}} {
		if end.in == nil {
			continue
		}
		if end.in.Entry("interface-zone", []string{end.iface}) != nil {
			errs = append(errs, fail("%s: an interface zone is named %s", end.side, end.iface))
		}
		if end.in.Entry("vrf", []string{end.iface}) != nil {
			errs = append(errs, fail("%s: a VRF is named %s", end.side, end.iface))
		}
		if end.in.Entry("interface", []string{end.iface}) != nil {
			errs = append(errs, fail("%s: %s is an interface of %s", end.side, end.iface, end.in.Leaf("name")))
		}
	}
	return errs
}
