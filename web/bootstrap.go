// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/datastore"
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
	// DefaultRouteLAN gives the DHCP LAN's default route to the firewall
	// instead of the DHCP WAN's; only when both use DHCP.
	DefaultRouteLAN bool
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
	if o.DefaultRouteLAN && (o.Address.IsValid() || o.WAN == "" || o.WANAddress.IsValid()) {
		return errors.New("the default route from the LAN needs DHCP on both the LAN and the WAN")
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
	if st.LastCommit > 0 && !o.Reconfigure {
		return nil, errors.New("this installation has been deployed already; configure it in the GUI, or run portitor-setup")
	}
	fwID, err := firstFirewallID(s.db)
	if err != nil {
		return nil, err
	}
	if o.AgentFingerprint != "" {
		if err := s.db.Model(&models.Firewall{}).Where("id = ?", fwID).Updates(map[string]any{
			"agent_url":         strings.TrimRight(o.AgentURL, "/"),
			"agent_token":       o.AgentToken,
			"agent_fingerprint": normalizeFingerprint(o.AgentFingerprint),
		}).Error; err != nil {
			return nil, err
		}
	}

	// The agent has usually just started.
	a, _, err := s.firewallAgent(fwID)
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
	if _, err := s.syncNICs(fwID, status.NICs); err != nil {
		return nil, err
	}

	v, err := s.view(ctx)
	if err != nil {
		return nil, err
	}
	host := ""
	for _, in := range v.Instances {
		if in.IsDefault && in.FirewallID == fwID {
			host = in.Name
		}
	}
	if host == "" {
		return nil, errors.New("the firewall has no default instance")
	}
	err = s.editConfig(ctx, func(work *datastore.Tree) error {
		b := &bootTree{s: s, work: work, inst: datastore.Path{{Name: "instance", Keys: []string{host}}}}
		if err := b.network(o); err != nil {
			return err
		}
		return b.dns(o)
	})
	var br *badRequest
	if errors.As(err, &br) {
		return nil, errors.New(br.msg)
	}
	if err != nil {
		return nil, err
	}
	noConfirm := 0
	res, err := s.deployCandidate(ctx, "bootstrap", &noConfirm)
	var dep *models.Deployment
	if res != nil && len(res.Deployments) > 0 {
		dep = &res.Deployments[0]
	}
	if err != nil {
		var ve *fwconfig.ValidationError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("%w: %s", err, strings.Join(ve.Problems, "; "))
		}
		return dep, err
	}
	slog.Info("bootstrap deployed", "lan", o.LAN, "address", o.Address, "wan", o.WAN, "reconfigure", o.Reconfigure, "commit", res.Commit)
	return dep, nil
}

// bootTree makes bootstrap's configuration in the firewall's host, inst,
// in a working copy of the candidate.
type bootTree struct {
	s    *Server
	work *datastore.Tree
	inst datastore.Path
}

func (b *bootTree) at(more ...datastore.Elem) datastore.Path {
	return append(slices.Clone(b.inst), more...)
}

func (b *bootTree) node() *datastore.Node {
	n, _, _ := b.work.Find(b.inst)
	return n
}

// set sets the leaves of the entry at p (a string, bool, number or list
// each; "" or an empty list unsets one).
func (b *bootTree) set(p datastore.Path, leaves map[string]any) error {
	for _, k := range slices.Sorted(maps.Keys(leaves)) {
		lp := append(slices.Clone(p), datastore.Elem{Name: k})
		var err error
		switch v := leaves[k].(type) {
		case []string:
			if len(v) == 0 {
				err = b.unset(lp)
			} else {
				err = b.work.SetList(lp, v)
			}
		case string:
			if v == "" {
				err = b.unset(lp)
			} else {
				err = b.work.Set(lp, v)
			}
		default:
			err = b.work.Set(lp, fmt.Sprint(v))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// unset removes the leaf (or leaf-list) at p, if it is set.
func (b *bootTree) unset(p datastore.Path) error {
	n, _, err := b.work.Find(p[:len(p)-1])
	if err != nil || n == nil {
		return err
	}
	leaf := p[len(p)-1].Name
	if _, ok := n.Leaves[leaf]; !ok && len(n.LeafLists[leaf]) == 0 {
		return nil
	}
	return b.work.Delete(p)
}

// create adds an entry to the list at p, given its next id if the list is
// keyed by one.
func (b *bootTree) create(p datastore.Path, entry map[string]any) error {
	body, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if body, err = b.s.assignID(b.work, p, body); err != nil {
		return err
	}
	return b.work.EditJSON(p, datastore.EditCreate, body)
}

func (b *bootTree) network(o BootstrapOptions) error {
	if err := b.iface(o.LAN, o.Address, "LAN", o.WAN != "" && !o.DefaultRouteLAN, o.Reconfigure); err != nil {
		return err
	}
	if err := b.dhcp(o); err != nil {
		return err
	}
	if o.WAN != "" {
		if err := b.iface(o.WAN, o.WANAddress, "WAN", o.DefaultRouteLAN, o.Reconfigure); err != nil {
			return err
		}
	}
	in := b.node()
	routes := b.at(datastore.Elem{Name: "route"})
	if o.Reconfigure {
		if err := b.defaultRoute(o.Gateway); err != nil {
			return err
		}
	} else if o.Gateway.IsValid() {
		dest := "0.0.0.0/0"
		if o.Gateway.Is6() {
			dest = "::/0"
		}
		if !slices.ContainsFunc(in.Lists["route"], func(r *datastore.Node) bool { return r.Leaf("destination") == dest }) {
			if err := b.create(routes, map[string]any{"destination": dest, "gateway": o.Gateway.String(), "enabled": true, "description": "default route"}); err != nil {
				return err
			}
		}
	}

	lan, wan := []string{o.LAN}, []string{o.WAN}
	mgmt, err := b.mgmtService(o)
	if err != nil {
		return err
	}
	type rule struct {
		chain, desc string
		in, out     []string
		services    []string
	}
	rules := []rule{
		{fwconfig.ChainInput, "management from the LAN", lan, nil, []string{mgmt}},
		{fwconfig.ChainInput, "ping from the LAN", lan, nil, []string{"all-icmp"}},
	}
	if o.WAN != "" {
		rules = append(rules, rule{fwconfig.ChainForward, "LAN to WAN", lan, wan, nil})
	}
	for _, r := range rules {
		// The input rules are the LAN's way in: reconfigure enables them,
		// and creates them if missing. The forward rule is created by the
		// first bootstrap only; reconfigure moves it to the new LAN and WAN.
		keep := r.chain == fwconfig.ChainInput
		var same []*datastore.Node
		for _, e := range b.node().Lists["rule"] {
			if e.Leaf("chain") == r.chain && e.Leaf("description") == r.desc {
				same = append(same, e)
			}
		}
		if len(same) > 0 {
			if !o.Reconfigure {
				continue
			}
			// The rules follow the (new) LAN and WAN.
			for _, e := range same {
				leaves := map[string]any{"in-interfaces": r.in, "out-interfaces": r.out}
				if keep {
					leaves["enabled"] = true
				}
				if err := b.set(datastore.PathOf(e), leaves); err != nil {
					return err
				}
			}
			continue
		}
		if o.Reconfigure && !keep {
			continue
		}
		entry := map[string]any{"chain": r.chain, "in-interfaces": r.in, "description": r.desc, "action": fwconfig.ActionAccept, "enabled": true}
		if r.out != nil {
			entry["out-interfaces"] = r.out
		}
		if r.services != nil {
			entry["services"] = r.services
		}
		if err := b.create(b.at(datastore.Elem{Name: "rule"}), entry); err != nil {
			return err
		}
	}

	if o.WAN == "" {
		return nil
	}
	// The LAN reaches the Internet through the WAN's address.
	const natDesc = "masquerade to the WAN"
	var masq []*datastore.Node
	for _, e := range b.node().Lists["nat-rule"] {
		if e.Leaf("kind") == fwconfig.NATMasquerade && e.Leaf("description") == natDesc {
			masq = append(masq, e)
		}
	}
	switch {
	case len(masq) > 0 && o.Reconfigure:
		for _, e := range masq {
			if err := b.set(datastore.PathOf(e), map[string]any{"out-interfaces": wan}); err != nil {
				return err
			}
		}
		return nil
	case len(masq) > 0 || o.Reconfigure:
		return nil
	}
	return b.create(b.at(datastore.Elem{Name: "nat-rule"}), map[string]any{"kind": fwconfig.NATMasquerade, "out-interfaces": wan, "enabled": true, "description": natDesc})
}

// dhcp serves the DHCP range on the LAN prefix (iface created it, or the
// user did), with the default gateway, and turns the instance's DHCP
// server on.
func (b *bootTree) dhcp(o BootstrapOptions) error {
	if !o.DHCPStart.IsValid() {
		return nil
	}
	leaves := map[string]any{"dhcp-enabled": true}
	// Clients get the domain of the zone that holds fw (dns), so
	// https://fw reaches the GUI; a domain the user set stays.
	if b.node().Leaf("dhcp-domain-name") == "" {
		leaves["dhcp-domain-name"] = bootstrapZone
	}
	if err := b.set(b.inst, leaves); err != nil {
		return err
	}
	prefix := o.Address.Masked().String()
	at := b.at(datastore.Elem{Name: "ipam-prefix", Keys: []string{prefix}})
	if p, _, _ := b.work.Find(at); p == nil {
		return bad(fmt.Sprintf("there is no prefix %s in IPAM", prefix))
	}
	leaves = map[string]any{"dhcp-enabled": true, "dhcp-range-start": o.DHCPStart.String(), "dhcp-range-end": o.DHCPEnd.String()}
	if len(o.DHCPDNS) > 0 {
		var dns []string
		for _, a := range o.DHCPDNS {
			dns = append(dns, a.String())
		}
		leaves["dhcp-dns-servers"] = dns
	}
	return b.set(at, leaves)
}

// bootstrapZone is the zone bootstrap creates, and the DHCP domain.
const bootstrapZone = "home.arpa"

// dns creates a starting point for DNS where there is none: the SOA
// template soa-1, the DNS template dns-1 with the firewall as
// ns1.home.arpa (at the LAN address, if static), and the zone home.arpa,
// with the firewall as fw.home.arpa (fwRecord). The templates are the
// instance's, global.
func (b *bootTree) dns(o BootstrapOptions) error {
	in := b.node()
	soa := ""
	if l := in.Lists["dns-soa-template"]; len(l) > 0 {
		soa = l[0].Leaf("name")
	} else {
		soa = "soa-1"
		if err := b.create(b.at(datastore.Elem{Name: "dns-soa-template"}), map[string]any{"name": soa, "global": true,
			"mname": "ns1.home.arpa.", "rname": "unknown@home.arpa", "refresh": 86400, "retry": 7200, "expire": 3600000, "minimum": 3600}); err != nil {
			return err
		}
	}
	tmpl := ""
	if l := in.Lists["dns-template"]; len(l) > 0 {
		tmpl = l[0].Leaf("name")
	} else {
		tmpl = "dns-1"
		ns := map[string]any{"name": "ns1.home.arpa.", "address": ""}
		if o.Address.IsValid() {
			ns["address"] = o.Address.Addr().String()
		}
		if err := b.create(b.at(datastore.Elem{Name: "dns-template"}), map[string]any{"name": tmpl, "global": true,
			"soa-template": soa, "default-ttl": 3600, "nameserver": []any{ns}}); err != nil {
			return err
		}
	}
	if len(in.Lists["dns-zone"]) == 0 {
		if err := b.create(b.at(datastore.Elem{Name: "dns-zone"}), map[string]any{"name": bootstrapZone, "type": fwconfig.ZoneForward, "dns-template": tmpl}); err != nil {
			return err
		}
	}
	return b.fwRecord(o)
}

// fwRecord points fw.home.arpa at the static IPv4 LAN address, if the
// instance has the zone home.arpa: it creates the A record, or moves it
// to the new address on reconfigure.
func (b *bootTree) fwRecord(o BootstrapOptions) error {
	if !o.Address.IsValid() || !o.Address.Addr().Is4() {
		return nil
	}
	z := b.node().Entry("dns-zone", []string{bootstrapZone})
	if z == nil || z.Leaf("type") != fwconfig.ZoneForward {
		return nil
	}
	var rec *datastore.Node
	for _, r := range z.Lists["record"] {
		if r.Leaf("name") == "fw" && r.Leaf("type") == "A" && (rec == nil || atoiLeaf(r, "id") < atoiLeaf(rec, "id")) {
			rec = r
		}
	}
	addr := o.Address.Addr().String()
	switch {
	case rec != nil && !o.Reconfigure:
		return nil
	case rec != nil:
		return b.set(datastore.PathOf(rec), map[string]any{"value": addr})
	}
	return b.create(append(datastore.PathOf(z), datastore.Elem{Name: "record"}), map[string]any{"name": "fw", "type": "A", "value": addr, "description": "the firewall (the GUI)"})
}

func atoiLeaf(n *datastore.Node, leaf string) int {
	v, _ := strconv.Atoi(n.Leaf(leaf))
	return v
}

// mgmtService returns the name of the management service: SSH and the
// GUI port (when portitor-web runs here), kept at the port on reconfigure.
func (b *bootTree) mgmtService(o BootstrapOptions) (string, error) {
	const name = "portitor-mgmt"
	port := func(p int) map[string]any {
		return map[string]any{"protocol": "tcp", "dst-lo": p, "dst-hi": 0, "src-lo": 0, "src-hi": 0}
	}
	ports := []map[string]any{port(22)}
	if o.GUIPort > 0 && o.GUIPort != 22 {
		ports = append(ports, port(o.GUIPort))
	}
	at := datastore.Path{{Name: "service", Keys: []string{name}}}
	switch old, _, err := b.work.Find(at); {
	case err != nil:
		return "", err
	case old == nil:
		return name, b.create(datastore.Path{{Name: "service"}}, map[string]any{"name": name, "type": models.ServiceTypePorts,
			"description": "Portitor management: SSH and the GUI", "port": ports})
	case o.Reconfigure:
		body, err := json.Marshal(ports)
		if err != nil {
			return "", err
		}
		return name, b.work.EditJSON(append(at, datastore.Elem{Name: "port"}), datastore.EditReplace, body)
	}
	return name, nil
}

// defaultRoute makes gw the only IPv4 default route, or removes them
// when gw is not valid (a DHCP WAN brings its own).
func (b *bootTree) defaultRoute(gw netip.Addr) error {
	var routes []*datastore.Node
	for _, r := range b.node().Lists["route"] {
		if d := r.Leaf("destination"); d == "0.0.0.0/0" || d == "default" {
			routes = append(routes, r)
		}
	}
	slices.SortFunc(routes, func(x, y *datastore.Node) int { return atoiLeaf(x, "id") - atoiLeaf(y, "id") })
	kept := false
	for _, r := range routes {
		if r.Leaf("destination") == "default" {
			if a, err := netip.ParseAddr(r.Leaf("gateway")); err != nil || !a.Is4() {
				continue
			}
		}
		if !gw.IsValid() || kept {
			if err := b.work.Delete(datastore.PathOf(r)); err != nil {
				return err
			}
			continue
		}
		if err := b.set(datastore.PathOf(r), map[string]any{"destination": "0.0.0.0/0", "gateway": gw.String(), "interface": "", "enabled": true}); err != nil {
			return err
		}
		kept = true
	}
	if !gw.IsValid() || kept {
		return nil
	}
	return b.create(b.at(datastore.Elem{Name: "route"}), map[string]any{"destination": "0.0.0.0/0", "gateway": gw.String(), "enabled": true, "description": "default route"})
}

// iface enables an interface, labelled role (LAN or WAN) unless the user
// labelled it: static with address (its prefix goes into IPAM, described
// as role), or DHCP when address is not valid, without a default route if
// noRoute. A static LAN gets DNS listening. With reconfigure, or DHCP,
// address becomes the interface's only IPv4 address, taken from another
// interface if need be.
func (b *bootTree) iface(name string, address netip.Prefix, role string, noRoute, reconfigure bool) error {
	ifc := b.node().Entry("interface", []string{name})
	if ifc == nil {
		return bad(fmt.Sprintf("the agent reports no interface %s", name))
	}
	leaves := map[string]any{"enabled": true, "dhcp-no-default-route": noRoute}
	// The role as label, unless the user has labelled the interface; the
	// description goes if the user has not written one (bootstrap used to
	// put the role there).
	switch ifc.Leaf("label") {
	case "", "LAN", "WAN":
		leaves["label"] = role
	}
	switch ifc.Leaf("description") {
	case "found on the firewall", "LAN", "WAN":
		leaves["description"] = ""
	}
	// The firewall answers DNS on a static LAN, and DHCP hands it out
	// there, so LAN clients find fw.home.arpa (fwRecord).
	if role == "LAN" && address.IsValid() {
		leaves["dns-listen"] = true
	}
	switch {
	case !address.IsValid():
		leaves["ipv4-mode"] = fwconfig.ModeDHCP
	case address.Addr().Is4():
		leaves["ipv4-mode"] = fwconfig.ModeStatic
	}
	// The addresses to keep: with reconfigure or DHCP no other IPv4 one,
	// and none with the new address's IP (it comes back with its length).
	addrs := []string{}
	for _, a := range ifc.LeafLists["addresses"] {
		p, err := netip.ParsePrefix(a)
		if err != nil || (address.IsValid() && p.Addr() == address.Addr()) ||
			(p.Addr().Is4() && (reconfigure || !address.IsValid())) {
			continue
		}
		addrs = append(addrs, a)
	}
	if address.IsValid() {
		addrs = append(addrs, address.String())
		if err := b.takeAddress(name, address.Addr(), reconfigure); err != nil {
			return err
		}
	}
	leaves["addresses"] = addrs
	if err := b.set(datastore.PathOf(ifc), leaves); err != nil {
		return err
	}
	if !address.IsValid() || address.IsSingleIP() {
		return nil
	}
	prefix := address.Masked().String()
	if b.node().Entry("ipam-prefix", []string{prefix}) == nil {
		return b.create(b.at(datastore.Elem{Name: "ipam-prefix"}), map[string]any{"prefix": prefix, "description": role})
	}
	return nil
}

// takeAddress removes ip from the instance's other interfaces than name,
// with reconfigure; without, an address on another interface is an error.
func (b *bootTree) takeAddress(name string, ip netip.Addr, reconfigure bool) error {
	for _, o := range b.node().Lists["interface"] {
		if o.Leaf("name") == name {
			continue
		}
		keep := []string{}
		for _, a := range o.LeafLists["addresses"] {
			if p, err := netip.ParsePrefix(a); err != nil || p.Addr() != ip {
				keep = append(keep, a)
			}
		}
		if len(keep) == len(o.LeafLists["addresses"]) {
			continue
		}
		if !reconfigure {
			return bad(fmt.Sprintf("%s is on another interface (%s)", ip, o.Leaf("name")))
		}
		if err := b.set(datastore.PathOf(o), map[string]any{"addresses": keep}); err != nil {
			return err
		}
	}
	return nil
}

// ParseDHCPRange parses "192.168.1.100-192.168.1.199".
func ParseDHCPRange(s string) (start, end netip.Addr, err error) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return start, end, errors.New("start-end, e.g. 192.168.1.100-192.168.1.199")
	}
	if start, err = netip.ParseAddr(strings.TrimSpace(a)); err != nil {
		return start, end, err
	}
	end, err = netip.ParseAddr(strings.TrimSpace(b))
	return start, end, err
}
