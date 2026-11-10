// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"crypto/sha256"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// HA nodes.
const (
	HAPrimary   = "primary"
	HASecondary = "secondary"
)

// HA makes the document's host one of an active/passive HA pair. Both
// hosts apply the same document but for Node and the addresses of their
// own two links (Interface.HARole). One is active; the other's traffic
// interfaces are closed by the gate (render.Gate), so it neither forwards
// nor answers, and it takes over with the same addresses and MAC addresses
// (Interface.MAC) when it holds the witness's vote and has heard the
// active host's promises run out (internal/agent/ha.go).
type HA struct {
	Node string `json:"node"`
	// Peer is the other host's agent API (https://...), its certificate
	// pinned by PeerFingerprint (SHA-256, hex).
	Peer            string `json:"peer"`
	PeerFingerprint string `json:"peer_fingerprint"`
	// PeerLink is the same agent over the HA link: the heartbeat's other
	// path.
	PeerLink string `json:"peer_link"`
	// Secret is shared by the pair for the heartbeat (/v1/ha/heartbeat)
	// and the copy of the certificates; the secondary's portitor-config
	// copies the primary's database with it too.
	Secret string `json:"secret" secret:"true"`
	// WitnessSecret, when the pair's witness is external (portitor-web on
	// a third host), opens GET /v1/ha and POST /v1/ha/vote to it alone.
	WitnessSecret string `json:"witness_secret,omitempty" secret:"true"`
	// PeerConfig is the peer's portitor-config (https://...), its tls_cert
	// pinned by PeerConfigFingerprint: where the secondary's
	// portitor-config copies the configuration from. Empty: none.
	PeerConfig            string `json:"peer_config,omitempty"`
	PeerConfigFingerprint string `json:"peer_config_fingerprint,omitempty"`
	// Epoch counts the pair's promotions: a secondary promoted to primary
	// raises it. A primary that hears a peer that is primary at a higher
	// epoch has been taken over: it is stale, fenced and standby, until it
	// is given the document of the secondary it now is.
	Epoch int64 `json:"epoch,omitempty"`
	// ConfigPort is this host's portitor-config port (its own
	// portitor-config URL's), which the default instance opens to the
	// peer's addresses (HAConfigAccess): the secondary copies the
	// configuration from the primary, and the other way round once it is
	// promoted. 0: none.
	ConfigPort int `json:"config_port,omitempty"`
	// AgentPort is this host's agent port, opened to the peer's addresses
	// for the heartbeat. 0: none.
	AgentPort int `json:"agent_port,omitempty"`
}

// HAGatewayPeer, as the management interface's gateway, is the peer's
// management address (Interface.HAGatewayPeer).
const HAGatewayPeer = "peer"

// HAPeerGateway is the peer's management address when the pair's hosts
// are each other's management gateway, "" otherwise, with the interface:
// the open host forwards and masquerades what comes from it.
func (in *Instance) HAPeerGateway() (dev, addr string) {
	if !in.Default {
		return "", ""
	}
	if ifc := in.HAInterface(HARoleManagement); ifc != nil && ifc.HAGatewayPeer {
		return ifc.Name, ifc.HAGateway
	}
	return "", ""
}

// HAMgmtTable is the routing table of what an HA host sends from its
// management address, and on the standby all it sends itself: the main
// table points at traffic interfaces, which are closed there.
const HAMgmtTable = 6800

// HA interface roles (Interface.HARole).
const (
	HARoleLink       = "ha_link"
	HARoleManagement = "management"
)

// GateDevices are the devices the gate holds in an instance of an HA pair:
// its physical traffic interfaces. A gate on the lowest device covers the
// VLANs and bridges on it.
func (in *Instance) GateDevices() []string {
	var out []string
	for _, ifc := range in.Interfaces {
		if ifc.Kind == KindPhysical && ifc.HARole == "" {
			out = append(out, ifc.Name)
		}
	}
	return out
}

// MonitoredDevices are the enabled devices whose carrier counts in the
// host's health.
func (in *Instance) MonitoredDevices() []string {
	var out []string
	for _, ifc := range in.Interfaces {
		if ifc.HAMonitor && ifc.Enabled {
			out = append(out, ifc.Name)
		}
	}
	return out
}

// HASyncPrefix starts the names of the devices virtual firewalls sync
// connections over; no interface may be called that.
const HASyncPrefix = "ha-"

// HASync is a virtual firewall's own way to its peer on an HA pair: a
// macvlan device on the host's HA link, in the instance's namespace, with
// a link-local address of its own (HALinkAddress). So conntrackd there reaches the peer's, on a
// cable or a hypervisor's access port alike, which tagged VLANs may not
// survive.
type HASync struct {
	Name    string `json:"name"`
	Parent  string `json:"parent"`
	Address string `json:"address"` // CIDR, this host's, link-local
}

// HALinkBits is the prefix length of the pair's addresses on the HA link.
const HALinkBits = 64

// HALinkAddress is a host's IPv6 link-local address on the HA link, by its
// node (HAPrimary or HASecondary): fe80::1 and fe80::2 for the default
// instance (id 0), fe80::<id>:1 and fe80::<id>:2 for a virtual firewall's
// device on it. Fixed by role, so neither host has to discover the other,
// and a promotion only swaps them; no address is entered for the link.
func HALinkAddress(node string, id uint32) netip.Addr {
	var b [16]byte
	b[0], b[1] = 0xfe, 0x80
	b[10], b[11], b[12], b[13] = byte(id>>24), byte(id>>16), byte(id>>8), byte(id)
	b[15] = 1
	if node == HASecondary {
		b[15] = 2
	}
	return netip.AddrFrom16(b)
}

// IsHALinkAddress reports whether a is one of HALinkAddress's: the agent
// removes those it no longer wants from the HA link, leaving the kernel's
// own link-local address alone.
func IsHALinkAddress(a netip.Addr) bool {
	if !a.Is6() || !a.IsLinkLocalUnicast() {
		return false
	}
	b := a.WithZone("").As16()
	return b[2]|b[3]|b[4]|b[5]|b[6]|b[7]|b[8]|b[9]|b[14] == 0 && (b[15] == 1 || b[15] == 2)
}

// haBlackholeMetric is above any route in use.
const haBlackholeMetric = 1<<31 - 1

// HABlackholes are the last-resort routes of the instance's static prefixes
// on an HA pair. A link that dies takes its connected route along, and the
// clients' traffic would then follow the default route out of the WAN: with
// their private addresses, and until the standby takes over.
func (in *Instance) HABlackholes() []Route {
	if len(in.GateDevices()) == 0 {
		return nil
	}
	var out []Route
	seen := map[netip.Prefix]bool{}
	for _, ifc := range in.Interfaces {
		if ifc.HARole != "" || !ifc.Enabled || (ifc.Kind != KindPhysical && ifc.Kind != KindVLAN && ifc.Kind != KindBridge) {
			continue
		}
		for _, a := range ifc.Addresses {
			p, err := ParseInterfaceAddress(a)
			if err != nil || p.IsSingleIP() {
				continue
			}
			m := p.Masked()
			if seen[m] {
				continue
			}
			seen[m] = true
			out = append(out, Route{Destination: m.String(), Metric: haBlackholeMetric, VRF: ifc.VRF, Blackhole: true})
		}
	}
	return out
}

// HAInterface is the interface of a role in the instance, nil if none.
func (in *Instance) HAInterface(role string) *Interface {
	for i := range in.Interfaces {
		if in.Interfaces[i].HARole == role {
			return &in.Interfaces[i]
		}
	}
	return nil
}

// HAConfigAccess is what Expand gives an HA host's default instance from
// HA: the ports of its portitor-config and agent, opened to the peer's
// addresses (the auto rule render.HAConfigService), and the agent's to the
// peer's link-local address on the HA link (Link, LinkPeer).
type HAConfigAccess struct {
	Port      int
	AgentPort int
	From      []string
	Link      string
	LinkPeer  string
}

// configAccess: the peer's addresses are those written as addresses in
// its agent and portitor-config URLs; a name gives none. A link-local
// address (PeerLink's) is known on its interface alone.
func (h *HA) configAccess() *HAConfigAccess {
	if h == nil || (h.ConfigPort == 0 && h.AgentPort == 0) {
		return nil
	}
	acc := &HAConfigAccess{Port: h.ConfigPort, AgentPort: h.AgentPort}
	for _, s := range []string{h.Peer, h.PeerLink, h.PeerConfig} {
		u, err := url.Parse(s)
		if err != nil {
			continue
		}
		a, err := netip.ParseAddr(u.Hostname())
		if err != nil {
			continue
		}
		if a.Zone() != "" {
			if acc.Link == "" && h.AgentPort != 0 {
				acc.Link, acc.LinkPeer = a.Zone(), a.WithZone("").String()
			}
			continue
		}
		if !slices.Contains(acc.From, a.Unmap().String()) {
			acc.From = append(acc.From, a.Unmap().String())
		}
	}
	if len(acc.From) == 0 && acc.Link == "" {
		return nil
	}
	return acc
}

var (
	haFingerprintRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	haSecretRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
	// A locally administered unicast address, in lowercase as ip -j shows it.
	haMACRe = regexp.MustCompile(`^[0-9a-f][26ae](:[0-9a-f]{2}){5}$`)
)

// DeriveHAMAC is the MAC address a pair's two hosts share on the traffic
// interface name: locally administered, from the pair's key.
func DeriveHAMAC(pair, name string) string {
	sum := sha256.Sum256([]byte("portitor ha mac\x00" + pair + "\x00" + name))
	sum[0] = sum[0]&^0x01 | 0x02
	return net.HardwareAddr(sum[:6]).String()
}

func (v *validator) ha(h *HA) {
	if h == nil {
		return
	}
	if h.Node != HAPrimary && h.Node != HASecondary {
		v.addf("ha: node must be %s or %s", HAPrimary, HASecondary)
	}
	if u, err := url.Parse(h.Peer); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		v.addf("ha: peer must be the other host's agent URL (https://<address>:8443)")
	}
	if !haFingerprintRe.MatchString(h.PeerFingerprint) {
		v.addf("ha: peer fingerprint must be 64 lowercase hex characters")
	}
	if !haSecretRe.MatchString(h.Secret) {
		v.addf("ha: secret must be 32-128 URL-safe base64 characters")
	}
	if h.WitnessSecret != "" && (!haSecretRe.MatchString(h.WitnessSecret) || h.WitnessSecret == h.Secret) {
		v.addf("ha: witness secret must be 32-128 URL-safe base64 characters, not the pair's secret")
	}
	if h.PeerConfig != "" {
		if u, err := url.Parse(h.PeerConfig); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			v.addf("ha: peer config must be the other host's portitor-config URL (https://<address>:<port>)")
		}
		if !haFingerprintRe.MatchString(h.PeerConfigFingerprint) {
			v.addf("ha: peer config fingerprint must be 64 lowercase hex characters")
		}
	}
	if h.Epoch < 0 {
		v.addf("ha: epoch must not be negative")
	}
	if h.ConfigPort < 0 || h.ConfigPort > 65535 {
		v.addf("ha: config port must be 1-65535")
	}
	if h.AgentPort < 0 || h.AgentPort > 65535 {
		v.addf("ha: agent port must be 1-65535")
	}
	if u, err := url.Parse(h.PeerLink); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		v.addf("ha: peer link must be the other host's agent URL on the HA link")
	}
	if h.PeerLink == h.Peer {
		v.addf("ha: the HA link and the management network must be two paths")
	}
}

// haInterfaces checks the interfaces' HA settings, for the whole document.
func (v *validator) haInterfaces(d *Document) {
	for i := range d.Instances {
		in := &d.Instances[i]
		p := "instance " + in.Name
		for _, ifc := range in.Interfaces {
			if ifc.MAC != "" && !haMACRe.MatchString(ifc.MAC) {
				v.addf("%s: interface %s: mac must be a locally administered unicast address", p, ifc.Name)
			}
			if ifc.HAMonitor && (ifc.Kind != KindPhysical || ifc.HARole != "") {
				v.addf("%s: interface %s: only a physical traffic interface is monitored", p, ifc.Name)
			}
			if ifc.MAC != "" && ifc.Kind != KindPhysical {
				v.addf("%s: interface %s: only a physical interface has a mac", p, ifc.Name)
			}
			if ifc.HAGatewayPeer && ifc.HARole != HARoleManagement {
				v.addf("%s: interface %s: only the management interface has the peer as its gateway", p, ifc.Name)
			}
			switch ifc.HARole {
			case "":
				if ifc.HAGateway != "" {
					v.addf("%s: interface %s: only the management interface has an HA gateway", p, ifc.Name)
				}
				continue
			case HARoleLink, HARoleManagement:
			default:
				v.addf("%s: interface %s: HA role must be %s or %s", p, ifc.Name, HARoleLink, HARoleManagement)
				continue
			}
			if !in.Default {
				v.addf("%s: interface %s: an HA role is the host's, on an interface of its default instance", p, ifc.Name)
			}
			if ifc.Kind != KindPhysical {
				v.addf("%s: interface %s: an HA role needs a physical interface", p, ifc.Name)
			}
			if ifc.MAC != "" {
				v.addf("%s: interface %s: an HA link or management interface keeps its own mac", p, ifc.Name)
			}
			if ifc.VRF != "" {
				v.addf("%s: interface %s: an HA link or management interface can't be in a VRF", p, ifc.Name)
			}
			if ifc.HARole == HARoleLink && ifc.HAGateway != "" {
				v.addf("%s: interface %s: only the management interface has an HA gateway", p, ifc.Name)
			}
			if ifc.HARole == HARoleManagement {
				v.haGateway(p, ifc)
			}
		}
		for _, role := range []string{HARoleLink, HARoleManagement} {
			if n := len(slices.DeleteFunc(slices.Clone(in.Interfaces), func(ifc Interface) bool { return ifc.HARole != role })); n > 1 {
				v.addf("%s: only one interface can be the %s", p, role)
			}
		}
		if h := in.HASync; h != nil {
			if !strings.HasPrefix(h.Name, HASyncPrefix) || !ValidIfname(h.Name) || !ValidIfname(h.Parent) || in.Default {
				v.addf("%s: invalid HA sync device %q on %q", p, h.Name, h.Parent)
			}
			if a, err := ParseInterfaceAddress(h.Address); err != nil || !a.Addr().IsLinkLocalUnicast() || !a.Addr().Is6() {
				v.addf("%s: HA sync device: %q is not an IPv6 link-local address with its prefix", p, h.Address)
			}
		}
		if d.HA == nil {
			continue
		}
		if len(in.VRRP) > 0 {
			v.addf("%s: VRRP is not used on an HA pair: the pair shares its addresses", p)
		}
		if !in.Default {
			continue
		}
		for _, role := range []string{HARoleLink, HARoleManagement} {
			ifc := in.HAInterface(role)
			if ifc == nil {
				v.addf("%s: an HA pair needs a physical interface with the role %s", p, role)
				continue
			}
			if !ifc.Enabled {
				v.addf("%s: interface %s: the %s must be enabled", p, ifc.Name, role)
			}
			if len(ifc.Addresses) == 0 {
				v.addf("%s: interface %s: the %s needs a static address", p, ifc.Name, role)
			}
		}
	}
}

// haGateway checks the management gateway: an address on the interface.
func (v *validator) haGateway(p string, ifc Interface) {
	gw, err := netip.ParseAddr(ifc.HAGateway)
	if err != nil {
		v.addf("%s: interface %s: the management interface needs a gateway", p, ifc.Name)
		return
	}
	for _, a := range ifc.Addresses {
		if q, err := ParseInterfaceAddress(a); err == nil && q.Contains(gw) && q.Addr() != gw {
			return
		}
	}
	v.addf("%s: interface %s: the gateway %s is not on the interface", p, ifc.Name, ifc.HAGateway)
}

// ConntrackSyncPort is conntrackd's UDP port between the hosts of a pair.
const ConntrackSyncPort = 3780

// ConntrackSync runs conntrackd in the instance on an HA pair: each host
// sends its connections to the other over Interface, from This to Peer
// (IPv6 link-local addresses on it, HALinkAddress), and the other puts them in its kernel's table at
// once, so they live on after a failover.
type ConntrackSync struct {
	Interface string `json:"interface"`
	This      string `json:"this"`
	Peer      string `json:"peer"`
}

func (v *validator) conntrackSync(p string, in *Instance) {
	c := in.ConntrackSync
	if c == nil {
		return
	}
	if !ValidIfname(c.Interface) {
		v.addf("%s: conntrack sync: invalid interface %q", p, c.Interface)
	}
	for _, a := range []string{c.This, c.Peer} {
		if ip, err := netip.ParseAddr(a); err != nil || !ip.Is6() || !ip.IsLinkLocalUnicast() || ip.Zone() != "" {
			v.addf("%s: conntrack sync: %q is not an IPv6 link-local address", p, a)
		}
	}
	if c.This == c.Peer {
		v.addf("%s: conntrack sync: this host and its peer have the same address", p)
	}
}
