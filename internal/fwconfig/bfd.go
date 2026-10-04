// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
	"net/netip"
)

// BFDInterface turns BFD (RFC 5880, single hop, FRR's bfdd) on for an
// interface of the instance, with its timers. Static routes (Route.BFD),
// OSPF interfaces (OSPFInterface.BFD) and BGP neighbours (BGPPeer.BFD)
// that ask for BFD use it on the interfaces that have it, and only there:
// on any other interface they run without, so this list is the switch.
// Each renders as a bfdd profile (BFDProfile) the users name.
type BFDInterface struct {
	Name string `json:"name"`
	// DetectMultiplier is how many packets may be missed before the peer
	// is down (2-255; 0: FRR's, 3).
	DetectMultiplier int `json:"detect_multiplier,omitempty"`
	// ReceiveInterval and TransmitInterval in milliseconds (10-60000; 0:
	// FRR's, 300).
	ReceiveInterval  int `json:"receive_interval,omitempty"`
	TransmitInterval int `json:"transmit_interval,omitempty"`
	// Passive waits for the peer to start the session.
	Passive bool `json:"passive,omitempty"`
}

// BFDPort is the UDP port of single-hop BFD control packets (RFC 5881).
const BFDPort = 3784

// BFDProfile is the bfdd profile of an interface's BFD settings.
func BFDProfile(iface string) string { return "if-" + iface }

// BFDRunning reports whether the instance runs bfdd: an interface has BFD.
func (in *Instance) BFDRunning() bool { return len(in.BFD) > 0 }

// BFDOn returns the BFD settings of an interface, nil when it has none.
func (in *Instance) BFDOn(iface string) *BFDInterface {
	for i := range in.BFD {
		if in.BFD[i].Name == iface {
			return &in.BFD[i]
		}
	}
	return nil
}

// BFDInterfaceFor is the interface a BFD session to a directly connected
// address runs on: iface when set, else the one with a network that holds
// the address. "" when there is none or it has no BFD. Call it on an
// expanded document so link ends are included.
func (in *Instance) BFDInterfaceFor(addr, iface string) string {
	if iface == "" {
		a, err := ParseAddr(addr)
		if err != nil {
			return ""
		}
	find:
		for _, ifc := range in.Interfaces {
			if !ifc.Enabled {
				continue
			}
			for _, s := range ifc.Addresses {
				if p, err := ParseInterfaceAddress(s); err == nil && p.Masked().Contains(a) && p.Addr() != a {
					iface = ifc.Name
					break find
				}
			}
		}
	}
	if iface == "" || in.BFDOn(iface) == nil {
		return ""
	}
	return iface
}

// RouteBFD is the interface whose BFD session watches a static route's
// gateway, "" when the route has no BFD (or its interface none). Such a
// route is FRR's (staticd), not the agent's kernel route: it is gone while
// the gateway's session is down.
func (in *Instance) RouteBFD(r Route) string {
	if !r.BFD || r.Gateway == "" {
		return ""
	}
	return in.BFDInterfaceFor(r.Gateway, r.Interface)
}

// KernelRoutes are the static routes the agent installs: those without a
// BFD session.
func (in *Instance) KernelRoutes() []Route {
	var out []Route
	for _, r := range in.Routes {
		if in.RouteBFD(r) == "" {
			out = append(out, r)
		}
	}
	return out
}

// HasBFDRoutes reports whether FRR's staticd has routes of the instance.
func (in *Instance) HasBFDRoutes() bool {
	for _, r := range in.Routes {
		if in.RouteBFD(r) != "" {
			return true
		}
	}
	return false
}

// NeighborBFD is the interface of a BGP neighbour's BFD session, "" when
// neither it nor its peer group asks for BFD or it is not on an interface
// with BFD.
func (in *Instance) NeighborBFD(n BGPPeer) string {
	on := n.BFD
	if !on && n.PeerGroup != "" && in.BGP != nil {
		for _, g := range in.BGP.PeerGroups {
			if g.Name == n.PeerGroup {
				on = g.BFD
			}
		}
	}
	if !on {
		return ""
	}
	return in.BFDInterfaceFor(n.Address, n.Interface)
}

// CheckBFDInterface checks an interface's BFD settings.
func CheckBFDInterface(b BFDInterface) []string {
	v := &validator{}
	v.bfdInterface("bfd", b)
	return v.problems
}

func (v *validator) bfdInterface(p string, b BFDInterface) {
	p = fmt.Sprintf("%s: BFD on %s", p, b.Name)
	if !ifnameRe.MatchString(b.Name) {
		v.addf("%s: invalid interface name", p)
	}
	if b.DetectMultiplier != 0 && (b.DetectMultiplier < 2 || b.DetectMultiplier > 255) {
		v.addf("%s: detect multiplier out of range (2-255)", p)
	}
	for _, t := range []struct {
		name string
		ms   int
	}{{"receive", b.ReceiveInterval}, {"transmit", b.TransmitInterval}} {
		if t.ms != 0 && (t.ms < 10 || t.ms > 60000) {
			v.addf("%s: %s interval out of range (10-60000 ms)", p, t.name)
		}
	}
}

// bfd checks the instance's BFD interfaces, and that a static route with
// BFD can be FRR's.
func (v *validator) bfd(p string, in *Instance, ifaces map[string]*Interface) {
	seen := map[string]bool{}
	for _, b := range in.BFD {
		if ifaces[b.Name] == nil {
			v.addf("%s: BFD: unknown interface %q", p, b.Name)
		} else if ifaces[b.Name].Kind == KindLoopback {
			v.addf("%s: BFD on %s: not on a loopback interface", p, b.Name)
		}
		if seen[b.Name] {
			v.addf("%s: BFD on %s: duplicate", p, b.Name)
		}
		seen[b.Name] = true
		v.bfdInterface(p, b)
	}
	for i, r := range in.Routes {
		if !r.BFD {
			continue
		}
		rp := fmt.Sprintf("%s: route %d", p, i+1)
		if r.Gateway == "" {
			v.addf("%s: BFD needs a gateway", rp)
		}
		// FRR takes the metric as the administrative distance.
		if r.Metric > 255 {
			v.addf("%s: with BFD, the metric is FRR's distance (0-255)", rp)
		}
		if a, err := ParseAddr(r.Gateway); err == nil && a.Is6() && a.IsLinkLocalUnicast() && r.Interface == "" {
			v.addf("%s: BFD to a link-local gateway needs the interface", rp)
		}
	}
}

// BFDRouteDest is FRR's destination of a static route: default as the
// gateway's family's.
func BFDRouteDest(r Route) string {
	if r.Destination != "default" {
		if p, err := netip.ParsePrefix(r.Destination); err == nil {
			return p.Masked().String()
		}
		return r.Destination
	}
	if a, err := ParseAddr(r.Gateway); err == nil && a.Is6() {
		return "::/0"
	}
	return "0.0.0.0/0"
}
