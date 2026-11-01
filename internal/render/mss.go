// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"fmt"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
)

// MSSChain clamps the MSS of the forwarded TCP SYNs (fwconfig.Interface.MSSClamp),
// at priority mangle: before the forward chain, so whatever the rules
// decide, and before its established accept would skip a SYN-ACK.
const MSSChain = "forward_mss"

// synOrSynAck matches the SYNs and SYN-ACKs, which carry the MSS.
const synOrSynAck = "tcp flags & (syn | rst) == syn"

// writeMSSClamp renders MSSChain. What leaves by an interface gets the
// route's MTU less the headers (rt mtu), or the interface's fixed MSS;
// what comes in on it the MSS its own MTU leaves (MSSClampIn), when known.
// An interface's VRRP and OpenVPN TCP devices are its; one in a VRF comes
// in with the VRF device, matched by sdifname. The kernel never raises an
// MSS with rt mtu; a fixed one is set only where it lowers the SYN's.
func writeMSSClamp(b *strings.Builder, in *fwconfig.Instance) {
	var lines []string
	for _, ifc := range in.Interfaces {
		if !ifc.MSSClamp || !ifc.Enabled {
			continue
		}
		ifs := in.AddOpenVPNDevices(in.AddVRRPDevices([]string{ifc.Name}))
		c := comment("mss clamp", ifc.Name)
		oif := "oifname " + quotedSet(ifs)
		if ifc.MSSClampValue == 0 {
			lines = append(lines, fmt.Sprintf("%s %s tcp option maxseg size set rt mtu %s", oif, synOrSynAck, c))
		} else {
			lines = append(lines, mssLines(oif, ifc.MSSClampValue, c)...)
		}
		if mss := ifc.MSSClampIn(); mss != 0 {
			for _, iif := range iifMatches(in, ifs, true) {
				lines = append(lines, mssLines(iif, mss, c)...)
			}
		}
	}
	if len(lines) == 0 {
		return
	}
	fmt.Fprintf(b, "\tchain %s {\n", MSSChain)
	b.WriteString("\t\ttype filter hook forward priority mangle; policy accept;\n")
	for _, l := range lines {
		b.WriteString("\t\t" + l + "\n")
	}
	b.WriteString("\t}\n\n")
}

// mssLines lowers the SYNs' MSS that match to mss, IPv4's (IPv6 takes 20
// bytes off, fwconfig.MSSFamily).
func mssLines(match string, mss int, c string) []string {
	var out []string
	for _, fam := range []struct {
		proto  string
		family int
	}{{"ipv4", 4}, {"ipv6", 6}} {
		m := fwconfig.MSSFamily(mss, fam.family)
		out = append(out, fmt.Sprintf("%s meta nfproto %s %s tcp option maxseg size > %d tcp option maxseg size set %d %s", match, fam.proto, synOrSynAck, m, m, c))
	}
	return out
}
