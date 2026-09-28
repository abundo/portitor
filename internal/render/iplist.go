// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"fmt"
	"net/netip"
	"strings"
)

// ipListChunk is how many elements go on one "add element" line.
const ipListChunk = 1000

// IPListElements renders the contents of an IP list's elements file
// (Paths.IPListFile): nft commands adding its addresses to its two sets in
// the firewall table. prefixes must not overlap (iplist.Normalize), since
// nft before 1.0.7 refuses overlapping elements even with auto-merge.
// An empty list renders only a comment, which nft accepts as an include.
func IPListElements(name string, prefixes []netip.Prefix) string {
	var v4, v6 []string
	for _, p := range prefixes {
		s := p.String()
		if p.IsSingleIP() {
			s = p.Addr().String()
		}
		if p.Addr().Is4() {
			v4 = append(v4, s)
		} else {
			v6 = append(v6, s)
		}
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "# ip list %s: %d IPv4 and %d IPv6 entries. Written by portitor-agent.\n", name, len(v4), len(v6))
	for _, part := range []struct {
		family string
		list   []string
	}{{"ipv4", v4}, {"ipv6", v6}} {
		for i := 0; i < len(part.list); i += ipListChunk {
			chunk := part.list[i:min(i+ipListChunk, len(part.list))]
			fmt.Fprintf(b, "add element inet %s %s { %s }\n", TableName, SetName(name, part.family), strings.Join(chunk, ", "))
		}
	}
	return b.String()
}

// IPListReload renders an nft transaction that replaces the elements of
// an IP list's sets with the contents of its elements file.
func IPListReload(name string, paths Paths) string {
	return fmt.Sprintf("flush set inet %s %s\nflush set inet %s %s\ninclude %q\n",
		TableName, SetName(name, "ipv4"), TableName, SetName(name, "ipv6"), paths.IPListFile(name))
}
