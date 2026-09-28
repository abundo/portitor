// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

// ICMPType is an ICMP or ICMPv6 message type by its nftables name.
type ICMPType struct {
	Name        string `json:"name"`
	Type        int    `json:"type"`
	Description string `json:"description"`
}

// ICMPTypes are the ICMP types nftables names (nft describe icmp type),
// ordered by type.
var ICMPTypes = []ICMPType{
	{"echo-reply", 0, "Ping reply"},
	{"destination-unreachable", 3, "Destination unreachable"},
	{"source-quench", 4, "Source quench (deprecated)"},
	{"redirect", 5, "Redirect"},
	{"echo-request", 8, "Ping request"},
	{"router-advertisement", 9, "Router advertisement"},
	{"router-solicitation", 10, "Router solicitation"},
	{"time-exceeded", 11, "Time exceeded (traceroute)"},
	{"parameter-problem", 12, "Parameter problem"},
	{"timestamp-request", 13, "Timestamp request"},
	{"timestamp-reply", 14, "Timestamp reply"},
	{"info-request", 15, "Information request (obsolete)"},
	{"info-reply", 16, "Information reply (obsolete)"},
	{"address-mask-request", 17, "Address mask request"},
	{"address-mask-reply", 18, "Address mask reply"},
}

// ICMPv6Types are the ICMPv6 types nftables names (nft describe icmpv6
// type), ordered by type.
var ICMPv6Types = []ICMPType{
	{"destination-unreachable", 1, "Destination unreachable"},
	{"packet-too-big", 2, "Packet too big (path MTU discovery)"},
	{"time-exceeded", 3, "Time exceeded (traceroute)"},
	{"parameter-problem", 4, "Parameter problem"},
	{"echo-request", 128, "Ping request"},
	{"echo-reply", 129, "Ping reply"},
	{"mld-listener-query", 130, "Multicast listener query"},
	{"mld-listener-report", 131, "Multicast listener report"},
	{"mld-listener-done", 132, "Multicast listener done"},
	{"nd-router-solicit", 133, "Router solicitation"},
	{"nd-router-advert", 134, "Router advertisement"},
	{"nd-neighbor-solicit", 135, "Neighbor solicitation"},
	{"nd-neighbor-advert", 136, "Neighbor advertisement"},
	{"nd-redirect", 137, "Redirect"},
	{"router-renumbering", 138, "Router renumbering"},
	{"ind-neighbor-solicit", 141, "Inverse neighbor discovery solicitation"},
	{"ind-neighbor-advert", 142, "Inverse neighbor discovery advertisement"},
	{"mld2-listener-report", 143, "Multicast listener report (MLDv2)"},
}

// ValidICMPType reports whether name is an ICMP type of protocol proto
// (icmp or icmpv6).
func ValidICMPType(proto, name string) bool {
	list := ICMPTypes
	if proto == "icmpv6" {
		list = ICMPv6Types
	} else if proto != "icmp" {
		return false
	}
	for _, t := range list {
		if t.Name == name {
			return true
		}
	}
	return false
}
