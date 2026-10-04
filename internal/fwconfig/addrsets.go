// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
	"strings"
)

// AddressSet is an address list (the GUI's "address list") that the
// instance's filter rules use: its addresses and prefixes, names already
// expanded. It renders as one nftables set per IP version, which the rules
// refer to as "$name" in their source and destination addresses.
type AddressSet struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

// AddressSetRef is the prefix of an address set reference in a rule's
// addresses.
const AddressSetRef = "$"

// AddressSetName returns the set an address entry refers to, if it is a
// reference.
func AddressSetName(entry string) (string, bool) {
	return strings.CutPrefix(entry, AddressSetRef)
}

// AddressSet returns the named address set, or nil.
func (in *Instance) AddressSet(name string) *AddressSet {
	for i := range in.AddressSets {
		if in.AddressSets[i].Name == name {
			return &in.AddressSets[i]
		}
	}
	return nil
}

// Families returns the addresses of one IP version ("ipv4", "ipv6").
func (s *AddressSet) Families(fam string) []string {
	return filterFamily(s.Addresses, fam)
}

func (v *validator) addressSets(p string, in *Instance) {
	v.sets = map[string]bool{}
	for _, s := range in.AddressSets {
		sp := fmt.Sprintf("%s: address list %q", p, s.Name)
		if !ValidName(s.Name) {
			v.addf("%s: invalid name", sp)
		}
		if v.sets[s.Name] {
			v.addf("%s: duplicate", sp)
		}
		v.sets[s.Name] = true
		for _, a := range s.Addresses {
			if _, err := ParseAddrOrPrefix(a); err != nil {
				v.addf("%s: invalid address %q", sp, a)
			}
		}
	}
}
