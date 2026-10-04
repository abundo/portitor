// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netobj resolves named hosts and prefixes (models.AddressObject)
// and address lists (models.AddressList), which share one set of names.
// Wherever the GUI takes addresses, an entry may be a name instead;
// portitor-web expands names when it builds the document, so the agent
// only ever sees addresses (a filter rule's address lists reach it as
// fwconfig.AddressSets, expanded too).
package netobj

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// addrLike is what an address or prefix is written with, a mistyped one
// included: hex digits, ".", ":" and "/", with a digit and one of the
// separators. Such text is never a name, so a typo is reported as a bad
// address rather than an unknown name.
var addrLike = regexp.MustCompile(`^[0-9a-fA-F.:/]*[0-9][0-9a-fA-F.:/]*$`)

// ValidName reports whether s can name a host/prefix: any name
// (fwconfig.ValidName) that can't be read as an address or prefix, nor
// as an IP list ("@"). "default" and "any" are taken by routes and the
// GUI.
func ValidName(s string) bool {
	return IsName(s) && s != "default" && s != "any"
}

// IsName reports whether an entry refers to an object rather than being a
// literal address or prefix, or an IP list.
func IsName(s string) bool {
	return fwconfig.ValidName(s) && !strings.HasPrefix(s, "@") &&
		!(addrLike.MatchString(s) && strings.ContainsAny(s, ".:/"))
}

// Set maps the names of hosts and address lists to their addresses.
type Set struct {
	entries map[string][]netip.Prefix
	lists   map[string]bool
	// bad holds why an address list can't be resolved (a cycle, an
	// unknown name), reported when it is used.
	bad map[string]error
}

// New resolves hosts and address lists. A list's entries are addresses,
// prefixes, and names of hosts and other lists, resolved recursively.
func New(objs []models.AddressObject, lists ...models.AddressList) Set {
	s := Set{entries: map[string][]netip.Prefix{}, lists: map[string]bool{}, bad: map[string]error{}}
	for _, o := range objs {
		var entries []netip.Prefix
		for _, a := range o.Addresses {
			if p, err := fwconfig.ParseAddrOrPrefix(a); err == nil {
				entries = append(entries, p)
			}
		}
		s.entries[o.Name] = entries
	}
	byName := map[string]models.AddressList{}
	for _, l := range lists {
		byName[l.Name] = l
		s.lists[l.Name] = true
	}
	var resolve func(name string, path []string) ([]netip.Prefix, error)
	resolve = func(name string, path []string) ([]netip.Prefix, error) {
		if err := s.bad[name]; err != nil {
			return nil, err
		}
		if out, ok := s.entries[name]; ok {
			return out, nil
		}
		l, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("unknown host/prefix name %q", name)
		}
		if slices.Contains(path, name) {
			return nil, fmt.Errorf("address list %s contains itself (%s)", name, strings.Join(append(path, name), " → "))
		}
		var out []netip.Prefix
		for _, e := range l.Entries {
			if !IsName(e) {
				if p, err := fwconfig.ParseAddrOrPrefix(e); err == nil && !slices.Contains(out, p) {
					out = append(out, p)
				}
				continue
			}
			sub, err := resolve(e, append(path, name))
			if err != nil {
				return nil, err
			}
			for _, p := range sub {
				if !slices.Contains(out, p) {
					out = append(out, p)
				}
			}
		}
		s.entries[name] = out
		return out, nil
	}
	for _, l := range lists {
		if _, err := resolve(l.Name, nil); err != nil {
			s.bad[l.Name] = err
		}
	}
	return s
}

// IsList reports whether name is an address list.
func (s Set) IsList(name string) bool {
	return s.lists[name]
}

// Has reports whether name is a host or an address list.
func (s Set) Has(name string) bool {
	_, ok := s.entries[name]
	return ok || s.lists[name]
}

// Expand replaces object names in list by their entries, written as
// addresses (hosts) or CIDRs. Literals are kept as they are; validation
// deals with them.
func (s Set) Expand(list []string) ([]string, error) {
	return s.expand(list, func(name string, p netip.Prefix) (string, error) {
		if p.IsSingleIP() {
			return p.Addr().String(), nil
		}
		return p.String(), nil
	})
}

// Prefixes is Expand, with hosts written as /32 or /128.
func (s Set) Prefixes(list []string) ([]string, error) {
	return s.expand(list, func(name string, p netip.Prefix) (string, error) {
		return p.String(), nil
	})
}

// Hosts is Expand for places that take plain addresses: every entry of a
// named object must be a single address.
func (s Set) Hosts(list []string) ([]string, error) {
	return s.expand(list, func(name string, p netip.Prefix) (string, error) {
		if !p.IsSingleIP() {
			return "", fmt.Errorf("%s is not a host: it contains the prefix %s", name, p)
		}
		return p.Addr().String(), nil
	})
}

// Host resolves one entry that must be a single address per IP version:
// a literal is returned as-is, a name as its IPv4 and/or IPv6 address.
func (s Set) Host(entry string) ([]string, error) {
	if !IsName(entry) {
		return []string{entry}, nil
	}
	out, err := s.Hosts([]string{entry})
	if err != nil {
		return nil, err
	}
	v4, v6 := 0, 0
	for _, a := range out {
		if fwconfig.AddrFamily(a) == "ipv4" {
			v4++
		} else {
			v6++
		}
	}
	if v4 > 1 || v6 > 1 {
		return nil, fmt.Errorf("%s has more than one address of an IP version; one is needed here", entry)
	}
	return out, nil
}

func (s Set) expand(list []string, conv func(name string, p netip.Prefix) (string, error)) ([]string, error) {
	var out []string
	for _, e := range list {
		if !IsName(e) {
			out = append(out, e)
			continue
		}
		if err := s.bad[e]; err != nil {
			return nil, err
		}
		entries, ok := s.entries[e]
		if !ok {
			return nil, fmt.Errorf("unknown host/prefix name %q", e)
		}
		if len(entries) == 0 {
			// Expanding to nothing would turn a match into "any".
			return nil, fmt.Errorf("%s has no addresses", e)
		}
		for _, p := range entries {
			a, err := conv(e, p)
			if err != nil {
				return nil, err
			}
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	return out, nil
}
