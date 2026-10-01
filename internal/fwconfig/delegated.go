// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Delegated is an IPv6 address or prefix relative to the prefix that
// Interface's DHCPv6 client got delegated (IA_PD), so a new prefix from
// the ISP renumbers it. Its text form is "<wan0>:SUBNET::HOST/BITS":
// SUBNET (hex, at most 4 digits) goes in the bits between the delegated
// prefix and /64, HOST is the low 64 bits. With 2001:db8:1000::/48
// delegated on wan0, "<wan0>:2000::1/64" is 2001:db8:1000:2000::1/64 and
// "<wan0>:2000::/64" the prefix 2001:db8:1000:2000::/64. "<wan0>::1/64"
// is subnet 0.
type Delegated struct {
	Interface string
	Subnet    uint16
	Host      uint64
	Bits      int
}

// IsDelegated reports whether s is in the delegated form (it may still
// be invalid).
func IsDelegated(s string) bool { return strings.HasPrefix(s, "<") }

// ParseDelegated parses "<iface>:SUBNET::HOST/BITS"; BITS is 64 to 128.
func ParseDelegated(s string) (Delegated, error) {
	var d Delegated
	name, rest, ok := strings.Cut(strings.TrimPrefix(s, "<"), ">")
	if !IsDelegated(s) || !ok {
		return d, fmt.Errorf("expected <interface>:subnet::host/length")
	}
	if !ifnameRe.MatchString(name) {
		return d, fmt.Errorf("invalid interface name %q", name)
	}
	d.Interface = name
	addr, bits, ok := strings.Cut(rest, "/")
	if !ok {
		return d, fmt.Errorf("missing /length")
	}
	n, err := strconv.Atoi(bits)
	if err != nil || n < 64 || n > 128 {
		return d, fmt.Errorf("length must be 64 to 128")
	}
	d.Bits = n
	body, ok := strings.CutPrefix(addr, ":")
	subnet, host := "", ""
	if after, zero := strings.CutPrefix(body, ":"); zero {
		host = after // "::HOST": subnet 0
	} else if ok {
		subnet, host, ok = strings.Cut(body, "::")
	}
	if !ok {
		return d, fmt.Errorf("expected <interface>:subnet::host/length")
	}
	if subnet != "" {
		v, err := strconv.ParseUint(subnet, 16, 16)
		if err != nil || len(subnet) > 4 {
			return d, fmt.Errorf("subnet %q is not 1 to 4 hex digits", subnet)
		}
		d.Subnet = uint16(v)
	}
	h, err := netip.ParseAddr("::" + host)
	if err != nil || !h.Is6() || h.Zone() != "" {
		return d, fmt.Errorf("invalid host part %q", host)
	}
	b := h.As16()
	if binary.BigEndian.Uint64(b[:8]) != 0 {
		return d, fmt.Errorf("host part %q is longer than 64 bits", host)
	}
	d.Host = binary.BigEndian.Uint64(b[8:])
	return d, nil
}

// String is the canonical text form.
func (d Delegated) String() string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[8:], d.Host)
	host := strings.TrimPrefix(netip.AddrFrom16(b).String(), "::")
	if d.Subnet == 0 {
		return fmt.Sprintf("<%s>::%s/%d", d.Interface, host, d.Bits)
	}
	return fmt.Sprintf("<%s>:%x::%s/%d", d.Interface, d.Subnet, host, d.Bits)
}

// IsPrefix reports whether d has no host bits: a prefix, not an address.
func (d Delegated) IsPrefix() bool {
	return d.Bits < 128 && d.Host&(uint64(1)<<(128-d.Bits)-1) == 0
}

// Resolve places d in the delegated prefix pd. It fails when the subnet
// does not fit in the bits pd leaves before /64.
func (d Delegated) Resolve(pd netip.Prefix) (netip.Prefix, error) {
	if !pd.IsValid() || !pd.Addr().Is6() || pd.Bits() > 64 {
		return netip.Prefix{}, fmt.Errorf("delegated prefix %s is not an IPv6 prefix of /64 or shorter", pd)
	}
	free := 64 - pd.Bits()
	if free < 16 && uint64(d.Subnet) >= 1<<free {
		return netip.Prefix{}, fmt.Errorf("subnet %x does not fit in delegated prefix %s", d.Subnet, pd)
	}
	b := pd.Masked().Addr().As16()
	upper := binary.BigEndian.Uint64(b[:8]) | uint64(d.Subnet)
	binary.BigEndian.PutUint64(b[:8], upper)
	binary.BigEndian.PutUint64(b[8:], d.Host)
	return netip.PrefixFrom(netip.AddrFrom16(b), d.Bits), nil
}

// DelegatedPrefixes are the prefixes the DHCPv6 clients got delegated,
// per instance and interface.
type DelegatedPrefixes map[string]map[string]netip.Prefix

// resolve returns s resolved, s itself when it is not delegated, or
// false when its prefix is not (yet) delegated or it does not fit.
func (pds DelegatedPrefixes) resolve(instance, s string, prefix bool) (string, bool) {
	if !IsDelegated(s) {
		return s, true
	}
	d, err := ParseDelegated(s)
	if err != nil {
		return "", false
	}
	pd, ok := pds[instance][d.Interface]
	if !ok {
		return "", false
	}
	p, err := d.Resolve(pd)
	if err != nil {
		return "", false
	}
	if prefix {
		return p.Masked().String(), true
	}
	return p.String(), true
}

// ResolveDelegated returns d with the delegated addresses (interface
// addresses, router advertisement prefixes and DNS servers) resolved
// from pds. One whose prefix is not delegated, or does not fit in it,
// is left out; router advertisements left without prefixes are dropped.
// d itself is not changed.
func (d Document) ResolveDelegated(pds DelegatedPrefixes) Document {
	out := d
	out.Instances = slices.Clone(d.Instances)
	for i := range out.Instances {
		in := &out.Instances[i]
		in.Interfaces = slices.Clone(in.Interfaces)
		for j := range in.Interfaces {
			ifc := &in.Interfaces[j]
			var addrs []string
			for _, a := range ifc.Addresses {
				if r, ok := pds.resolve(in.Name, a, false); ok {
					addrs = append(addrs, r)
				}
			}
			ifc.Addresses = addrs
		}
		var ras []RAInterface
		for _, ra := range in.RA {
			delegated := false
			var pfxs []RAPrefix
			for _, p := range ra.Prefixes {
				delegated = delegated || IsDelegated(p.Prefix)
				if r, ok := pds.resolve(in.Name, p.Prefix, true); ok {
					pfxs = append(pfxs, RAPrefix{Prefix: r, Autonomous: p.Autonomous})
				}
			}
			if delegated && len(pfxs) == 0 {
				continue
			}
			var rdnss []string
			for _, a := range ra.RDNSS {
				if IsDelegated(a) {
					if r, ok := pds.resolve(in.Name, a, false); ok {
						rdnss = append(rdnss, netip.MustParsePrefix(r).Addr().String())
					}
					continue
				}
				rdnss = append(rdnss, a)
			}
			ra.Prefixes, ra.RDNSS = pfxs, rdnss
			ras = append(ras, ra)
		}
		in.RA = ras
	}
	return out
}

// UsesDelegated reports whether the instance has delegated addresses or
// router advertisement prefixes.
func (in *Instance) UsesDelegated() bool {
	for _, ifc := range in.Interfaces {
		if slices.ContainsFunc(ifc.Addresses, IsDelegated) {
			return true
		}
	}
	for _, ra := range in.RA {
		for _, p := range ra.Prefixes {
			if IsDelegated(p.Prefix) {
				return true
			}
		}
	}
	return false
}
