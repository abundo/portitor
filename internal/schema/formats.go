// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package schema

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"unicode"

	"github.com/abundo/portitor/internal/fwconfig"
)

// A format is a typedef of portitor-types.yang: Go checks a value and
// writes it in its canonical form. Surrounding spaces are taken off first.
type format func(v string) (string, error)

var formats = map[string]format{
	"text": func(v string) (string, error) {
		if strings.ContainsFunc(v, unicode.IsControl) {
			return "", errors.New("control characters are not allowed")
		}
		return v, nil
	},
	"name": func(v string) (string, error) {
		if !fwconfig.ValidName(v) {
			return "", errors.New("not empty, no control characters")
		}
		return v, nil
	},
	"word": func(v string) (string, error) {
		if !fwconfig.ValidWord(v) {
			return "", fmt.Errorf("%q is not one word (no spaces, not starting with ! or #)", v)
		}
		return v, nil
	},
	"ifname": func(v string) (string, error) {
		if !fwconfig.ValidIfname(v) {
			return "", fmt.Errorf("%q is not an interface name: 1-15 characters, no '/', ':' or spaces", v)
		}
		return v, nil
	},
	"ip-address": func(v string) (string, error) {
		a, err := netip.ParseAddr(v)
		if err != nil || a.Zone() != "" {
			return "", fmt.Errorf("%q is not an IP address", v)
		}
		return a.Unmap().String(), nil
	},
	"ipv4-address": func(v string) (string, error) {
		a, err := netip.ParseAddr(v)
		if err != nil || !a.Unmap().Is4() {
			return "", fmt.Errorf("%q is not an IPv4 address", v)
		}
		return a.Unmap().String(), nil
	},
	"ipv6-address": func(v string) (string, error) {
		a, err := netip.ParseAddr(v)
		if err != nil || !a.Is6() || a.Is4In6() || a.Zone() != "" {
			return "", fmt.Errorf("%q is not an IPv6 address", v)
		}
		return a.String(), nil
	},
	"ip-prefix": func(v string) (string, error) {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return "", fmt.Errorf("%q is not a prefix (CIDR)", v)
		}
		return p.Masked().String(), nil
	},
	"interface-address": func(v string) (string, error) {
		p, err := fwconfig.ParseInterfaceAddress(v)
		if err != nil {
			return "", fmt.Errorf("%q: %v", v, err)
		}
		return p.String(), nil
	},
	"mac-address": func(v string) (string, error) {
		m, err := net.ParseMAC(v)
		if err != nil || len(m) != 6 {
			return "", fmt.Errorf("%q is not a MAC address of 6 bytes, like 02:00:5e:00:01:01", v)
		}
		return m.String(), nil
	},
	"domain-name": func(v string) (string, error) {
		v = strings.ToLower(strings.TrimSuffix(v, "."))
		if !fwconfig.ValidDomain(v) {
			return "", fmt.Errorf("%q is not a domain name", v)
		}
		return v, nil
	},
	"email": func(v string) (string, error) {
		if !fwconfig.ValidEmail(v) {
			return "", fmt.Errorf("%q is not an email address", v)
		}
		return v, nil
	},
	"url": func(v string) (string, error) {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return "", fmt.Errorf("%q is not an http or https URL", v)
		}
		return v, nil
	},
	"wg-key": func(v string) (string, error) {
		if !fwconfig.ValidWGKey(v) {
			return "", errors.New("not a WireGuard key (32 bytes in base64)")
		}
		return v, nil
	},
	"address-or-prefix": func(v string) (string, error) {
		if strings.Contains(v, "/") {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				return "", fmt.Errorf("%q is not an address or prefix", v)
			}
			if p.IsSingleIP() {
				return p.Addr().String(), nil // a host's address
			}
			return p.Masked().String(), nil
		}
		a, err := fwconfig.ParseAddr(v)
		if err != nil {
			return "", fmt.Errorf("%q is not an address or prefix", v)
		}
		return a.Unmap().String(), nil
	},
	"cidr": func(v string) (string, error) {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return "", fmt.Errorf("%q is not a CIDR (e.g. 192.168.1.0/24)", v)
		}
		return p.Masked().String(), nil
	},
	"ip-list-ref": func(v string) (string, error) {
		name, ok := fwconfig.IPListName(v)
		if !ok || !fwconfig.ValidName(name) {
			return "", fmt.Errorf("%q is not an IP list (@name)", v)
		}
		return v, nil
	},
	"delegated-address": func(v string) (string, error) {
		d, err := fwconfig.ParseDelegated(v)
		if err != nil {
			return "", fmt.Errorf("%q: %v (e.g. <wan0>:2000::1/64)", v, err)
		}
		return d.String(), nil
	},
	"delegated-interface-address": func(v string) (string, error) {
		d, err := fwconfig.ParseDelegated(v)
		if err != nil {
			return "", fmt.Errorf("%q: %v (e.g. <wan0>:2000::1/64)", v, err)
		}
		if d.IsPrefix() && d.Bits < 127 {
			return "", fmt.Errorf("%s is the network address of the prefix; give the interface's own address, e.g. <%s>:%x::1/%d", v, d.Interface, d.Subnet, d.Bits)
		}
		return d.String(), nil
	},
	"endpoint": func(v string) (string, error) {
		if !fwconfig.ValidEndpoint(v) {
			return "", fmt.Errorf("%q is not host:port", v)
		}
		return v, nil
	},
	"host-or-address": func(v string) (string, error) {
		if a, err := fwconfig.ParseAddr(v); err == nil {
			return a.Unmap().String(), nil
		}
		if !fwconfig.ValidNTPServer(v) {
			return "", fmt.Errorf("%q is not an address or host name", v)
		}
		return strings.ToLower(v), nil
	},
	"default-route": func(v string) (string, error) {
		if v != "default" {
			return "", fmt.Errorf("%q is not \"default\"", v)
		}
		return v, nil
	},
	"ospf-area": func(v string) (string, error) {
		a, ok := fwconfig.ParseOSPFArea(v)
		if !ok {
			return "", fmt.Errorf("%q is not an area id (0.0.0.1 or 1)", v)
		}
		return a, nil
	},
}

// Formats of one of two others: goyang keeps one string member of a
// union, so a union of two string typedefs is a typedef of its own.
func init() {
	either := func(a, b string) format {
		return func(v string) (string, error) {
			if c, err := formats[a](v); err == nil {
				return c, nil
			}
			return formats[b](v)
		}
	}
	formats["route-destination"] = either("default-route", "ip-prefix")
	formats["lowercase-name"] = func(v string) (string, error) {
		return strings.ToLower(v), nil
	}
	formats["prefix-or-any"] = func(v string) (string, error) {
		if v == "any" {
			return v, nil
		}
		return formats["cidr"](v)
	}
	formats["rule-address"] = either("ip-list-ref", "address-or-prefix")
	formats["any-interface-address"] = either("delegated-interface-address", "interface-address")
}
