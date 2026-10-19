// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// ACMEProxy is an ACME server (RFC 8555) for the hosts behind the
// firewall: certbot, Caddy, Traefik and the like point their ACME
// directory at it, prove control of a name by HTTP-01 over the internal
// network, and get a certificate the agent orders from the upstream CA
// (Let's Encrypt) as the policy that allows the name says: with DNS-01,
// through its DNS update client, so only the firewall holds the DNS
// credentials and the hosts need not be reachable from the internet; or
// with HTTP-01, answered by the agent on port 80 of the policy's
// interface, where the name must resolve to the firewall from the
// internet (opened as a certificate's HTTP-01, render.ACMEHTTPSet).
//
// The server listens with HTTPS on Port of the instance's addresses,
// opened on Interfaces by the auto input rule "acme proxy" (from the
// policies' sources when every policy lists some). A client may order
// names that a policy allows from its address; for each, the agent
// fetches the HTTP-01 token from the name, resolved in the instance, and
// every address the name resolves to must be in that policy's sources
// too. Wildcards can't be validated by HTTP-01 and are refused.
type ACMEProxy struct {
	Port       int      `json:"port"`
	Interfaces []string `json:"interfaces"`
	// Certificate names one of the instance's certificates the server
	// presents; empty: a self-signed one the agent makes, which clients
	// must be told to trust.
	Certificate string `json:"certificate,omitempty"`
	// CA and Email are the upstream ACME account's, as a Certificate's.
	CA       string            `json:"ca"`
	Email    string            `json:"email,omitempty"`
	Policies []ACMEProxyPolicy `json:"policies"`
}

// ACMEProxyPolicy allows names to the clients in Sources.
type ACMEProxyPolicy struct {
	Name string `json:"name"`
	// Domains are DNS names: "host.example.com" allows that name,
	// "*.example.com" any name below example.com (not example.com).
	Domains []string `json:"domains"`
	// Sources are the prefixes the clients, and the addresses the names
	// resolve to, must be in; empty: any.
	Sources []string `json:"sources,omitempty"`
	// Challenge is the upstream challenge: ChallengeDNS01 (also when
	// empty) or ChallengeHTTP01.
	Challenge string `json:"challenge,omitempty"`
	// Interface is where the CA's HTTP-01 requests come in (HTTP-01
	// only).
	Interface string `json:"interface,omitempty"`
	// DNS01 writes the upstream DNS-01 challenge's TXT records (DNS-01
	// only).
	DNS01 *DNS01 `json:"dns01,omitempty"`
}

// HTTP01 says whether the policy's names are validated upstream by
// HTTP-01.
func (pol *ACMEProxyPolicy) HTTP01() bool { return pol.Challenge == ChallengeHTTP01 }

// HTTP01Interfaces are the interfaces of the HTTP-01 policies, where port
// 80 opens while the agent answers the upstream CA.
func (p *ACMEProxy) HTTP01Interfaces() []string {
	var out []string
	for _, pol := range p.Policies {
		if pol.HTTP01() && !slices.Contains(out, pol.Interface) {
			out = append(out, pol.Interface)
		}
	}
	return out
}

// ACMEProxyService is the proxy's auto input rule's service, and its
// source set's name.
const (
	ACMEProxyService = "acme proxy"
	ACMEProxySet     = "acme_proxy_clients"
)

// ACMEProxyAllows says whether a policy domain allows name.
func ACMEProxyAllows(domain, name string) bool {
	if rest, ok := strings.CutPrefix(domain, "*."); ok {
		return strings.HasSuffix(name, "."+rest)
	}
	return name == domain
}

// Policy returns the first policy that allows name from addr; nil when
// none does.
func (p *ACMEProxy) Policy(name string, addr netip.Addr) *ACMEProxyPolicy {
	for i := range p.Policies {
		pol := &p.Policies[i]
		if pol.AllowsSource(addr) && pol.allowsName(name) {
			return pol
		}
	}
	return nil
}

func (pol *ACMEProxyPolicy) allowsName(name string) bool {
	for _, d := range pol.Domains {
		if ACMEProxyAllows(d, name) {
			return true
		}
	}
	return false
}

// AllowsSource says whether addr is in the policy's sources.
func (pol *ACMEProxyPolicy) AllowsSource(addr netip.Addr) bool {
	if len(pol.Sources) == 0 {
		return true
	}
	addr = addr.Unmap()
	for _, s := range pol.Sources {
		if p, err := netip.ParsePrefix(s); err == nil && p.Contains(addr) {
			return true
		}
	}
	return false
}

// Clients are the prefixes the auto rule lets in: every policy's sources,
// or nil (any) when a policy has none.
func (p *ACMEProxy) Clients() []string {
	var out []string
	for _, pol := range p.Policies {
		if len(pol.Sources) == 0 {
			return nil
		}
		for _, s := range pol.Sources {
			if pfx, err := netip.ParsePrefix(s); err == nil {
				out = append(out, pfx.Masked().String())
			}
		}
	}
	return out
}

// ACMEProxyDomain checks a policy domain: a certificate domain, a
// wildcard allowing the names below it.
func ACMEProxyDomain(d string) error {
	return CertDomain(d, ChallengeDNS01)
}

func (v *validator) acmeProxy(p string, in *Instance, ifaces map[string]*Interface) {
	x := in.ACMEProxy
	pp := p + ": acme proxy"
	if x.Port < 1 || x.Port > 65535 {
		v.addf("%s: port must be 1-65535", pp)
	}
	if len(x.Interfaces) == 0 {
		v.addf("%s: needs an interface", pp)
	}
	for _, name := range x.Interfaces {
		if ifaces[name] == nil {
			v.addf("%s: unknown interface %q", pp, name)
		}
	}
	if x.Certificate != "" {
		found := false
		for _, c := range in.Certificates {
			found = found || c.Name == x.Certificate
		}
		if !found {
			v.addf("%s: unknown certificate %q", pp, x.Certificate)
		}
	}
	if _, err := ACMEDirectory(x.CA); err != nil {
		v.addf("%s: %v", pp, err)
	}
	if x.Email != "" && !ValidEmail(x.Email) {
		v.addf("%s: invalid email %q", pp, x.Email)
	}
	if len(x.Policies) == 0 {
		v.addf("%s: needs a policy", pp)
	}
	names := map[string]bool{}
	for _, pol := range x.Policies {
		pp := fmt.Sprintf("%s: policy %q", pp, pol.Name)
		if pol.Name == "" || len(pol.Name) > 64 || strings.ContainsFunc(pol.Name, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
			v.addf("%s: invalid name", pp)
		}
		if names[pol.Name] {
			v.addf("%s: duplicate", pp)
		}
		names[pol.Name] = true
		if len(pol.Domains) == 0 || len(pol.Domains) > 100 {
			v.addf("%s: needs 1-100 domains", pp)
		}
		for _, d := range pol.Domains {
			if err := ACMEProxyDomain(d); err != nil {
				v.addf("%s: %v", pp, err)
			}
		}
		for _, s := range pol.Sources {
			if _, err := netip.ParsePrefix(s); err != nil {
				v.addf("%s: invalid source prefix %q", pp, s)
			}
		}
		switch pol.Challenge {
		case ChallengeHTTP01:
			if ifaces[pol.Interface] == nil {
				v.addf("%s: unknown interface %q", pp, pol.Interface)
			}
			if pol.DNS01 != nil {
				v.addf("%s: HTTP-01 has no DNS update client", pp)
			}
		case "", ChallengeDNS01:
			if pol.Interface != "" {
				v.addf("%s: DNS-01 has no interface", pp)
			}
			d := pol.DNS01
			if d == nil {
				v.addf("%s: DNS-01 needs a DNS update client", pp)
				continue
			}
			dp := fmt.Sprintf("%s: dns update %q", pp, d.Client)
			v.dnsProvider(dp, DynDNS{Provider: d.Provider, ProviderSettings: d.ProviderSettings, Server: d.Server, TSIG: d.TSIG})
			v.tsig(dp, d.Provider, d.TSIG)
			if !validDomain(d.Zone) {
				v.addf("%s: invalid zone %q", dp, d.Zone)
			}
		default:
			v.addf("%s: challenge must be one of %s", pp, strings.Join(Challenges, ", "))
		}
	}
}
