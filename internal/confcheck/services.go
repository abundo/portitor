// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package confcheck

import (
	"encoding/base64"
	"slices"
	"strings"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
)

// The services of a virtual firewall: DNS (templates, blocklists, DNS
// update clients), the ACME proxy, SNMP and BFD. What a service's own
// fields must be is fwconfig.Validate's at the build (a save's warnings);
// here the GUI's normalizing, and what takes several rows.

func init() {
	register("/instance/dns-soa-template", hook{normalize: normalizeSOA, check: func(c *Ctx, e *datastore.Node) []error {
		return append(checkDNSScope(c, e), checkSOA(e)...)
	}})
	register("/instance/dns-template", hook{check: checkDNSTemplate})
	register("/instance/dns-blocklist", hook{check: checkBlocklist})
	register("/instance/dns-update", hook{normalize: normalizeDynDNS, check: checkDynDNS})
	register("/instance/dns-update/record", hook{normalize: normalizeDynDNSRecord, check: checkDynDNSRecord})
	register("/instance/acme-proxy-policy", hook{normalize: normalizeProxyPolicy, check: checkProxyPolicy})
	register("/instance/snmp-user", hook{normalize: normalizeSNMPUser, check: checkSNMPUser})
	register("/instance/bfd-interface", hook{check: checkBFDInterface})
}

// checkServices of an instance: what its switches need (instance hook,
// called from checkInstance).
func checkInstanceServices(c *Ctx, in *datastore.Node) []error {
	var errs []error
	for _, n := range in.LeafLists["dns-blocklist-allow"] {
		if !fwconfig.ValidDomain(n) {
			errs = append(errs, fail("dns-blocklist-allow: %q is not a domain", n))
		}
	}
	if len(in.Lists["dns-blocklist"]) > fwconfig.MaxBlocklists {
		errs = append(errs, fail("dns-blocklist: at most %d in a virtual firewall", fwconfig.MaxBlocklists))
	}
	if ca := in.Leaf("acme-proxy-ca"); ca != "" {
		if _, err := fwconfig.ACMEDirectory(ca); err != nil {
			errs = append(errs, fail("acme-proxy-ca: %v", err))
		}
	}
	if crt := in.Entry("certificate", []string{in.Leaf("acme-proxy-certificate")}); crt != nil && isCA(crt) {
		errs = append(errs, fail("acme-proxy-certificate: %s is a certificate authority; pick a server certificate", crt.Leaf("name")))
	}
	if on(in, "acme-proxy-enabled") && !anyOn(in, "acme-proxy-policy") {
		errs = append(errs, fail("acme-proxy-enabled: add a policy first"))
	}
	if cm := in.Leaf("snmp-community"); cm != "" {
		if e := fwconfig.CheckSNMPCommunity(cm); e != "" {
			errs = append(errs, fail("snmp-community: %s", e))
		}
	}
	for _, l := range []string{"snmp-location", "snmp-contact"} {
		if !fwconfig.CheckSNMPText(in.Leaf(l)) {
			errs = append(errs, fail("%s: one line of at most 255 characters", l))
		}
	}
	if on(in, "snmp-enabled") && in.Leaf("snmp-community") == "" && !anyOn(in, "snmp-user") {
		errs = append(errs, fail("snmp-enabled: set a community (SNMPv2c) or add an SNMPv3 user first"))
	}
	if m := num(in, "bfd-detect-multiplier"); m != 0 && (m < 2 || m > 255) {
		errs = append(errs, fail("bfd-detect-multiplier: 2-255"))
	}
	for _, l := range []string{"bfd-receive-interval", "bfd-transmit-interval"} {
		if ms := num(in, l); ms != 0 && (ms < 10 || ms > 60000) {
			errs = append(errs, fail("%s: 10-60000 ms", l))
		}
	}
	return errs
}

// anyOn reports whether an entry of in's list is enabled.
func anyOn(in *datastore.Node, list string) bool {
	for _, e := range in.Lists[list] {
		if e.Leaf("enabled") != "false" {
			return true
		}
	}
	return false
}

// normalizeInstanceServices of an instance (called from
// normalizeInstance).
func normalizeInstanceServices(c *Ctx, in *datastore.Node) {
	if ns := in.LeafLists["dns-blocklist-allow"]; ns != nil {
		for i, n := range ns {
			ns[i] = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(n), "*."), "."))
		}
		in.LeafLists["dns-blocklist-allow"] = dedupe(ns)
	}
}

func normalizeSOA(c *Ctx, s *datastore.Node) error {
	// The mailbox may be written as an email address.
	if r, ok := s.Leaves["rname"]; ok {
		s.Leaves["rname"] = strings.Replace(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r), ".")), "@", ".", 1)
	}
	return nil
}

// checkDNSScope: only the default instance's SOA templates, DNSSEC
// policies and DNS templates may be global, a global one's name is unique
// over every instance, and an instance's own can't take a global one's
// name (zones and templates refer to them by name).
func checkDNSScope(c *Ctx, e *datastore.Node) []error {
	var errs []error
	in, list, name := instanceOf(e), e.S.Name, e.Leaf("name")
	global := on(e, "global")
	if global && !on(in, "is-default") {
		errs = append(errs, fail("global: only the default virtual firewall's can be global"))
	}
	for _, other := range c.T.Root.Lists["instance"] {
		if other == in {
			continue
		}
		if o := other.Entry(list, []string{name}); o != nil && (global || on(o, "global")) {
			errs = append(errs, fail("name: %q is in use (in %s)", name, other.Leaf("name")))
		}
	}
	// Used by another instance's templates or zones: it stays global.
	if !global && on(in, "is-default") {
		for _, other := range c.T.Root.Lists["instance"] {
			if other != in && usesDNS(other, list, name) {
				errs = append(errs, fail("global: %s stays global; %s uses it", name, other.Leaf("name")))
				break
			}
		}
	}
	return errs
}

// usesDNS reports whether in's templates or zones name the entry of list.
func usesDNS(in *datastore.Node, list, name string) bool {
	switch list {
	case "dns-soa-template", "dnssec-policy":
		leaf := "soa-template"
		if list == "dnssec-policy" {
			leaf = "dnssec-policy"
		}
		for _, t := range in.Lists["dns-template"] {
			if t.Leaf(leaf) == name {
				return true
			}
		}
	case "dns-template":
		for _, z := range in.Lists["dns-zone"] {
			if z.Leaf("dns-template") == name {
				return true
			}
		}
	}
	return false
}

func checkDNSTemplate(c *Ctx, t *datastore.Node) []error {
	errs := append(checkDNSScope(c, t), checkZoneTemplate(c, t)...)
	if !on(t, "global") {
		return errs
	}
	def := c.T.Root
	for _, in := range c.T.Root.Lists["instance"] {
		if on(in, "is-default") {
			def = in
		}
	}
	if s := def.Entry("dns-soa-template", []string{t.Leaf("soa-template")}); s != nil && !on(s, "global") {
		errs = append(errs, fail("soa-template: a global DNS template needs a global SOA template"))
	}
	if p := t.Leaf("dnssec-policy"); p != "" {
		if k := def.Entry("dnssec-policy", []string{p}); k != nil && !on(k, "global") {
			errs = append(errs, fail("dnssec-policy: a global DNS template needs a global DNSSEC policy"))
		}
	}
	return errs
}

func checkBlocklist(c *Ctx, b *datastore.Node) []error {
	var errs []error
	if !fwconfig.ValidBlocklistName(b.Leaf("name")) {
		errs = append(errs, fail("name: lowercase letters, digits and '-', at most 32 characters"))
	}
	urls, key := b.LeafLists["urls"], b.Leaf("auth-key")
	if len(urls) == 0 || len(urls) > fwconfig.MaxBlocklistURLs {
		errs = append(errs, fail("urls: 1 to %d", fwconfig.MaxBlocklistURLs))
	}
	keyed := false
	for _, u := range urls {
		if err := fwconfig.CheckBlocklistURL(u, key != ""); err != nil {
			errs = append(errs, fail("urls: %s: %v", u, err))
		}
		keyed = keyed || strings.Contains(u, fwconfig.BlocklistKeyPlaceholder)
	}
	if key != "" && !keyed {
		errs = append(errs, fail("auth-key: put %s in the url where it goes", fwconfig.BlocklistKeyPlaceholder))
	}
	if key != "" && !fwconfig.ValidBlocklistKey(key) {
		errs = append(errs, fail("auth-key: letters, digits and . _ ~ -, at most 256 characters"))
	}
	if r := b.Leaf("refresh"); r != "" && (num(b, "refresh") < 5 || num(b, "refresh") > 10080) {
		errs = append(errs, fail("refresh: 5 to 10080 minutes (a week)"))
	}
	return errs
}

func normalizeDynDNS(c *Ctx, d *datastore.Node) error {
	if p := d.Leaf("provider"); p != "" && p != fwconfig.ProviderRFC2136 {
		clear(d, "server", "tsig-name", "tsig-algorithm", "tsig-secret")
		return nil
	}
	delete(d.Lists, "provider-setting")
	if d.Leaf("tsig-name") == "" {
		clear(d, "tsig-algorithm", "tsig-secret")
	} else if d.Leaf("tsig-algorithm") == "" {
		set(d, "tsig-algorithm", fwconfig.TSIGAlgorithms[0])
	}
	return nil
}

func checkDynDNS(c *Ctx, d *datastore.Node) []error {
	var errs []error
	if !fwconfig.ValidFileName(d.Leaf("name")) {
		errs = append(errs, fail("name: no control characters or /, not . or .., at most 255 bytes"))
	}
	p := d.Leaf("provider")
	if p == "" {
		p = fwconfig.ProviderRFC2136
	}
	if fwconfig.FindDNSProvider(p) == nil {
		return append(errs, fail("provider: no provider %q", p))
	}
	errs = append(errs, checkDynDNSDoc(d)...)
	if p != fwconfig.ProviderRFC2136 {
		return errs
	}
	if _, err := fwconfig.DynDNSServer(d.Leaf("server")); err != nil {
		errs = append(errs, fail("server: the nameserver's IP address or DNS name, optionally with a port (192.0.2.53, [2001:db8::53]:53 or ns1.example.com)"))
	}
	if d.Leaf("tsig-name") != "" {
		s := d.Leaf("tsig-secret")
		if s == "" {
			errs = append(errs, fail("tsig-secret: a TSIG key needs its secret"))
		} else if _, err := base64.StdEncoding.DecodeString(s); err != nil {
			errs = append(errs, fail("tsig-secret: base64, as in the key file"))
		}
	}
	return errs
}

func normalizeDynDNSRecord(c *Ctx, r *datastore.Node) error {
	if t, ok := r.Leaves["type"]; ok {
		r.Leaves["type"] = strings.ToUpper(t)
	}
	if t := r.Leaf("type"); t == "A" || t == "AAAA" {
		if v, ok := r.Leaves["value"]; ok {
			r.Leaves["value"] = strings.ToLower(v)
		}
	}
	return nil
}

func checkDynDNSRecord(c *Ctx, r *datastore.Node) []error {
	t := r.Leaf("type")
	ok := false
	for _, x := range fwconfig.DynDNSRecordTypes {
		ok = ok || x == t
	}
	if !ok {
		return []error{fail("type: one of %s", strings.Join(fwconfig.DynDNSRecordTypes, ", "))}
	}
	if t == "CNAME" && r.Leaf("value") == "" {
		return []error{fail("value: a CNAME needs its target")}
	}
	return nil
}

func normalizeProxyPolicy(c *Ctx, p *datastore.Node) error {
	if ds := p.LeafLists["domains"]; ds != nil {
		for i, d := range ds {
			ds[i] = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		}
		p.LeafLists["domains"] = dedupe(ds)
	}
	if p.Leaf("challenge") == fwconfig.ChallengeHTTP01 {
		clear(p, "dns-update")
	} else {
		clear(p, "interface")
	}
	return nil
}

func checkProxyPolicy(c *Ctx, p *datastore.Node) []error {
	var errs []error
	ds := p.LeafLists["domains"]
	if len(ds) == 0 || len(ds) > 100 {
		errs = append(errs, fail("domains: 1-100 names"))
	}
	for _, d := range ds {
		if err := fwconfig.ACMEProxyDomain(d); err != nil {
			errs = append(errs, fail("domains: %v", err))
		}
	}
	if p.Leaf("challenge") == fwconfig.ChallengeHTTP01 {
		if p.Leaf("interface") == "" {
			errs = append(errs, fail("interface: pick the interface that answers the challenge"))
		}
	} else if p.Leaf("dns-update") == "" {
		errs = append(errs, fail("dns-update: pick the DNS update client that answers the challenge"))
	}
	return errs
}

func normalizeSNMPUser(c *Ctx, u *datastore.Node) error {
	if u.Leaf("priv-protocol") == "" {
		clear(u, "priv-password")
	}
	return nil
}

func checkSNMPUser(c *Ctx, u *datastore.Node) []error {
	var errs []error
	for _, e := range fwconfig.CheckSNMPUser(fwconfig.SNMPUser{Name: u.Leaf("name"), AuthProtocol: u.Leaf("auth-protocol"),
		AuthPassword: u.Leaf("auth-password"), PrivProtocol: u.Leaf("priv-protocol"), PrivPassword: u.Leaf("priv-password")}) {
		errs = append(errs, fail("%s", e))
	}
	if a := u.Leaf("auth-password"); a != "" && a == u.Leaf("priv-password") {
		errs = append(errs, fail("priv-password: use a different privacy password than the authentication one"))
	}
	return errs
}

func checkBFDInterface(c *Ctx, b *datastore.Node) []error {
	if i := instanceOf(b).Entry("interface", []string{b.Leaf("interface")}); i != nil && i.Leaf("kind") == fwconfig.KindLoopback {
		return []error{fail("interface: BFD is not for loopback interfaces")}
	}
	return nil
}

func init() {
	register("/instance/certificate", hook{normalize: normalizeCertificate, check: checkCertificate})
	register("/instance/ospf", hook{normalize: normalizeOSPF, check: checkOSPF})
	register("/instance/ospf-interface", hook{normalize: normalizeOSPFInterface, check: func(c *Ctx, e *datastore.Node) []error {
		var v fwconfig.OSPFInterface
		asFW(e, &v, nil)
		errs := asErrors(fwconfig.CheckOSPFInterface(v, num(e, "version")))
		if e.Leaf("version") == "3" && e.Leaf("area") == "" {
			errs = append(errs, fail("area: an OSPFv3 interface needs its area"))
		}
		return errs
	}})
}

// normalizeOpenVPN of an OpenVPN interface (from normalizeInterface).
func normalizeOpenVPN(c *Ctx, i *datastore.Node) error {
	clear(i, "peer-addresses") // both hosts of an HA pair have the same
	if i.Leaf("ovpn-tls-crypt") == "" {
		key, err := fwconfig.GenerateOpenVPNKey()
		if err != nil {
			return err
		}
		set(i, "ovpn-tls-crypt", key)
	}
	// A role set once is required until an edit takes it away: a deleted
	// role, or one left out of a bundle, lets no one in.
	if i.Leaf("ovpn-role") != "" {
		set(i, "ovpn-require-role", "true")
	} else if old := c.old(i); old != nil && old.Leaf("ovpn-role") != "" {
		clear(i, "ovpn-require-role")
	}
	return nil
}

// checkOpenVPN of an OpenVPN interface (from checkInterface).
func checkOpenVPN(c *Ctx, i *datastore.Node) []error {
	var errs []error
	in, name := instanceOf(i), i.Leaf("name")
	if i.Leaf("ipv4-mode") == fwconfig.ModeDHCP {
		errs = append(errs, fail("OpenVPN interfaces have static addresses"))
	}
	for _, o := range in.Lists["interface"] {
		if o != i && o.Leaf("kind") == fwconfig.KindOpenVPN {
			errs = append(errs, fail("a virtual firewall has one OpenVPN interface; %s is it", o.Leaf("name")))
		}
	}
	mode := i.Leaf("ovpn-mode")
	var tcp []string
	if mode == fwconfig.OpenVPNAdaptive {
		tcp = i.LeafLists["ovpn-tcp-addresses"]
	}
	for _, e := range fwconfig.CheckOpenVPNAddresses(mode, i.LeafLists["addresses"], tcp) {
		errs = append(errs, fail("addresses: %s", e))
	}
	if crt := in.Entry("certificate", []string{i.Leaf("ovpn-certificate")}); crt != nil && isCA(crt) {
		errs = append(errs, fail("ovpn-certificate: %s is a certificate authority; pick a server certificate", crt.Leaf("name")))
	}
	if l := i.Leaf("ovpn-listen"); l != "" {
		if l == name {
			errs = append(errs, fail("ovpn-listen: clients come in on another interface"))
		} else if !ifaceNames(c, in)[l] {
			errs = append(errs, fail("ovpn-listen: %s is not an interface of this virtual firewall", l))
		}
	}
	return errs
}

// isCA reports whether a certificate is an imported (or made) CA.
func isCA(crt *datastore.Node) bool {
	if crt.Leaf("source") != fwconfig.CertSourceImport {
		return false
	}
	leaf := fwconfig.ChainLeaf(crt.Leaf("full-chain"))
	return leaf != nil && leaf.IsCA
}

func normalizeCertificate(c *Ctx, crt *datastore.Node) error {
	old := c.old(crt)
	if old != nil && old.Leaf("source") != crt.Leaf("source") && old.Leaf("full-chain") == "" {
		// An ACME certificate made here becomes an imported one (generate).
	} else if old != nil && old.Leaf("source") != crt.Leaf("source") {
		return fail("source: can't change; add a new certificate")
	}
	if old != nil && isCA(old) != isCA(crt) {
		return fail("can't change between a CA and a server certificate; add a new one")
	}
	if crt.Leaf("source") == fwconfig.CertSourceImport {
		return normalizeImported(crt)
	}
	clear(crt, "full-chain", "priv-key")
	if crt.Leaf("challenge") == fwconfig.ChallengeHTTP01 {
		clear(crt, "dns-update")
	} else {
		clear(crt, "interface")
	}
	var ds []string
	for _, d := range crt.LeafLists["domains"] {
		ds = append(ds, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), ".")))
	}
	if cn, ok := crt.Leaves["common-name"]; ok {
		cn = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cn), "."))
		crt.Leaves["common-name"] = cn
		// The common name is one of the subject alternative names.
		if cn != "" {
			ds = append([]string{cn}, ds...)
		}
	}
	if ds != nil {
		crt.LeafLists["domains"] = dedupe(ds)
	}
	return nil
}

func checkCertificate(c *Ctx, crt *datastore.Node) []error {
	var errs []error
	if !fwconfig.ValidFileName(crt.Leaf("name")) {
		errs = append(errs, fail("name: no control characters or /, not . or .., at most 255 bytes"))
	}
	if isCA(crt) && !on(instanceOf(crt), "is-default") {
		errs = append(errs, fail("a CA belongs to the firewall: add it on the firewall's host, not in a virtual firewall"))
	}
	if crt.Leaf("source") != fwconfig.CertSourceACME {
		return errs
	}
	if len(crt.LeafLists["domains"]) == 0 {
		errs = append(errs, fail("domains: at least one DNS name"))
	}
	if len(crt.Leaf("common-name")) > 64 {
		errs = append(errs, fail("common-name: at most 64 characters"))
	}
	if crt.Leaf("challenge") == fwconfig.ChallengeHTTP01 {
		if crt.Leaf("interface") == "" {
			errs = append(errs, fail("interface: pick the interface that answers the challenge"))
		}
	} else if crt.Leaf("dns-update") == "" {
		errs = append(errs, fail("dns-update: pick the DNS update client that answers the challenge"))
	}
	return errs
}

func normalizeOSPF(c *Ctx, o *datastore.Node) error {
	if !on(o, "default-originate") {
		clear(o, "default-always")
	}
	for _, a := range o.Lists["area"] {
		if a.Leaf("type") == fwconfig.AreaNormal || a.Leaf("type") == "" {
			clear(a, "no-summary")
		}
	}
	for _, r := range o.Lists["range"] {
		if on(r, "not-advertise") {
			clear(r, "cost")
		}
	}
	return nil
}

// checkOSPF: network statements and interfaces with an area are FRR's two
// ways of enabling OSPF, one at a time per routing.
func checkOSPF(c *Ctx, o *datastore.Node) []error {
	if v := o.Leaf("version"); v != "2" && v != "3" {
		return []error{fail("version: 2 (OSPFv2, IPv4) or 3 (OSPFv3, IPv6)")}
	}
	if errs := checkOSPFConfig(o); len(errs) > 0 {
		return errs
	}
	if len(o.Lists["network"]) == 0 {
		return nil
	}
	in := instanceOf(o)
	var ifs []string
	for _, i := range in.Lists["ospf-interface"] {
		if i.Leaf("version") != o.Leaf("version") || i.Leaf("area") == "" {
			continue
		}
		if ifc := in.Entry("interface", []string{i.Leaf("name")}); ifc != nil && ifc.Leaf("vrf") == vrfOf(o) {
			ifs = append(ifs, i.Leaf("name"))
		}
	}
	if len(ifs) > 0 {
		return []error{fail("network: network statements can't be used while interfaces have an area (%s); FRR enables OSPF one way or the other", strings.Join(ifs, ", "))}
	}
	return nil
}

func normalizeOSPFInterface(c *Ctx, i *datastore.Node) error {
	switch {
	case i.Leaf("version") != "2" || i.Leaf("auth-key") == "":
		clear(i, "auth-key", "auth-key-id")
	case i.Leaf("auth-key-id") == "" || i.Leaf("auth-key-id") == "0":
		set(i, "auth-key-id", "1")
	}
	return nil
}

// normalizeImported checks an imported certificate's chain against its
// key and takes its names from it.
func normalizeImported(crt *datastore.Node) error {
	for _, l := range []string{"full-chain", "priv-key"} {
		if v, ok := crt.Leaves[l]; ok && v != "" {
			crt.Leaves[l] = strings.TrimSpace(v) + "\n"
		}
	}
	leaf, err := fwconfig.ParseImported(crt.Leaf("full-chain"), crt.Leaf("priv-key"))
	if err != nil {
		return fail("certificate and key: %v", err)
	}
	names := slices.Clone(leaf.DNSNames)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) > 0 {
		crt.LeafLists["domains"] = names
	} else {
		delete(crt.LeafLists, "domains")
	}
	clear(crt, "email", "ca", "key-type", "challenge", "interface", "dns-update")
	if cn := leaf.Subject.CommonName; cn != "" {
		crt.Leaves["common-name"] = cn
	} else {
		clear(crt, "common-name")
	}
	return nil
}
