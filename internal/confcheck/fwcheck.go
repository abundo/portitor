// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package confcheck

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/schema"
)

// The routing objects' own checks are fwconfig's (Check*), which the build
// runs only while BGP, OSPF or IS-IS does; the GUI ran them on every save.
// An entry is made the fwconfig struct by its JSON: the leaves' names in
// snake case, the lists' by lists.

func init() {
	register("/instance/prefix-list", hook{check: fwCheck(func(e *datastore.Node) []string {
		var v fwconfig.PrefixList
		asFW(e, &v, map[string]string{"entry": "entries"})
		return fwconfig.CheckPrefixList(v)
	})})
	register("/instance/as-path-list", hook{check: fwCheck(func(e *datastore.Node) []string {
		var v fwconfig.ASPathList
		asFW(e, &v, map[string]string{"entry": "entries"})
		return fwconfig.CheckASPathList(v)
	})})
	register("/instance/community-list", hook{normalize: normalizeCommunityList, check: fwCheck(func(e *datastore.Node) []string {
		var v fwconfig.CommunityList
		asFW(e, &v, map[string]string{"entry": "entries"})
		return fwconfig.CheckCommunityList(v)
	})})
	register("/instance/route-map", hook{normalize: normalizeRouteMap, check: fwCheck(func(e *datastore.Node) []string {
		var v fwconfig.RouteMap
		asFW(e, &v, map[string]string{"entry": "entries"})
		return fwconfig.CheckRouteMap(v)
	})})
	register("/instance/isis-interface", hook{check: func(c *Ctx, e *datastore.Node) []error {
		var v fwconfig.ISISInterface
		asFW(e, &v, nil)
		style := ""
		for _, s := range instanceOf(e).Lists["isis"] {
			if s.Leaf("vrf") == vrfName(instanceOf(e), e.Leaf("name")) {
				style = s.Leaf("metric-style")
			}
		}
		return asErrors(fwconfig.CheckISISInterface(v, style))
	}})
}

// checkOSPFConfig is fwconfig's check of an OSPF config entry.
func checkOSPFConfig(o *datastore.Node) []error {
	var v fwconfig.OSPF
	asFW(o, &v, map[string]string{"area": "areas", "range": "ranges", "summary": "summaries", "network": "networks"})
	return asErrors(fwconfig.CheckOSPF(&v, num(o, "version")))
}

// checkISISConfig is fwconfig's check of an IS-IS config entry: its
// interfaces are checked as theirs.
func checkISISConfig(c *Ctx, s *datastore.Node) []error {
	var v fwconfig.ISIS
	asFW(s, &v, nil)
	if v.NET == "" {
		v.NET = "49.0001.0000.0000.0001.00" // not enabled yet: the rest is checked all the same
	}
	errs := asErrors(fwconfig.CheckISIS(&v))
	if on(s, "enabled") && s.Leaf("net") == "" {
		errs = append(errs, fail("net: a NET is required (49.0001.1921.6800.1001.00: area, system id, 00)"))
	}
	// Narrow metrics cap the interfaces' metrics too.
	if max := fwconfig.ISISMaxMetric(s.Leaf("metric-style")); max < fwconfig.ISISMaxMetric("") {
		in := instanceOf(s)
		var over []string
		for _, i := range in.Lists["isis-interface"] {
			if num(i, "metric") > max && vrfName(in, i.Leaf("name")) == s.Leaf("vrf") {
				over = append(over, i.Leaf("name"))
			}
		}
		if len(over) > 0 {
			errs = append(errs, fail("metric-style: narrow metrics go up to %d; lower the metric of %s first", max, strings.Join(over, ", ")))
		}
	}
	return errs
}

// vrfName is the VRF of the instance's interface: "main" for the main
// table, as the routing lists' keys write it.
func vrfName(in *datastore.Node, ifname string) string {
	if i := in.Entry("interface", []string{ifname}); i != nil && i.Leaf("vrf") != "" {
		return i.Leaf("vrf")
	}
	return "main"
}

func fwCheck(fn func(*datastore.Node) []string) func(*Ctx, *datastore.Node) []error {
	return func(c *Ctx, e *datastore.Node) []error { return asErrors(fn(e)) }
}

func asErrors(problems []string) []error {
	var errs []error
	for _, p := range problems {
		errs = append(errs, fail("%s", p))
	}
	return errs
}

// asFW decodes the entry e into the fwconfig struct dst.
func asFW(e *datastore.Node, dst any, lists map[string]string) {
	data, _ := json.Marshal(fwValue(e, lists))
	_ = json.Unmarshal(data, dst)
}

func fwValue(n *datastore.Node, lists map[string]string) map[string]any {
	out := map[string]any{}
	key := func(name string) string {
		if k, ok := lists[name]; ok {
			return k
		}
		return strings.ReplaceAll(name, "-", "_")
	}
	for _, s := range n.S.Children {
		switch s.Kind {
		case schema.Leaf:
			if v, ok := n.Leaves[s.Name]; ok {
				out[key(s.Name)] = fwScalar(s, v)
			} else if s.HasDefault {
				out[key(s.Name)] = fwScalar(s, s.Default)
			}
		case schema.LeafList:
			var vs []any
			for _, v := range n.LeafLists[s.Name] {
				vs = append(vs, fwScalar(s, v))
			}
			if vs != nil {
				out[key(s.Name)] = vs
			}
		case schema.Container:
			if c := n.Containers[s.Name]; c != nil {
				out[key(s.Name)] = fwValue(c, nil)
			}
		case schema.List:
			var es []any
			for _, e := range n.Lists[s.Name] {
				es = append(es, fwValue(e, nil))
			}
			if es != nil {
				out[key(s.Name)] = es
			}
		}
	}
	return out
}

func fwScalar(s *schema.Node, v string) any {
	switch {
	case s.Type.Kind == "boolean":
		return v == "true"
	case s.Type.Numeric():
		return json.Number(v)
	}
	return v
}

func init() {
	register("/instance/dnssec-policy", hook{check: func(c *Ctx, e *datastore.Node) []error {
		errs := checkDNSScope(c, e)
		for _, b := range []string{"default", "insecure", "none"} {
			if e.Leaf("name") == b {
				errs = append(errs, fail("name: %s is one of BIND's own policies", b))
			}
		}
		return errs
	}})
}

// checkDynDNSDoc is fwconfig's check of a DNS update client and its
// records, as one alone in a virtual firewall (the GUI's check): what the
// build skips while the client is off.
func checkDynDNSDoc(d *datastore.Node) []error {
	var v fwconfig.DynDNS
	asFW(d, &v, map[string]string{"record": "records", "provider-setting": "provider_settings"})
	v.ProviderSettings = map[string]string{}
	for _, s := range d.Lists["provider-setting"] {
		v.ProviderSettings[s.Leaf("name")] = s.Leaf("value")
	}
	if len(v.ProviderSettings) == 0 {
		v.ProviderSettings = nil
	}
	if n := d.Leaf("tsig-name"); n != "" {
		v.TSIG = &fwconfig.TSIG{Name: n, Algorithm: d.Leaf("tsig-algorithm"), Secret: d.Leaf("tsig-secret")}
	}
	if v.Interface == "" {
		v.Interface = "eth0"
	}
	in := fwconfig.Instance{Name: "check", Default: true,
		Interfaces: []fwconfig.Interface{{Name: v.Interface, Kind: fwconfig.KindPhysical, Enabled: true, IPv4Mode: fwconfig.ModeNone}},
		DynDNS:     []fwconfig.DynDNS{v}}
	err := (&fwconfig.Document{Version: fwconfig.Version, Instances: []fwconfig.Instance{in}}).Validate()
	ve, ok := err.(*fwconfig.ValidationError)
	if !ok {
		return nil
	}
	var errs []error
	for _, p := range ve.Problems {
		if strings.HasSuffix(p, "needs at least one record") {
			continue
		}
		if i := strings.Index(p, fmt.Sprintf("dns update %q: ", v.Name)); i >= 0 {
			p = p[i+len(fmt.Sprintf("dns update %q: ", v.Name)):]
		}
		errs = append(errs, fail("%s", p))
	}
	return errs
}

// checkSOA is fwconfig's check of an SOA template.
func checkSOA(s *datastore.Node) []error {
	var v fwconfig.DNSSOATemplate
	asFW(s, &v, nil)
	in := fwconfig.Instance{Name: "check", Default: true, DNS: fwconfig.DNSServer{SOATemplates: []fwconfig.DNSSOATemplate{v}}}
	err := (&fwconfig.Document{Version: fwconfig.Version, Instances: []fwconfig.Instance{in}}).Validate()
	ve, ok := err.(*fwconfig.ValidationError)
	if !ok {
		return nil
	}
	var errs []error
	for _, p := range ve.Problems {
		errs = append(errs, fail("%s", p[strings.LastIndex(p, ": ")+2:]))
	}
	return errs
}

// checkZoneTemplate is fwconfig's check of a DNS template, with the SOA
// template and DNSSEC policy it uses (its instance's, or global ones).
func checkZoneTemplate(c *Ctx, t *datastore.Node) []error {
	in := instanceOf(t)
	find := func(list, name string) *datastore.Node {
		if e := in.Entry(list, []string{name}); e != nil {
			return e
		}
		for _, o := range c.T.Root.Lists["instance"] {
			if e := o.Entry(list, []string{name}); e != nil && on(e, "global") {
				return e
			}
		}
		return nil
	}
	zt := fwconfig.DNSZoneTemplate{Name: t.Leaf("name"), SOA: t.Leaf("soa-template"), DNSSECPolicy: t.Leaf("dnssec-policy")}
	zt.DefaultTTL, _ = strconv.ParseInt(t.Leaf("default-ttl"), 10, 64)
	for _, n := range t.Lists["nameserver"] {
		if !slices.Contains(zt.Nameservers, n.Leaf("name")) {
			zt.Nameservers = append(zt.Nameservers, n.Leaf("name"))
		}
	}
	dns := fwconfig.DNSServer{ZoneTemplates: []fwconfig.DNSZoneTemplate{zt}}
	if s := find("dns-soa-template", zt.SOA); s != nil {
		var v fwconfig.DNSSOATemplate
		asFW(s, &v, nil)
		dns.SOATemplates = []fwconfig.DNSSOATemplate{v}
	}
	if p := find("dnssec-policy", zt.DNSSECPolicy); p != nil {
		var v fwconfig.DNSSECPolicy
		asFW(p, &v, nil)
		dns.DNSSECPolicies = []fwconfig.DNSSECPolicy{v}
	}
	check := fwconfig.Instance{Name: "check", Default: true, DNS: dns}
	err := (&fwconfig.Document{Version: fwconfig.Version, Instances: []fwconfig.Instance{check}}).Validate()
	ve, ok := err.(*fwconfig.ValidationError)
	if !ok {
		return nil
	}
	var errs []error
	for _, p := range ve.Problems {
		errs = append(errs, fail("%s", p[strings.LastIndex(p, ": ")+2:]))
	}
	return errs
}
