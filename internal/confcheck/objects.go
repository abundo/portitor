// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package confcheck

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/abundo/portitor/internal/cron"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/netobj"
	"github.com/abundo/portitor/models"
)

// The objects the virtual firewalls share (hosts, address lists, IP
// lists, services, port names, folders, tasks), and per instance rate
// limits and syslog servers; and what a new virtual firewall starts with.

func init() {
	register("/host", hook{check: checkHost})
	register("/address-list", hook{check: checkAddressList})
	register("/ip-list", hook{normalize: normalizeIPList, check: checkIPList})
	register("/service", hook{normalize: normalizeService, check: checkService})
	register("/port-name", hook{normalize: normalizePortName, check: checkPortName})
	register("/object-folder", hook{normalize: normalizeFolder, check: checkFolder})
	register("/task", hook{normalize: normalizeTask, check: checkTask})
	register("/instance/rate-limit", hook{normalize: normalizeRateLimit, check: checkRateLimit})
	register("/instance/syslog-server", hook{check: checkSyslogServer})
}

func checkHost(c *Ctx, o *datastore.Node) []error {
	errs := checkItemFolder(c, o, "hosts")
	name := o.Leaf("name")
	if !netobj.ValidName(name) {
		errs = append(errs, fail("name: letters, digits, _ . -, starting with a letter, at most 63 characters (not \"default\" or \"any\")"))
	}
	if c.T.Root.Entry("address-list", []string{name}) != nil {
		errs = append(errs, fail("name: an address list is named %s", name))
	}
	if len(o.LeafLists["addresses"]) == 0 {
		errs = append(errs, fail("addresses: at least one address or prefix"))
	}
	return errs
}

// nameSet is the hosts and address lists of the tree, for netobj.
func nameSet(c *Ctx) netobj.Set {
	var objs []models.AddressObject
	for _, o := range c.T.Root.Lists["host"] {
		objs = append(objs, models.AddressObject{Name: o.Leaf("name"), Addresses: o.LeafLists["addresses"]})
	}
	var lists []models.AddressList
	for _, l := range c.T.Root.Lists["address-list"] {
		lists = append(lists, models.AddressList{Name: l.Leaf("name"), Entries: l.LeafLists["entries"]})
	}
	return netobj.New(objs, lists...)
}

func checkAddressList(c *Ctx, l *datastore.Node) []error {
	errs := checkItemFolder(c, l, "address_lists")
	name := l.Leaf("name")
	if !netobj.ValidName(name) {
		errs = append(errs, fail("name: letters, digits, _ . -, starting with a letter, at most 63 characters (not \"default\" or \"any\")"))
	}
	if c.T.Root.Entry("host", []string{name}) != nil {
		errs = append(errs, fail("name: a host is named %s", name))
	}
	entries := l.LeafLists["entries"]
	if len(entries) == 0 {
		errs = append(errs, fail("entries: at least one"))
	}
	if slices.Contains(entries, name) {
		errs = append(errs, fail("entries: %s can't hold itself", name))
	} else if _, err := nameSet(c).Expand([]string{name}); err != nil {
		errs = append(errs, fail("entries: %v", err))
	}
	return errs
}

func normalizeIPList(c *Ctx, l *datastore.Node) error {
	// Renamed: the rules and policy routes that name it follow.
	if old := c.old(l); old != nil && old.Leaf("name") != l.Leaf("name") {
		from, to := fwconfig.IPListRef+old.Leaf("name"), fwconfig.IPListRef+l.Leaf("name")
		for _, in := range c.T.Root.Lists["instance"] {
			for _, list := range []string{"rule", "policy-route"} {
				for _, r := range in.Lists[list] {
					for _, leaf := range []string{"src-addrs", "dst-addrs"} {
						for i, v := range r.LeafLists[leaf] {
							if v == from {
								r.LeafLists[leaf][i] = to
							}
						}
					}
				}
			}
		}
	}
	switch l.Leaf("source") {
	case fwconfig.IPListCountry:
		clear(l, "url", "username", "password", "api-key")
		if cs := l.LeafLists["countries"]; cs != nil {
			for i, x := range cs {
				cs[i] = strings.ToUpper(strings.TrimSpace(x))
			}
			l.LeafLists["countries"] = dedupe(cs)
		}
	case fwconfig.IPListCrowdSec:
		clear(l, "countries", "username", "password")
	default:
		clear(l, "countries", "api-key")
		if l.Leaf("username") == "" {
			clear(l, "password")
		}
	}
	return nil
}

func checkIPList(c *Ctx, l *datastore.Node) []error {
	errs := checkItemFolder(c, l, "ip_lists")
	name := l.Leaf("name")
	if strings.HasPrefix(name, fwconfig.IPListRef) {
		errs = append(errs, fail("name: not starting with %s", fwconfig.IPListRef))
	}
	doc := fwconfig.IPList{Name: name, Source: l.Leaf("source"), URL: l.Leaf("url"), Username: l.Leaf("username"),
		Password: l.Leaf("password"), APIKey: l.Leaf("api-key"), Countries: l.LeafLists["countries"]}
	switch doc.Source {
	case fwconfig.IPListCountry:
		if len(doc.Countries) == 0 {
			errs = append(errs, fail("countries: pick at least one"))
		}
		for _, x := range doc.Countries {
			if !fwconfig.ValidCountry(x) {
				errs = append(errs, fail("countries: %q is not a two-letter country code", x))
			}
		}
	default:
		if err := fwconfig.ValidURL(doc.URL); err != nil {
			errs = append(errs, fail("url: %v", err))
		}
		if doc.Source == fwconfig.IPListCrowdSec && doc.APIKey == "" {
			errs = append(errs, fail("api-key: CrowdSec needs a bouncer API key (cscli bouncers add portitor)"))
		}
	}
	if fwconfig.PlainTextCredentials(doc) {
		errs = append(errs, fail("url: http:// would send the credentials unencrypted; use https:// (or a loopback address such as 127.0.0.1)"))
	}
	return errs
}

func normalizeService(c *Ctx, s *datastore.Node) error {
	// Only the fields of the service's type are kept.
	typ := s.Leaf("type")
	if typ != models.ServiceTypePorts {
		delete(s.Lists, "port")
	}
	if typ != models.ServiceTypeICMP && typ != models.ServiceTypeICMP6 {
		clear(s, "icmp-type", "icmp-code")
	}
	if typ != models.ServiceTypeIP {
		clear(s, "ip-protocol")
	}
	return nil
}

// serviceModel is the service entry s as netobj takes it.
func serviceModel(s *datastore.Node) models.Service {
	m := models.Service{Name: s.Leaf("name"), Type: s.Leaf("type"), IcmpType: s.Leaf("icmp-type"), IpProtocol: num(s, "ip-protocol"), Ports: models.ServicePortList{}}
	if v, ok := s.Leaves["icmp-code"]; ok {
		code, _ := strconv.Atoi(v)
		m.IcmpCode = &code
	}
	for _, p := range s.Lists["port"] {
		m.Ports = append(m.Ports, models.ServicePort{Protocol: p.Leaf("protocol"),
			DstLo: num(p, "dst-lo"), DstHi: num(p, "dst-hi"), SrcLo: num(p, "src-lo"), SrcHi: num(p, "src-hi")})
	}
	return m
}

func checkService(c *Ctx, s *datastore.Node) []error {
	name := s.Leaf("name")
	if predefined[name] {
		return []error{fail("name: %s is a predefined service", name)}
	}
	if !netobj.ValidServiceName(name) {
		return []error{fail("name: lower-case letters, digits, _ . -, starting with a letter, at most 63 characters")}
	}
	if err := netobj.CheckService(serviceModel(s)); err != nil {
		return []error{err}
	}
	return nil
}

// normalizePortName: a port name renamed is renamed in the NAT rules'
// port lists, which name it.
func normalizePortName(c *Ctx, p *datastore.Node) error {
	old := c.old(p)
	if old == nil || old.Leaf("name") == p.Leaf("name") {
		return nil
	}
	from, to := old.Leaf("name"), p.Leaf("name")
	for _, in := range c.T.Root.Lists["instance"] {
		for _, n := range in.Lists["nat-rule"] {
			ports, ok := n.Leaves["dst-ports"]
			if !ok {
				continue
			}
			parts := strings.Split(ports, ",")
			for i, part := range parts {
				if strings.EqualFold(strings.TrimSpace(part), from) {
					parts[i] = strings.Replace(part, strings.TrimSpace(part), to, 1)
				}
			}
			n.Leaves["dst-ports"] = strings.Join(parts, ",")
		}
	}
	return nil
}

func checkPortName(c *Ctx, p *datastore.Node) []error {
	var errs []error
	name := p.Leaf("name")
	if !portNameRe.MatchString(name) {
		errs = append(errs, fail("name: lower-case letters, digits, _ . -, starting with a letter, at most 63 characters"))
	}
	if _, ok := fwconfig.ServicePort(name); ok {
		errs = append(errs, fail("name: %s is a built-in port name", name))
	}
	if port := num(p, "port"); port < 1 || port > 65535 {
		errs = append(errs, fail("port: 1 to 65535"))
	}
	return errs
}

func normalizeFolder(c *Ctx, f *datastore.Node) error {
	if old := c.old(f); old != nil && old.Leaf("kind") != f.Leaf("kind") {
		return fail("a folder can't change kind")
	}
	// A folder can't be inside itself.
	seen := map[string]bool{}
	for id := f.Leaf("id"); id != ""; {
		if seen[id] {
			return fail("parent: a folder can't be inside itself")
		}
		seen[id] = true
		p := c.T.Root.Entry("object-folder", []string{id})
		if p == nil {
			break
		}
		id = p.Leaf("parent")
	}
	return nil
}

func normalizeTask(c *Ctx, t *datastore.Node) error {
	words(t, "schedule")
	if t.Leaf("kind") == fwconfig.TaskIPList {
		clear(t, "command", "timeout")
	} else {
		clear(t, "ip-list")
	}
	return nil
}

func checkTask(c *Ctx, t *datastore.Node) []error {
	var errs []error
	if !fwconfig.ValidFileName(t.Leaf("name")) {
		errs = append(errs, fail("name: no control characters or /, not . or .., at most 255 bytes"))
	}
	if _, err := cron.Parse(t.Leaf("schedule")); err != nil {
		errs = append(errs, fail("schedule: %v", err))
	}
	if t.Leaf("kind") == fwconfig.TaskIPList && t.Leaf("ip-list") == "" {
		errs = append(errs, fail("ip-list: pick the IP list to download"))
	}
	return errs
}

func normalizeRateLimit(c *Ctx, l *datastore.Node) error {
	if old := c.old(l); old != nil {
		// A service's rate limit stays the service's.
		if s, ok := old.Leaves["service"]; ok {
			set(l, "service", s)
		} else {
			clear(l, "service")
		}
	} else if svc := l.Leaf("service"); svc != "" {
		// One rate limit per service: the seeded one.
		for _, o := range l.Parent.Lists["rate-limit"] {
			if o != l && o.Leaf("service") == svc {
				clear(l, "service")
			}
		}
	}
	set(l, "per", fwconfig.RatePerSecond)
	if on(l, "shape") {
		clear(l, "burst", "per-source", "connections")
		if l.Leaf("unit") == "" {
			set(l, "unit", fwconfig.RateUnitMBit)
		}
	}
	return nil
}

func checkRateLimit(c *Ctx, l *datastore.Node) []error {
	var errs []error
	if r := num(l, "rate"); r < 1 || r > fwconfig.MaxRate {
		errs = append(errs, fail("rate: 1-%d", fwconfig.MaxRate))
	}
	if b := num(l, "burst"); b < 0 || b > fwconfig.MaxRate {
		errs = append(errs, fail("burst: 0-%d", fwconfig.MaxRate))
	}
	unit := l.Leaf("unit")
	if on(l, "shape") {
		if unit != fwconfig.RateUnitMBit && unit != fwconfig.RateUnitKBit {
			errs = append(errs, fail("unit: shaping is in mbit or kbit per second"))
		}
		if l.Leaf("service") != "" {
			errs = append(errs, fail("shape: this is a service's rate limit, which polices; it can't shape"))
		}
		n := 0
		for _, o := range instanceOf(l).Lists["rate-limit"] {
			if on(o, "shape") {
				n++
			}
		}
		if n > fwconfig.MaxShapers {
			errs = append(errs, fail("at most %d rate limits that shape in a virtual firewall", fwconfig.MaxShapers))
		}
	} else {
		if unit != "" && unit != fwconfig.RateUnitMBit {
			errs = append(errs, fail("unit: policing is in packets or mbit per second"))
		}
		if unit != "" && !on(l, "connections") {
			errs = append(errs, fail("unit: policing Mbit/s needs whole connections"))
		}
	}
	return errs
}

func checkSyslogServer(c *Ctx, s *datastore.Node) []error {
	if !on(instanceOf(s), "is-default") {
		return []error{fail("syslog servers are the firewall's: add them to its default virtual firewall")}
	}
	port := num(s, "port")
	if port == 0 {
		port = fwconfig.SyslogPort
	}
	srv := fwconfig.SyslogServer{Address: s.Leaf("address"), Port: port, Protocol: s.Leaf("protocol"), Format: s.Leaf("format"), Severity: s.Leaf("severity")}
	if errs := fwconfig.CheckSyslogServer(srv); len(errs) > 0 {
		return []error{fail("%s", strings.Join(errs, "; "))}
	}
	for _, o := range s.Parent.Lists["syslog-server"] {
		if o != s && o.Leaf("address") == s.Leaf("address") && o.Leaf("protocol") == s.Leaf("protocol") && (num(o, "port") == port || (o.Leaf("port") == "" && port == fwconfig.SyslogPort)) {
			return []error{fail("there is a syslog server %s port %s/%d already", srv.Address, srv.Protocol, port)}
		}
	}
	return nil
}

var portNameRe = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,62}$`)

// The services with a rate limit of their own: the instance's leaf that
// switches it on, and the rate limit's name and description.
var serviceRateLimits = []struct{ service, leaf, name, description string }{
	{"dns", "dns-rate-limit", "dns server", "What comes in to the DNS server"},
	{"dhcp", "dhcp-rate-limit", "dhcp server", "What comes in to the DHCP server"},
	{"ntp", "ntp-rate-limit", "ntp server", "What comes in to the NTP server"},
}

// seedInstance gives a new virtual firewall its services' rate limits,
// switched on, and the rule that keeps the firewall's own traffic open
// (the output chain drops by default) until the user narrows it.
func seedInstance(c *Ctx, in *datastore.Node) error {
	for _, sv := range serviceRateLimits {
		set(in, sv.leaf, "true")
	}
	if err := ensureServiceRateLimits(c, in, nil); err != nil {
		return err
	}
	if len(in.Lists["rule"]) == 0 {
		r := in.AddEntry(in.S.Child("rule"), map[string]string{"id": strconv.FormatUint(nextRuleID(c), 10)})
		set(r, "chain", fwconfig.ChainOutput)
		set(r, "action", fwconfig.ActionAccept)
		set(r, "description", "allow all output")
	}
	return nil
}

// ensureServiceRateLimits makes the rate limit of each service the
// instance switches its rate limit on for (it was off in old, or there was
// no old), unless it has one: policing
// fwconfig.DefaultServiceRate Mbit/s of connections, named after the
// service, or with a number when that name is taken.
func ensureServiceRateLimits(c *Ctx, in, old *datastore.Node) error {
	s := in.S.Child("rate-limit")
	for _, sv := range serviceRateLimits {
		if !on(in, sv.leaf) || (old != nil && on(old, sv.leaf)) || serviceLimit(in, sv.service) != nil {
			continue
		}
		name := sv.name
		for k := 2; in.Entry("rate-limit", []string{name}) != nil; k++ {
			name = fmt.Sprintf("%s %d", sv.name, k)
		}
		l := in.AddEntry(s, map[string]string{"name": name})
		set(l, "description", sv.description)
		set(l, "service", sv.service)
		set(l, "rate", strconv.Itoa(fwconfig.DefaultServiceRate))
		set(l, "unit", fwconfig.RateUnitMBit)
		set(l, "per", fwconfig.RatePerSecond)
		set(l, "connections", "true")
	}
	return nil
}

// serviceLimit is the instance's rate limit of the service, or nil.
func serviceLimit(in *datastore.Node, service string) *datastore.Node {
	for _, l := range in.Lists["rate-limit"] {
		if l.Leaf("service") == service {
			return l
		}
	}
	return nil
}

// checkServiceLimits: a service's switch on needs its rate limit.
func checkServiceLimits(in *datastore.Node) []error {
	var errs []error
	for _, sv := range serviceRateLimits {
		if on(in, sv.leaf) && serviceLimit(in, sv.service) == nil {
			errs = append(errs, fail("%s: on, but the %s's rate limit is gone; switch it off first", sv.leaf, strings.ToUpper(sv.service)+" server"))
		}
	}
	return errs
}

// nextRuleID is an id above every rule's in the tree and before the edit.
func nextRuleID(c *Ctx) uint64 {
	var max uint64
	for _, t := range []*datastore.Tree{c.T, c.Before} {
		if t == nil {
			continue
		}
		for _, in := range t.Root.Lists["instance"] {
			for _, r := range in.Lists["rule"] {
				if id, _ := strconv.ParseUint(r.Leaf("id"), 10, 32); id > max {
					max = id
				}
			}
		}
	}
	return max + 1
}

// checkFolder: a folder's name is unique where it is, and its parent is a
// folder of its kind.
func checkFolder(c *Ctx, f *datastore.Node) []error {
	var errs []error
	for _, o := range c.T.Root.Lists["object-folder"] {
		if o != f && o.Leaf("kind") == f.Leaf("kind") && o.Leaf("name") == f.Leaf("name") && o.Leaf("parent") == f.Leaf("parent") {
			errs = append(errs, fail("name: there is a folder %s here already", f.Leaf("name")))
		}
	}
	if p := c.T.Root.Entry("object-folder", []string{f.Leaf("parent")}); p != nil && p.Leaf("kind") != f.Leaf("kind") {
		errs = append(errs, fail("parent: a folder of %s, not %s", p.Leaf("kind"), f.Leaf("kind")))
	}
	return errs
}

// checkItemFolder: an item is in a folder of its kind.
func checkItemFolder(c *Ctx, e *datastore.Node, kind string) []error {
	if f := c.T.Root.Entry("object-folder", []string{e.Leaf("folder")}); f != nil && f.Leaf("kind") != kind {
		return []error{fail("folder: a folder of %s, not %s", f.Leaf("kind"), kind)}
	}
	return nil
}
