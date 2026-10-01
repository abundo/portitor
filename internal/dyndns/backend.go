// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dyndns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/miekg/dns"

	"github.com/abundo/portitor/internal/fwconfig"
)

// rrset is an RRset to publish: Name is an FQDN, Data the one value.
type rrset struct {
	Name, Type string
	TTL        uint32
	Data       string
}

// backend reads and replaces RRsets where the zone is hosted.
type backend interface {
	// lookup returns the values of name's RRset of type typ: addresses in
	// canonical form, CNAME targets as lower-case FQDNs, TXT strings
	// joined. A missing name or RRset is no values, not an error.
	lookup(ctx context.Context, name, typ string) ([]string, error)
	// update replaces each RRset with its one value.
	update(ctx context.Context, sets []rrset) error
}

// resolveTTL is how long a nameserver's resolved address is used before
// its name is looked up again.
const resolveTTL = time.Minute

// rfc2136 queries the nameserver and sends it UPDATEs.
type rfc2136 struct {
	server   string // host:port; the host is an IP address or a name
	zone     string // FQDN
	tsig     *fwconfig.TSIG
	exchange func(c *dns.Client, m *dns.Msg, addr string) (*dns.Msg, error)
	resolve  func(ctx context.Context, host string) (netip.Addr, error)
	now      func() time.Time
	// resolved reports the address a name resolved to, for the status.
	resolved func(addr string)

	addr       string // ip:port last resolved
	resolvedAt time.Time
}

// serverAddr returns the nameserver as ip:port, resolving a name at most
// every resolveTTL.
func (b *rfc2136) serverAddr(ctx context.Context) (string, error) {
	host, port, err := net.SplitHostPort(b.server)
	if err != nil {
		return "", err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return b.server, nil
	}
	if b.addr != "" && b.now().Sub(b.resolvedAt) < resolveTTL && !b.now().Before(b.resolvedAt) {
		return b.addr, nil
	}
	a, err := b.resolve(ctx, host)
	if err != nil {
		b.addr = ""
		return "", fmt.Errorf("resolve nameserver %s: %w", host, err)
	}
	b.addr, b.resolvedAt = net.JoinHostPort(a.Unmap().String(), port), b.now()
	if b.resolved != nil {
		b.resolved(b.addr)
	}
	return b.addr, nil
}

func (b *rfc2136) lookup(ctx context.Context, name, typ string) ([]string, error) {
	addr, err := b.serverAddr(ctx)
	if err != nil {
		return nil, err
	}
	qtype := dns.StringToType[typ]
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = false
	resp, err := b.exchange(&dns.Client{Net: "udp", Timeout: timeout}, msg, addr)
	if err != nil {
		return nil, fmt.Errorf("DNS query %s %s: %w", name, typ, err)
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, nil
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query %s %s rejected: %s", name, typ, dns.RcodeToString[resp.Rcode])
	}
	var got []string
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype != qtype {
			continue
		}
		switch r := rr.(type) {
		case *dns.A:
			got = append(got, r.A.String())
		case *dns.AAAA:
			got = append(got, r.AAAA.String())
		case *dns.CNAME:
			got = append(got, strings.ToLower(r.Target))
		case *dns.TXT:
			// Concatenated character-strings.
			got = append(got, strings.Join(r.Txt, ""))
		}
	}
	return got, nil
}

func (b *rfc2136) update(ctx context.Context, sets []rrset) error {
	addr, err := b.serverAddr(ctx)
	if err != nil {
		return err
	}
	msg := new(dns.Msg)
	msg.SetUpdate(b.zone)
	for _, s := range sets {
		rr, err := rrOf(s)
		if err != nil {
			return err
		}
		// Classic dynamic update: delete the RRset, then insert the record.
		msg.RemoveRRset([]dns.RR{rr})
		msg.Insert([]dns.RR{rr})
	}
	client := &dns.Client{Net: "udp", Timeout: timeout}
	if t := b.tsig; t != nil {
		client.TsigSecret = map[string]string{t.Name: t.Secret}
		msg.SetTsig(t.Name, mapAlgorithm(t.Algorithm), 300, b.now().Unix())
	}
	resp, err := b.exchange(client, msg, addr)
	if err != nil {
		return fmt.Errorf("DNS update: %w", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS update rejected: %s", dns.RcodeToString[resp.Rcode])
	}
	return nil
}

func rrOf(s rrset) (dns.RR, error) {
	data := s.Data
	if s.Type == "TXT" {
		// Quote so spaces and special characters are valid presentation format.
		data = fmt.Sprintf("%q", data)
	}
	str := fmt.Sprintf("%s %d IN %s %s", s.Name, s.TTL, s.Type, data)
	rr, err := dns.NewRR(str)
	if err != nil {
		return nil, fmt.Errorf("invalid RR %q: %w", str, err)
	}
	return rr, nil
}

func mapAlgorithm(name string) string {
	switch strings.ToLower(name) {
	case "hmac-md5":
		return dns.HmacMD5
	case "hmac-sha1":
		return dns.HmacSHA1
	case "hmac-sha224":
		return dns.HmacSHA224
	case "hmac-sha384":
		return dns.HmacSHA384
	case "hmac-sha512":
		return dns.HmacSHA512
	default:
		return dns.HmacSHA256
	}
}

// Provider is a libdns provider that can list and replace records.
type Provider interface {
	libdns.RecordGetter
	libdns.RecordSetter
}

// listCacheTTL is how long a zone listing answers lookups: the records of
// one check are read with one API call.
const listCacheTTL = 10 * time.Second

// libdnsBackend keeps records at a DNS hosting provider through its API.
type libdnsBackend struct {
	zone string // FQDN
	p    Provider
	now  func() time.Time

	cache    []libdns.Record
	cachedAt time.Time
}

func (b *libdnsBackend) lookup(ctx context.Context, name, typ string) ([]string, error) {
	if b.cache == nil || b.now().Sub(b.cachedAt) > listCacheTTL || b.now().Before(b.cachedAt) {
		recs, err := b.p.GetRecords(ctx, b.zone)
		if err != nil {
			return nil, fmt.Errorf("list records of %s: %w", b.zone, err)
		}
		if recs == nil {
			recs = []libdns.Record{}
		}
		b.cache, b.cachedAt = recs, b.now()
	}
	var got []string
	for _, r := range b.cache {
		rr := r.RR()
		if !strings.EqualFold(rr.Type, typ) || !strings.EqualFold(dns.Fqdn(libdns.AbsoluteName(rr.Name, b.zone)), name) {
			continue
		}
		switch r := r.(type) {
		case libdns.Address:
			got = append(got, r.IP.Unmap().String())
		case libdns.CNAME:
			got = append(got, strings.ToLower(dns.Fqdn(r.Target)))
		case libdns.TXT:
			got = append(got, r.Text)
		default:
			got = append(got, rr.Data)
		}
	}
	return got, nil
}

func (b *libdnsBackend) update(ctx context.Context, sets []rrset) error {
	b.cache = nil // read again to verify
	recs := make([]libdns.Record, 0, len(sets))
	for _, s := range sets {
		name := libdns.RelativeName(s.Name, b.zone)
		ttl := time.Duration(s.TTL) * time.Second
		switch s.Type {
		case "A", "AAAA":
			ip, err := netip.ParseAddr(s.Data)
			if err != nil {
				return err
			}
			recs = append(recs, libdns.Address{Name: name, TTL: ttl, IP: ip})
		case "CNAME":
			recs = append(recs, libdns.CNAME{Name: name, TTL: ttl, Target: s.Data})
		case "TXT":
			recs = append(recs, libdns.TXT{Name: name, TTL: ttl, Text: s.Data})
		default:
			return fmt.Errorf("unsupported type %q", s.Type)
		}
	}
	// SetRecords replaces the RRset of each name and type it is given.
	if _, err := b.p.SetRecords(ctx, b.zone, recs); err != nil {
		return fmt.Errorf("update records of %s: %w", b.zone, err)
	}
	return nil
}
