// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package acme

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

// txtLog is a TXTWriter that logs what it is asked to do.
type txtLog struct {
	zone string
	log  []string
}

func (w *txtLog) Zone() string { return w.zone }
func (w *txtLog) InZone(name string) bool {
	name = dns.Fqdn(strings.ToLower(name))
	return name == w.zone || strings.HasSuffix(name, "."+w.zone)
}
func (w *txtLog) Add(_ context.Context, name, value string) error {
	w.log = append(w.log, "add "+name+" "+value)
	return nil
}
func (w *txtLog) Remove(_ context.Context, name, value string) error {
	w.log = append(w.log, "remove "+name+" "+value)
	return nil
}

// resolver serves CNAMEs for lego's lookups of _acme-challenge names, as
// the recursive nameserver it reads from resolv.conf would.
func resolver(t *testing.T, cnames map[string]string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(m)
		q := m.Question[0]
		if target, ok := cnames[strings.ToLower(q.Name)]; ok && (q.Qtype == dns.TypeCNAME || q.Qtype == dns.TypeTXT) {
			r.Answer = append(r.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: target})
		} else {
			r.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(r)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = srv.Shutdown()
		// lego's resolvers are a package variable: back to the host's.
		servers := []string{"google-public-dns-a.google.com:53"}
		if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cfg.Servers) > 0 {
			servers = cfg.Servers
		}
		_ = dns01.AddRecursiveNameservers(servers)(nil)
	})
	if err := dns01.AddRecursiveNameservers([]string{pc.LocalAddr().String()})(nil); err != nil {
		t.Fatal(err)
	}
}

// A CNAME at _acme-challenge.<domain> is followed, through a chain, to
// the DNS update client's zone; the record is written there, under the
// name lego's propagation check and the CA look at.
func TestDNS01CNAME(t *testing.T) {
	resolver(t, map[string]string{
		"_acme-challenge.www.example.com.":  "www.acme.example.net.",
		"_acme-challenge.mail.example.com.": "mail.example.org.",
		"mail.example.org.":                 "Mail.Acme.Example.net.",
		"_acme-challenge.bad.example.com.":  "bad.example.org.",
	})
	w := &txtLog{zone: "acme.example.net."}
	p := NewDNS01(w)
	keyAuth := "token.thumbprint"
	value := dns01.GetChallengeInfo("www.example.com", keyAuth).Value

	for domain, want := range map[string]string{
		"www.example.com":       "www.acme.example.net.",
		"mail.example.com":      "mail.acme.example.net.",
		"host.acme.example.net": "_acme-challenge.host.acme.example.net.", // in the zone, no CNAME
	} {
		w.log = nil
		if err := p.Present(domain, "token", keyAuth); err != nil {
			t.Errorf("%s: %v", domain, err)
			continue
		}
		if err := p.CleanUp(domain, "token", keyAuth); err != nil {
			t.Errorf("%s: %v", domain, err)
		}
		if exp := []string{"add " + want + " " + value, "remove " + want + " " + value}; !slices.Equal(w.log, exp) {
			t.Errorf("%s: %q, want %q", domain, w.log, exp)
		}
	}

	w.log = nil
	for domain, msg := range map[string]string{
		"bad.example.com":   "the CNAME at _acme-challenge.bad.example.com leads to bad.example.org, not in zone acme.example.net",
		"plain.example.com": "_acme-challenge.plain.example.com is not in zone acme.example.net: add a CNAME there to a name in acme.example.net",
	} {
		if err := p.Present(domain, "token", keyAuth); err == nil || err.Error() != msg {
			t.Errorf("%s: %v, want %q", domain, err, msg)
		}
	}
	if len(w.log) != 0 {
		t.Errorf("written outside the zone: %q", w.log)
	}
}
