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

// challengeTTL is the TTL of an ACME challenge's TXT record: short, as
// it lives for one validation.
const challengeTTL = 60

// TXTUpdater adds and removes single TXT values in a DNS update client's
// zone, for ACME's DNS-01 challenge. Unlike a client's records, a value
// is added to the name's RRset, not put in its place: two domains of one
// order (example.com and *.example.com) share a name, and both values are
// there while the CA validates.
type TXTUpdater struct {
	zone string // FQDN, lower case
	// edit adds (or removes) the TXT value at an FQDN in zone.
	edit func(ctx context.Context, name, value string, add bool) error
}

// NewTXTUpdater returns the updater of a certificate's DNS-01 settings.
// Env's Exchange, Resolve and Provider are used as a client's; the rest
// are not.
func NewTXTUpdater(d fwconfig.DNS01, env Env) (*TXTUpdater, error) {
	u := &TXTUpdater{zone: dns.Fqdn(strings.ToLower(d.Zone))}
	if d.Provider == "" || d.Provider == fwconfig.ProviderRFC2136 {
		server, err := fwconfig.DynDNSServer(d.Server)
		if err != nil {
			return nil, fmt.Errorf("server: %w", err)
		}
		var tsig *fwconfig.TSIG
		if d.TSIG != nil {
			t := *d.TSIG
			t.Name = dns.Fqdn(strings.ToLower(t.Name))
			tsig = &t
		}
		if env.Exchange == nil {
			env.Exchange = func(c *dns.Client, m *dns.Msg, addr string) (*dns.Msg, error) {
				r, _, err := c.Exchange(m, addr)
				return r, err
			}
		}
		if env.Resolve == nil {
			env.Resolve = func(ctx context.Context, host string) (netip.Addr, error) {
				addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
				if err != nil {
					return netip.Addr{}, err
				}
				return addrs[0], nil
			}
		}
		b := &rfc2136{server: server, zone: u.zone, tsig: tsig, exchange: env.Exchange, resolve: env.Resolve, now: time.Now}
		u.edit = b.editTXT
		return u, nil
	}
	p := env.Provider
	if p == nil {
		var err error
		if p, err = NewProvider(d.Provider, d.ProviderSettings); err != nil {
			return nil, err
		}
	}
	ad, ok := p.(txtProvider)
	if !ok {
		return nil, fmt.Errorf("provider %s can't add and delete single records", d.Provider)
	}
	u.edit = func(ctx context.Context, name, value string, add bool) error {
		recs := []libdns.Record{libdns.TXT{Name: libdns.RelativeName(name, u.zone), TTL: challengeTTL * time.Second, Text: value}}
		var err error
		if add {
			_, err = ad.AppendRecords(ctx, u.zone, recs)
		} else {
			_, err = ad.DeleteRecords(ctx, u.zone, recs)
		}
		if err != nil {
			return fmt.Errorf("TXT %s in %s: %w", name, u.zone, err)
		}
		return nil
	}
	return u, nil
}

// txtProvider is a libdns provider that adds and deletes single records.
type txtProvider interface {
	libdns.RecordAppender
	libdns.RecordDeleter
}

// Zone is the zone the updater writes in, an FQDN.
func (u *TXTUpdater) Zone() string { return u.zone }

// InZone says whether an FQDN is the zone or a name in it.
func (u *TXTUpdater) InZone(name string) bool {
	name = dns.Fqdn(strings.ToLower(name))
	return name == u.zone || strings.HasSuffix(name, "."+u.zone)
}

// Add adds value to the TXT RRset at name, an FQDN in the zone.
func (u *TXTUpdater) Add(ctx context.Context, name, value string) error {
	return u.change(ctx, name, value, true)
}

// Remove removes value from the TXT RRset at name.
func (u *TXTUpdater) Remove(ctx context.Context, name, value string) error {
	return u.change(ctx, name, value, false)
}

func (u *TXTUpdater) change(ctx context.Context, name, value string, add bool) error {
	name = dns.Fqdn(strings.ToLower(name))
	if !u.InZone(name) {
		return fmt.Errorf("%s is not in zone %s", name, u.zone)
	}
	return u.edit(ctx, name, value, add)
}

// editTXT adds or removes one TXT record with an UPDATE.
func (b *rfc2136) editTXT(ctx context.Context, name, value string, add bool) error {
	addr, err := b.serverAddr(ctx)
	if err != nil {
		return err
	}
	rr, err := rrOf(rrset{Name: name, Type: "TXT", TTL: challengeTTL, Data: value})
	if err != nil {
		return err
	}
	msg := new(dns.Msg)
	msg.SetUpdate(b.zone)
	if add {
		msg.Insert([]dns.RR{rr})
	} else {
		msg.Remove([]dns.RR{rr})
	}
	return b.send(msg, addr)
}
