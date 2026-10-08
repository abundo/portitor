// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package acme

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
)

// TXTWriter adds and removes single TXT values in one zone
// (dyndns.TXTUpdater).
type TXTWriter interface {
	Zone() string
	InZone(name string) bool
	Add(ctx context.Context, name, value string) error
	Remove(ctx context.Context, name, value string) error
}

// DNS-01's timeouts: how long one record change may take, and how long
// lego waits for the record to be seen at the zone's nameservers. A
// provider's API can be slow to publish.
const (
	dnsChangeTimeout = time.Minute
	dnsPropagation   = 5 * time.Minute
	dnsPollInterval  = 5 * time.Second
)

// dns01Provider answers DNS-01 challenges through a TXTWriter.
type dns01Provider struct {
	w TXTWriter
	// info is dns01.GetChallengeInfo (a fake in tests): the record's name
	// after any CNAMEs at _acme-challenge.<domain>, and its value.
	info func(domain, keyAuth string) dns01.ChallengeInfo
}

// NewDNS01 returns a DNS-01 provider that writes the TXT records with w.
// A CNAME at _acme-challenge.<domain> is followed, as lego's propagation
// check and the CA follow it, so the record may be put in another zone:
// w's, where the CNAME (chain) must end.
func NewDNS01(w TXTWriter) challenge.ProviderTimeout {
	return &dns01Provider{w: w, info: dns01.GetChallengeInfo}
}

// target is the name and value of a domain's TXT record.
func (p *dns01Provider) target(domain, keyAuth string) (string, string, error) {
	info := p.info(domain, keyAuth)
	name := strings.ToLower(info.EffectiveFQDN)
	if p.w.InZone(name) {
		return name, info.Value, nil
	}
	zone := strings.TrimSuffix(p.w.Zone(), ".")
	if strings.EqualFold(info.EffectiveFQDN, info.FQDN) {
		return "", "", fmt.Errorf("%s is not in zone %s: add a CNAME there to a name in %s", strings.TrimSuffix(info.FQDN, "."), zone, zone)
	}
	return "", "", fmt.Errorf("the CNAME at %s leads to %s, not in zone %s", strings.TrimSuffix(info.FQDN, "."), strings.TrimSuffix(name, "."), zone)
}

func (p *dns01Provider) Present(domain, _, keyAuth string) error {
	name, value, err := p.target(domain, keyAuth)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsChangeTimeout)
	defer cancel()
	return p.w.Add(ctx, name, value)
}

func (p *dns01Provider) CleanUp(domain, _, keyAuth string) error {
	name, value, err := p.target(domain, keyAuth)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsChangeTimeout)
	defer cancel()
	return p.w.Remove(ctx, name, value)
}

func (p *dns01Provider) Timeout() (time.Duration, time.Duration) {
	return dnsPropagation, dnsPollInterval
}
