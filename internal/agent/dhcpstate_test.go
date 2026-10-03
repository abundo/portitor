// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

func savedLease4(t *testing.T, obtained time.Time) savedLease {
	t.Helper()
	ack, err := dhcpv4.New(
		dhcpv4.WithMessageType(dhcpv4.MessageTypeAck),
		dhcpv4.WithYourIP(net.ParseIP("192.0.2.10")),
		dhcpv4.WithNetmask(net.CIDRMask(24, 32)),
		dhcpv4.WithServerIP(net.ParseIP("192.0.2.1")),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.0.2.1"))),
		dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(time.Hour)),
		dhcpv4.WithDNS(net.ParseIP("192.0.2.53")),
	)
	if err != nil {
		t.Fatal(err)
	}
	return savedLease{Offer: ack.ToBytes(), ACK: ack.ToBytes(), Obtained: obtained}
}

// A saved DHCPv4 lease gives the first apply its DNS servers; the first
// Reconcile drops the ones no client takes, and an expired one is dropped
// at once.
func TestDHCPRestore(t *testing.T) {
	dir := t.TempDir()
	saveLease(dir, leaseID{"main", "ens18"}, savedLease4(t, time.Now()))
	saveLease(dir, leaseID{"main", "ens19"}, savedLease4(t, time.Now().Add(-2*time.Hour)))

	m := newDHCPManager(nil, false, dir, nil)
	got := m.DNSServers()
	if want := []string{"192.0.2.53"}; !slices.Equal(got["main"]["ens18"], want) || len(got["main"]) != 1 {
		t.Fatalf("DNSServers = %v, want ens18 %v only", got, want)
	}
	if _, err := os.Stat(leasePath(dir, leaseID{"main", "ens19"})); !os.IsNotExist(err) {
		t.Errorf("expired lease kept: %v", err)
	}

	m.Reconcile(nil)
	if got := m.DNSServers(); len(got) != 0 {
		t.Errorf("DNSServers after Reconcile = %v", got)
	}
	if _, err := os.Stat(leasePath(dir, leaseID{"main", "ens18"})); !os.IsNotExist(err) {
		t.Errorf("unused lease kept: %v", err)
	}
}

// A saved DHCPv6 lease gives the first apply its delegated prefix.
func TestDHCP6Restore(t *testing.T) {
	dir := t.TempDir()
	_, pd, _ := net.ParseCIDR("2001:db8:aa00::/56")
	r := reply6(t, &dhcpv6.OptIAPD{T1: time.Hour, Options: dhcpv6.PDOptions{Options: dhcpv6.Options{
		&dhcpv6.OptIAPrefix{Prefix: pd, PreferredLifetime: 2 * time.Hour, ValidLifetime: 3 * time.Hour},
	}}})
	saveLease(dir, leaseID{"main", "ens18"}, savedLease{Reply: r.ToBytes(), Obtained: time.Now()})

	m := newDHCP6Manager(nil, false, dir, nil)
	if got, want := m.Prefixes()["main"]["ens18"], netip.MustParsePrefix("2001:db8:aa00::/56"); got != want {
		t.Fatalf("Prefixes = %v, want %v", m.Prefixes(), want)
	}
	m.Reconcile(nil)
	if got := m.Prefixes(); len(got) != 0 {
		t.Errorf("Prefixes after Reconcile = %v", got)
	}
}
