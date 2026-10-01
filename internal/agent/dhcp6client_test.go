// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

func reply6(t *testing.T, opts ...dhcpv6.Option) *dhcpv6.Message {
	t.Helper()
	m, err := dhcpv6.NewMessage()
	if err != nil {
		t.Fatal(err)
	}
	m.MessageType = dhcpv6.MessageTypeReply
	m.AddOption(dhcpv6.OptServerID(&dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}}))
	for _, o := range opts {
		m.AddOption(o)
	}
	return m
}

func TestParseReply6(t *testing.T) {
	_, pd, _ := net.ParseCIDR("2001:db8:aa00::/48")
	r := reply6(t,
		&dhcpv6.OptIANA{T1: time.Hour, T2: 2 * time.Hour, Options: dhcpv6.IdentityOptions{Options: dhcpv6.Options{
			&dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP("2001:db8:1::5"), PreferredLifetime: 3 * time.Hour, ValidLifetime: 4 * time.Hour},
		}}},
		&dhcpv6.OptIAPD{Options: dhcpv6.PDOptions{Options: dhcpv6.Options{
			&dhcpv6.OptIAPrefix{Prefix: pd, PreferredLifetime: 2 * time.Hour, ValidLifetime: 3 * time.Hour},
		}}},
		dhcpv6.OptDNS(net.ParseIP("2001:db8::53")),
	)
	now := time.Unix(1_800_000_000, 0)
	l, err := parseReply6(r, now)
	if err != nil {
		t.Fatal(err)
	}
	if l.addr.String() != "2001:db8:1::5" || l.pd.String() != "2001:db8:aa00::/48" {
		t.Errorf("addr %s, pd %s", l.addr, l.pd)
	}
	// T1 is the IA_NA's; the IA_PD has none.
	if l.renew != time.Hour || !l.expires.Equal(now.Add(3*time.Hour)) {
		t.Errorf("renew %s, expires %s", l.renew, l.expires)
	}
	if len(l.dns) != 1 || l.dns[0] != "2001:db8::53" {
		t.Errorf("dns %v", l.dns)
	}
	if lft(l.addrValid) != "14400" || lft(infinite) != "forever" {
		t.Errorf("lft %s", lft(l.addrValid))
	}
}

func TestParseReply6Refused(t *testing.T) {
	if _, err := parseReply6(reply6(t, &dhcpv6.OptStatusCode{StatusCode: iana.StatusNoAddrsAvail}), time.Now()); err == nil {
		t.Error("status NoAddrsAvail accepted")
	}
	if _, err := parseReply6(reply6(t), time.Now()); err == nil {
		t.Error("reply without address or prefix accepted")
	}
}

func TestPortUsers(t *testing.T) {
	ss := `UNCONN 0 0 [fe80::1]%ens18:546 [::]:* users:(("systemd-network",pid=412,fd=21))` + "\n" +
		`UNCONN 0 0 [fe80::2]%ens19:546 [::]:* users:(("systemd-network",pid=412,fd=22),("dhclient",pid=9,fd=3))`
	if got := portUsers(ss); len(got) != 2 || got[0] != "systemd-network" || got[1] != "dhclient" {
		t.Errorf("portUsers = %v", got)
	}
}
