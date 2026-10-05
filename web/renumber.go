// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/netip"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// renumberPrefixes moves the DHCP and router advertisement settings with an
// interface's address. DHCP and RA are set per prefix (ipam_prefixes), so
// changing 2001:db8:1::1/64 to 2001:db8:2::1/64 would otherwise leave them on
// a prefix no interface has an address in, which the agent refuses, and
// nothing on the new one. Per IP version, when exactly one prefix leaves the
// interface and one comes in, no other interface of the instance has an
// address in the old one, and the new one has no DHCP or RA yet, the settings
// move: the DHCP range keeps its host part when the prefix length is the same
// and is emptied otherwise.
func renumberPrefixes(tx *gorm.DB, old, i *models.Interface) error {
	if old == nil || old.InstanceID != i.InstanceID {
		return nil
	}
	gone, added := prefixDiff(old.Addresses, i.Addresses), prefixDiff(i.Addresses, old.Addresses)
	for _, v4 := range []bool{true, false} {
		from, to := ofVersion(gone, v4), ofVersion(added, v4)
		if len(from) != 1 || len(to) != 1 {
			continue
		}
		if err := movePrefixSettings(tx, i, from[0], to[0]); err != nil {
			return err
		}
	}
	return nil
}

func movePrefixSettings(tx *gorm.DB, i *models.Interface, from, to netip.Prefix) error {
	var src models.IpamPrefix
	err := tx.Where("instance_id = ? AND prefix = ?", i.InstanceID, from.String()).Take(&src).Error
	if err == gorm.ErrRecordNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if !src.DhcpEnabled && !src.RaEnabled {
		return nil
	}
	var others []models.Interface
	if err := tx.Where("instance_id = ? AND id <> ?", i.InstanceID, i.ID).Find(&others).Error; err != nil {
		return err
	}
	for _, o := range others {
		if p := prefixDiff(o.Addresses, nil); containsPrefix(p, from) {
			return nil // still served there
		}
	}
	var dst models.IpamPrefix
	err = tx.Where("instance_id = ? AND prefix = ?", i.InstanceID, to.String()).Take(&dst).Error
	switch {
	case err == gorm.ErrRecordNotFound:
		dst = models.IpamPrefix{InstanceID: i.InstanceID, Prefix: to.String()}
	case err != nil:
		return err
	case dst.DhcpEnabled || dst.RaEnabled:
		return nil // the new prefix has its own settings
	}
	dst.DhcpEnabled, dst.RaEnabled = src.DhcpEnabled, src.RaEnabled
	dst.RaSlaac = src.RaSlaac && to.Bits() == 64
	dst.DhcpDnsServers = src.DhcpDnsServers
	dst.DhcpRangeStart, dst.DhcpRangeEnd, dst.DhcpGateway = "", "", ""
	if from.Bits() == to.Bits() {
		dst.DhcpRangeStart = rebase(src.DhcpRangeStart, to)
		dst.DhcpRangeEnd = rebase(src.DhcpRangeEnd, to)
		dst.DhcpGateway = rebase(src.DhcpGateway, to)
	}
	if dst.DhcpEnabled && (dst.DhcpRangeStart == "") != (dst.DhcpRangeEnd == "") {
		dst.DhcpRangeStart, dst.DhcpRangeEnd = "", ""
	}
	if err := tx.Save(&dst).Error; err != nil {
		return err
	}
	return tx.Model(&src).Updates(map[string]any{"dhcp_enabled": false, "ra_enabled": false, "ra_slaac": false}).Error
}

// prefixDiff is the prefixes of the addresses in a that none in b is in.
func prefixDiff(a, b []string) []netip.Prefix {
	in := func(list []string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range list {
			if fwconfig.IsDelegated(s) {
				continue
			}
			if p, err := netip.ParsePrefix(s); err == nil && !containsPrefix(out, p.Masked()) {
				out = append(out, p.Masked())
			}
		}
		return out
	}
	other := in(b)
	var out []netip.Prefix
	for _, p := range in(a) {
		if !containsPrefix(other, p) {
			out = append(out, p)
		}
	}
	return out
}

func containsPrefix(list []netip.Prefix, p netip.Prefix) bool {
	for _, q := range list {
		if q == p {
			return true
		}
	}
	return false
}

func ofVersion(list []netip.Prefix, v4 bool) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range list {
		if p.Addr().Is4() == v4 {
			out = append(out, p)
		}
	}
	return out
}

// rebase puts the host part of address s into prefix p ("" stays "").
func rebase(s string, p netip.Prefix) string {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Is4() != p.Addr().Is4() {
		return ""
	}
	host, net := a.AsSlice(), p.Addr().AsSlice()
	for b := 0; b < p.Bits(); b++ {
		mask := byte(0x80 >> (b % 8))
		host[b/8] = host[b/8]&^mask | net[b/8]&mask
	}
	out, _ := netip.AddrFromSlice(host)
	return out.String()
}
