// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/netobj"
	"github.com/abundo/portitor/models"
)

// Named hosts and prefixes. Other rows refer to them by name inside their
// address lists; renaming an object rewrites those references, and an
// object in use cannot be deleted.

func prepareAddressObject(tx *gorm.DB, o, old *models.AddressObject) error {
	o.Name = strings.TrimSpace(o.Name)
	if !netobj.ValidName(o.Name) {
		return bad("name: letters, digits, _ . -, starting with a letter, at most 63 characters (not \"default\" or \"any\")")
	}
	if err := itemFolder(tx, &o.FolderID, models.ObjectFolderHosts); err != nil {
		return err
	}
	o.Addresses = cleanList(o.Addresses)
	if len(o.Addresses) == 0 {
		return bad("at least one address or prefix")
	}
	for i, a := range o.Addresses {
		p, err := fwconfig.ParseAddrOrPrefix(a)
		if err != nil {
			return bad(fmt.Sprintf("%q is not an address or CIDR", a))
		}
		if p.IsSingleIP() {
			o.Addresses[i] = p.Addr().String()
		} else {
			o.Addresses[i] = p.String()
		}
	}
	if old != nil && old.Name != o.Name {
		return eachObjectRef(tx, func(_ string, entry *string) bool {
			if *entry == old.Name {
				*entry = o.Name
				return true
			}
			return false
		})
	}
	return nil
}

func deleteAddressObject(tx *gorm.DB, o *models.AddressObject) error {
	var users []string
	err := eachObjectRef(tx, func(where string, entry *string) bool {
		if *entry == o.Name && (len(users) == 0 || users[len(users)-1] != where) {
			users = append(users, where)
		}
		return false
	})
	if err != nil {
		return err
	}
	if len(users) > 0 {
		if len(users) > 5 {
			users = append(users[:5], "...")
		}
		return bad(fmt.Sprintf("%s is used by %s", o.Name, strings.Join(users, ", ")))
	}
	return nil
}

// eachObjectRef calls visit for every entry that can hold an object name.
// Rows where visit changed an entry are saved.
func eachObjectRef(tx *gorm.DB, visit func(where string, entry *string) bool) error {
	list := func(where string, l models.StringList) bool {
		changed := false
		for i := range l {
			if visit(where, &l[i]) {
				changed = true
			}
		}
		return changed
	}
	save := func(model any, id uint, cols map[string]any) error {
		return tx.Model(model).Where("id = ?", id).UpdateColumns(cols).Error
	}
	instName := map[uint]string{}

	var instances []models.Instance
	if err := tx.Find(&instances).Error; err != nil {
		return err
	}
	for _, in := range instances {
		instName[in.ID] = in.Name
		where := "virtual firewall " + in.Name + " DNS"
		a, b := list(where, in.DnsForwarders), list(where, in.DnsAllowRecursion)
		if a || b {
			if err := save(&models.Instance{}, in.ID, map[string]any{"dns_forwarders": in.DnsForwarders, "dns_allow_recursion": in.DnsAllowRecursion}); err != nil {
				return err
			}
		}
	}
	var rules []models.Rule
	if err := tx.Order("position, id").Find(&rules).Error; err != nil {
		return err
	}
	names := ruleNamer{}
	for _, r := range rules {
		where := fmt.Sprintf("%s in %s", names.rule(r), instName[r.InstanceID])
		a, b := list(where, r.SrcAddrs), list(where, r.DstAddrs)
		if a || b {
			if err := save(&models.Rule{}, r.ID, map[string]any{"src_addrs": r.SrcAddrs, "dst_addrs": r.DstAddrs}); err != nil {
				return err
			}
		}
	}
	var nat []models.NatRule
	if err := tx.Order("position, id").Find(&nat).Error; err != nil {
		return err
	}
	for _, n := range nat {
		where := fmt.Sprintf("%s in %s", names.nat(n), instName[n.InstanceID])
		a, b, c := list(where, n.SrcAddrs), list(where, n.DstAddrs), visit(where, &n.ToAddr)
		if a || b || c {
			if err := save(&models.NatRule{}, n.ID, map[string]any{"src_addrs": n.SrcAddrs, "dst_addrs": n.DstAddrs, "to_addr": n.ToAddr}); err != nil {
				return err
			}
		}
	}
	var routes []models.Route
	if err := tx.Find(&routes).Error; err != nil {
		return err
	}
	for _, r := range routes {
		where := fmt.Sprintf("a route in %s (%s)", instName[r.InstanceID], r.Destination)
		a, b := visit(where, &r.Destination), visit(where, &r.Gateway)
		if a || b {
			if err := save(&models.Route{}, r.ID, map[string]any{"destination": r.Destination, "gateway": r.Gateway}); err != nil {
				return err
			}
		}
	}
	var peers []models.WgPeer
	if err := tx.Find(&peers).Error; err != nil {
		return err
	}
	for _, p := range peers {
		a, b := list("WireGuard peer "+p.Name, p.AllowedIPs), list("WireGuard peer "+p.Name, p.Networks)
		if a || b {
			if err := save(&models.WgPeer{}, p.ID, map[string]any{"allowed_ips": p.AllowedIPs, "networks": p.Networks}); err != nil {
				return err
			}
		}
	}
	var prefixes []models.IpamPrefix
	if err := tx.Find(&prefixes).Error; err != nil {
		return err
	}
	for _, p := range prefixes {
		if list(fmt.Sprintf("prefix %s in %s", p.Prefix, instName[p.InstanceID]), p.DhcpDnsServers) {
			if err := save(&models.IpamPrefix{}, p.ID, map[string]any{"dhcp_dns_servers": p.DhcpDnsServers}); err != nil {
				return err
			}
		}
	}
	return nil
}

// ruleNamer names rules the way the Rules page numbers them, per instance
// and chain in list order with comment and group rows left out ("forward rule 2"),
// and NAT rules per instance in list order ("NAT rule 3"); a description
// is added in parentheses. Rules must be named in list order (position, id).
type ruleNamer map[string]int

func (n ruleNamer) rule(r models.Rule) string {
	if r.IsNote() {
		return r.Kind
	}
	return n.next(fmt.Sprintf("%d %s", r.InstanceID, r.Chain), r.Chain+" rule", r.Description)
}

func (n ruleNamer) nat(r models.NatRule) string {
	return n.next(fmt.Sprintf("%d nat", r.InstanceID), "NAT rule", r.Description)
}

func (n ruleNamer) next(key, kind, desc string) string {
	n[key]++
	s := fmt.Sprintf("%s %d", kind, n[key])
	if desc != "" {
		s += " (" + desc + ")"
	}
	return s
}

// Address entry kinds for checkEntries.
const (
	entryAny  = iota // address or CIDR
	entryCIDR        // CIDR
	entryHost        // single address
	entryRule        // address, CIDR or IP list ("@name")
)

// checkEntries checks an address list where names of hosts/prefixes may
// stand in for literals. The builder expands the names at deploy time.
func checkEntries(tx *gorm.DB, field string, list models.StringList, kind int) error {
	for _, s := range list {
		if name, ok := fwconfig.IPListName(s); ok {
			if kind != entryRule {
				return bad(fmt.Sprintf("%s: IP lists (%s) can only be used in firewall rules", field, s))
			}
			if err := checkIPListRef(tx, field, name); err != nil {
				return err
			}
			continue
		}
		if netobj.IsName(s) {
			if err := checkObjectName(tx, field, s, kind == entryHost); err != nil {
				return err
			}
			continue
		}
		var err error
		example := "an address or CIDR"
		switch kind {
		case entryAny, entryRule:
			_, err = fwconfig.ParseAddrOrPrefix(s)
		case entryCIDR:
			_, err = fwconfig.ParseAddrOrPrefix(s)
			if err == nil && !strings.Contains(s, "/") {
				err = fmt.Errorf("no prefix length")
			}
			example = "a CIDR (e.g. 192.168.1.0/24)"
		case entryHost:
			_, err = fwconfig.ParseAddrOrPrefix(s)
			if err == nil && strings.Contains(s, "/") {
				err = fmt.Errorf("prefix")
			}
			example = "an IP address"
		}
		if err != nil {
			return bad(fmt.Sprintf("%s: %q is not %s, or the name of a host/prefix", field, s, example))
		}
	}
	return nil
}

// checkHost checks one entry that must be a host: an address, or a named
// host with at most one address per IP version.
func checkHost(tx *gorm.DB, field, s string) error {
	if !netobj.IsName(s) {
		return checkEntries(tx, field, models.StringList{s}, entryHost)
	}
	if err := checkObjectName(tx, field, s, true); err != nil {
		return err
	}
	var o models.AddressObject
	tx.Where("name = ?", s).First(&o)
	if _, err := netobj.New([]models.AddressObject{o}).Host(s); err != nil {
		return bad(field + ": " + err.Error())
	}
	return nil
}

func checkObjectName(tx *gorm.DB, field, name string, hostOnly bool) error {
	var o models.AddressObject
	if tx.Where("name = ?", name).First(&o).Error != nil {
		return bad(fmt.Sprintf("%s: no host/prefix named %q", field, name))
	}
	if hostOnly {
		if _, err := netobj.New([]models.AddressObject{o}).Hosts([]string{name}); err != nil {
			return bad(field + ": " + err.Error())
		}
	}
	return nil
}
