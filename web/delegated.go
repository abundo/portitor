// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// Addresses relative to a delegated prefix ("<wan0>:2000::1/64") name the
// interface whose DHCPv6 client gets the prefix. Renaming that interface
// rewrites them; deleting it, moving it to another instance or turning
// its prefix delegation off is refused while they use it.

// prepareDHCPv6 checks the DHCPv6 client settings of i and the
// interfaces its delegated addresses name.
func prepareDHCPv6(tx *gorm.DB, i, old *models.Interface) error {
	if i.Dhcpv6 && (i.Kind == fwconfig.KindWireGuard || i.Kind == fwconfig.KindLink) {
		return bad(fmt.Sprintf("%s interfaces have no DHCPv6 client", i.Kind))
	}
	if i.Dhcpv6 && !i.Ipv6AcceptRA {
		return bad("the DHCPv6 client needs router advertisements accepted: the default route comes from them")
	}
	if !i.Dhcpv6 {
		i.Dhcpv6Pd = false
	}
	if !i.Dhcpv6Pd {
		i.Dhcpv6PdLength = 0
	}
	if i.Dhcpv6PdLength != 0 && (i.Dhcpv6PdLength < 32 || i.Dhcpv6PdLength > 64) {
		return bad("delegated prefix length must be 32-64, or empty to let the server choose")
	}
	for _, a := range i.Addresses {
		d, err := fwconfig.ParseDelegated(a)
		if err != nil {
			continue
		}
		if d.Interface == i.Name {
			if !i.Dhcpv6Pd {
				return bad(fmt.Sprintf("addresses: %s needs prefix delegation on this interface", a))
			}
			continue
		}
		var n int64
		if err := tx.Model(&models.Interface{}).Where("instance_id = ? AND name = ? AND dhcpv6_pd", i.InstanceID, d.Interface).Count(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			return bad(fmt.Sprintf("addresses: %s: %s is not an interface of this instance with DHCPv6 prefix delegation", a, d.Interface))
		}
	}
	if old == nil || !old.Dhcpv6Pd {
		return nil
	}
	switch {
	case old.InstanceID != i.InstanceID:
		return refuseDelegatedUsers(tx, old, "move to another instance")
	case !i.Dhcpv6Pd:
		return refuseDelegatedUsers(tx, old, "stop asking for a delegated prefix")
	case old.Name != i.Name:
		return renameDelegated(tx, old, i.Name)
	}
	return nil
}

// delegatedUsers are the other interfaces of i's instance with an address
// in the prefix delegated to i.
func delegatedUsers(tx *gorm.DB, i *models.Interface) ([]models.Interface, error) {
	var others []models.Interface
	if err := tx.Where("instance_id = ? AND id <> ?", i.InstanceID, i.ID).Order("name").Find(&others).Error; err != nil {
		return nil, err
	}
	var out []models.Interface
	for _, o := range others {
		for _, a := range o.Addresses {
			if d, err := fwconfig.ParseDelegated(a); err == nil && d.Interface == i.Name {
				out = append(out, o)
				break
			}
		}
	}
	return out, nil
}

func refuseDelegatedUsers(tx *gorm.DB, i *models.Interface, what string) error {
	users, err := delegatedUsers(tx, i)
	if err != nil || len(users) == 0 {
		return err
	}
	var names []string
	for _, u := range users {
		names = append(names, u.Name)
	}
	return bad(fmt.Sprintf("%s cannot %s while %s have addresses in its delegated prefix", i.Name, what, strings.Join(names, ", ")))
}

// renameDelegated rewrites the delegated addresses that name old to name.
func renameDelegated(tx *gorm.DB, old *models.Interface, name string) error {
	users, err := delegatedUsers(tx, old)
	if err != nil {
		return err
	}
	for _, u := range users {
		addrs := models.StringList{}
		for _, a := range u.Addresses {
			if d, err := fwconfig.ParseDelegated(a); err == nil && d.Interface == old.Name {
				d.Interface = name
				a = d.String()
			}
			addrs = append(addrs, a)
		}
		if err := tx.Model(&models.Interface{}).Where("id = ?", u.ID).Update("addresses", addrs).Error; err != nil {
			return err
		}
	}
	return nil
}
