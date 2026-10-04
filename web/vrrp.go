// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// VRRP virtual routers, per instance, on an interface by name (renaming
// one rewrites them, deleting one in use is refused, web/ifzones.go).

// vrrpAddrs reads a list of virtual addresses: canonical, without
// duplicates; a prefix length typed with one is dropped.
func vrrpAddrs(what string, list models.StringList) (models.StringList, error) {
	out := models.StringList{}
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			s = p.Addr().String()
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, bad(fmt.Sprintf("%s: %q is not an address", what, s))
		}
		if !slices.Contains(out, a.String()) {
			out = append(out, a.String())
		}
	}
	return out, nil
}

// vrrpParent is the interface (or link end) name of the instance as the
// document will hold it, for the checks against its kind and networks;
// nil when there is none.
func vrrpParent(tx *gorm.DB, instanceID uint, name string) (*fwconfig.Interface, error) {
	var ifc models.Interface
	err := tx.Where("instance_id = ? AND name = ?", instanceID, name).First(&ifc).Error
	if err == nil {
		return &fwconfig.Interface{Name: ifc.Name, Kind: ifc.Kind, Addresses: ifc.Addresses}, nil
	}
	var links []models.Link
	if err := tx.Where("instance_a_id = ? OR instance_b_id = ?", instanceID, instanceID).Find(&links).Error; err != nil {
		return nil, err
	}
	for _, l := range links {
		switch {
		case l.InstanceAID == instanceID && l.InterfaceA == name:
			return &fwconfig.Interface{Name: name, Kind: fwconfig.KindLink, Addresses: l.AddressesA}, nil
		case l.InstanceBID == instanceID && l.InterfaceB == name:
			return &fwconfig.Interface{Name: name, Kind: fwconfig.KindLink, Addresses: l.AddressesB}, nil
		}
	}
	return nil, nil
}

func prepareVrrpRouter(tx *gorm.DB, r, old *models.VrrpRouter) error {
	if old != nil {
		r.InstanceID = old.InstanceID
	}
	if err := instanceExists(tx, r.InstanceID); err != nil {
		return err
	}
	r.Interface = strings.TrimSpace(r.Interface)
	parent, err := vrrpParent(tx, r.InstanceID, r.Interface)
	if err != nil {
		return err
	}
	if parent == nil {
		return bad(fmt.Sprintf("%q is not an interface of this virtual firewall", r.Interface))
	}
	if r.Version == 0 {
		r.Version = 3
	}
	if r.Priority == 0 {
		r.Priority = 100
	}
	if r.AdvertisementInterval == 0 {
		r.AdvertisementInterval = 1000
	}
	if r.Ipv4, err = vrrpAddrs("IPv4 addresses", r.Ipv4); err != nil {
		return err
	}
	if r.Ipv6, err = vrrpAddrs("IPv6 addresses", r.Ipv6); err != nil {
		return err
	}
	r.Description = strings.TrimSpace(r.Description)
	if err := problems(fwconfig.CheckVRRP(r.Router(), parent)); err != nil {
		return err
	}
	var others []models.VrrpRouter
	if err := tx.Where("instance_id = ? AND id <> ?", r.InstanceID, r.ID).Find(&others).Error; err != nil {
		return err
	}
	for _, o := range others {
		if o.Interface == r.Interface && o.Vrid == r.Vrid {
			return bad(fmt.Sprintf("%s already has virtual router %d", r.Interface, r.Vrid))
		}
		for _, a := range slices.Concat(r.Ipv4, r.Ipv6) {
			if slices.Contains(o.Ipv4, a) || slices.Contains(o.Ipv6, a) {
				return bad(fmt.Sprintf("%s is also an address of virtual router %d on %s", a, o.Vrid, o.Interface))
			}
		}
	}
	return nil
}

// vrrpIfaceUsers lists the virtual routers on interface name.
func vrrpIfaceUsers(tx *gorm.DB, instanceID uint, name string) []string {
	var ids []int
	tx.Model(&models.VrrpRouter{}).Where("instance_id = ? AND interface = ?", instanceID, name).Order("vrid").Pluck("vrid", &ids)
	var users []string
	for _, id := range ids {
		users = append(users, fmt.Sprintf("VRRP virtual router %d", id))
	}
	return users
}
