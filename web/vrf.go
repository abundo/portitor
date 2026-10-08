// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/netip"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// VRFs (Routing → VRF) belong to an instance. Interfaces are put in one by
// name (interfaces.vrf), which a rename rewrites; routes by id. A VRF in use
// can't be deleted. Its name is that of its Linux device, so it may not be
// an interface's, a link end's or an interface zone's of the instance. Its
// L3VNI (evpn_*, fwconfig.VRFEVPN) names its underlay interface, which a
// rename rewrites (renameIfaceRefs) and which can't be deleted.

func vrfExists(tx *gorm.DB, instanceID uint, name string) bool {
	var n int64
	tx.Model(&models.Vrf{}).Where("instance_id = ? AND name = ?", instanceID, name).Count(&n)
	return n > 0
}

func prepareVrf(tx *gorm.DB, v, old *models.Vrf) error {
	if err := instanceExists(tx, v.InstanceID); err != nil {
		return err
	}
	if old != nil && old.InstanceID != v.InstanceID {
		return bad("a VRF cannot move to another virtual firewall")
	}
	v.Name = strings.TrimSpace(v.Name)
	if !fwconfig.ValidIfname(v.Name) || v.Name == "lo" {
		return bad("name: a Linux interface name (at most 15 characters, no spaces)")
	}
	if strings.HasPrefix(v.Name, fwconfig.IFBPrefix) || strings.HasPrefix(v.Name, fwconfig.NAT64DevicePrefix) ||
		strings.HasPrefix(v.Name, "vrrp4-") || strings.HasPrefix(v.Name, "vrrp6-") || fwconfig.IsL3VNIName(v.Name) {
		return bad("name: that prefix is for the firewall's own devices")
	}
	v.Description = strings.TrimSpace(v.Description)
	if !fwconfig.ValidName(v.Description) && v.Description != "" {
		return bad("description: no control characters")
	}
	if msg := fwconfig.CheckVRFTable(v.RouteTable); msg != "" {
		return bad("table: " + msg)
	}
	names, err := ifaceNames(tx, v.InstanceID)
	if err != nil {
		return err
	}
	if names[v.Name] {
		return bad(fmt.Sprintf("name: %s is an interface of this virtual firewall", v.Name))
	}
	if ifaceZoneExists(tx, v.InstanceID, v.Name) {
		return bad(fmt.Sprintf("name: an interface zone is named %s", v.Name))
	}
	var others []models.Vrf
	if err := tx.Where("instance_id = ? AND id <> ?", v.InstanceID, v.ID).Find(&others).Error; err != nil {
		return err
	}
	if err := prepareVrfEVPN(tx, v, names, others); err != nil {
		return err
	}
	for _, o := range others {
		if o.Name == v.Name {
			return bad(fmt.Sprintf("name: there is a VRF %s already", v.Name))
		}
		if o.RouteTable == v.RouteTable {
			return bad(fmt.Sprintf("table: %d is VRF %s's", v.RouteTable, o.Name))
		}
	}
	if old != nil && old.Name != v.Name {
		return tx.Model(&models.Interface{}).Where("instance_id = ? AND vrf = ?", v.InstanceID, old.Name).UpdateColumn("vrf", v.Name).Error
	}
	return nil
}

// prepareVrfEVPN checks a VRF's L3VNI, or clears its settings when it has
// none (VNI 0).
func prepareVrfEVPN(tx *gorm.DB, v *models.Vrf, names map[string]bool, others []models.Vrf) error {
	if v.EvpnVni == 0 {
		v.EvpnLocal, v.EvpnDevice, v.EvpnPort, v.EvpnRd = "", "", 0, ""
		v.EvpnImportRts, v.EvpnExportRts = models.StringList{}, models.StringList{}
		return nil
	}
	v.EvpnLocal, v.EvpnDevice, v.EvpnRd = strings.TrimSpace(v.EvpnLocal), strings.TrimSpace(v.EvpnDevice), strings.TrimSpace(v.EvpnRd)
	if a, err := netip.ParseAddr(v.EvpnLocal); err == nil {
		v.EvpnLocal = a.String()
	}
	v.EvpnImportRts, v.EvpnExportRts = cleanList(v.EvpnImportRts), cleanList(v.EvpnExportRts)
	if problems := fwconfig.CheckVRFEVPN(v.EVPN()); len(problems) > 0 {
		return bad(strings.Join(problems, "; "))
	}
	if v.EvpnDevice != "" {
		if !names[v.EvpnDevice] {
			return bad(fmt.Sprintf("evpn underlay: %s is not an interface of this virtual firewall", v.EvpnDevice))
		}
		var in models.Interface
		if tx.Where("instance_id = ? AND name = ?", v.InstanceID, v.EvpnDevice).Limit(1).Find(&in); in.ID != 0 {
			if in.Kind == fwconfig.KindVXLAN {
				return bad(fmt.Sprintf("evpn underlay: %s is a VXLAN", v.EvpnDevice))
			}
			if in.Vrf != "" {
				return bad(fmt.Sprintf("evpn underlay: %s is in VRF %s", v.EvpnDevice, in.Vrf))
			}
		}
	}
	for _, o := range others {
		if o.EvpnVni == v.EvpnVni {
			return bad(fmt.Sprintf("evpn vni: %d is VRF %s's", v.EvpnVni, o.Name))
		}
	}
	var vxlans []string
	tx.Model(&models.Interface{}).Where("instance_id = ? AND kind = ? AND vxlan_vni = ?", v.InstanceID, fwconfig.KindVXLAN, v.EvpnVni).Pluck("name", &vxlans)
	if len(vxlans) > 0 {
		return bad(fmt.Sprintf("evpn vni: %d is VXLAN %s's", v.EvpnVni, vxlans[0]))
	}
	return nil
}

// deleteVrf refuses a VRF that interfaces, routes, BGP neighbours or peer
// groups are in, or that runs BGP, OSPF or IS-IS; a disabled config goes
// with it.
func deleteVrf(tx *gorm.DB, v *models.Vrf) error {
	var users []string
	var ifs, routes, neighbors, groups []string
	tx.Model(&models.Interface{}).Where("instance_id = ? AND vrf = ?", v.InstanceID, v.Name).Order("name").Pluck("name", &ifs)
	tx.Model(&models.Route{}).Where("vrf_id = ?", v.ID).Order("destination").Pluck("destination", &routes)
	tx.Model(&models.BgpNeighbor{}).Where("vrf_id = ?", v.ID).Order("address").Pluck("address", &neighbors)
	tx.Model(&models.BgpPeerGroup{}).Where("vrf_id = ?", v.ID).Order("name").Pluck("name", &groups)
	for _, i := range ifs {
		users = append(users, "interface "+i)
	}
	for _, r := range routes {
		users = append(users, "route "+r)
	}
	for _, n := range neighbors {
		users = append(users, "BGP neighbour "+n)
	}
	for _, g := range groups {
		users = append(users, "BGP peer group "+g)
	}
	for _, c := range []struct {
		what  string
		model any
		where string
	}{
		{"BGP", &models.BgpConfig{}, "vrf_id = ? AND enabled"},
		{"OSPFv2", &models.OspfConfig{}, "vrf_id = ? AND enabled AND version = 2"},
		{"OSPFv3", &models.OspfConfig{}, "vrf_id = ? AND enabled AND version = 3"},
		{"IS-IS", &models.IsisConfig{}, "vrf_id = ? AND enabled"},
	} {
		var n int64
		tx.Model(c.model).Where(c.where, v.ID).Count(&n)
		if n > 0 {
			users = append(users, c.what)
		}
	}
	if len(users) == 0 {
		return nil
	}
	if len(users) > 5 {
		users = append(users[:5], "...")
	}
	return bad(fmt.Sprintf("VRF %s is used by %s", v.Name, strings.Join(users, ", ")))
}

// prepareIfaceVrf checks an interface's VRF: one of its virtual firewall's
// (so an interface moving to another one leaves it first), and not for a
// bridge's member, which the bridge takes along.
func prepareIfaceVrf(tx *gorm.DB, i *models.Interface) error {
	i.Vrf = strings.TrimSpace(i.Vrf)
	if i.Vrf == "" {
		return nil
	}
	if !vrfExists(tx, i.InstanceID, i.Vrf) {
		return bad(fmt.Sprintf("VRF: %s is not a VRF of this virtual firewall", i.Vrf))
	}
	var bridges []models.Interface
	if err := tx.Where("instance_id = ? AND kind = ? AND id <> ?", i.InstanceID, fwconfig.KindBridge, i.ID).Find(&bridges).Error; err != nil {
		return err
	}
	for _, b := range bridges {
		for _, m := range b.Members {
			if m == i.Name {
				return bad(fmt.Sprintf("VRF: %s is a member of bridge %s; put the bridge in the VRF", i.Name, b.Name))
			}
		}
	}
	return nil
}

// Routing rows (BGP, OSPF and IS-IS configs, BGP peer groups and
// neighbours) belong to the main table (vrf_id NULL) or a VRF of their
// instance, and stay there. OSPF and IS-IS interfaces belong to the
// routing of their interface's VRF.

// rowVrf returns a routing row's VRF (nil: the main table), checking that
// it is one of the instance's.
func rowVrf(tx *gorm.DB, instanceID uint, id *uint) (*models.Vrf, error) {
	if id == nil {
		return nil, nil
	}
	var v models.Vrf
	if tx.First(&v, *id).Error != nil || v.InstanceID != instanceID {
		return nil, bad("VRF: not a VRF of this virtual firewall")
	}
	return &v, nil
}

// whereVrf limits a query to the rows of a VRF (nil: the main table).
func whereVrf(q *gorm.DB, id *uint) *gorm.DB {
	if id == nil {
		return q.Where("vrf_id IS NULL")
	}
	return q.Where("vrf_id = ?", *id)
}

// vrfName is a VRF's name, "" for the main table.
func vrfName(v *models.Vrf) string {
	if v == nil {
		return ""
	}
	return v.Name
}

// vrfText names the main table or a VRF in a message.
func vrfText(v *models.Vrf) string {
	if v == nil {
		return "the main table (no VRF)"
	}
	return "VRF " + v.Name
}

// ifaceVrf is the VRF an interface of the instance is in, "" for none
// (and for a link end).
func ifaceVrf(tx *gorm.DB, instanceID uint, name string) string {
	var vrf string
	tx.Model(&models.Interface{}).Where("instance_id = ? AND name = ?", instanceID, name).Limit(1).Pluck("vrf", &vrf)
	return vrf
}

// ifacesInVrf are the names of the instance's interfaces (link ends
// included, which are in none) in a VRF ("" for none).
func ifacesInVrf(tx *gorm.DB, instanceID uint, vrf string) (map[string]bool, error) {
	names, err := ifaceNames(tx, instanceID)
	if err != nil {
		return nil, err
	}
	for name := range names {
		if ifaceVrf(tx, instanceID, name) != vrf {
			delete(names, name)
		}
	}
	return names, nil
}

// checkIfaceVrf refuses an interface outside the routing's VRF.
func checkIfaceVrf(tx *gorm.DB, instanceID uint, what, name string, v *models.Vrf) error {
	if name == "" {
		return nil
	}
	if got := ifaceVrf(tx, instanceID, name); got != vrfName(v) {
		where := "in no VRF"
		if got != "" {
			where = "in VRF " + got
		}
		return bad(fmt.Sprintf("%s: %s is %s, not in %s", what, name, where, vrfText(v)))
	}
	return nil
}

// ifaceVrfID is the id of the VRF an interface of the instance is in, nil
// for none: the routing whose OSPF or IS-IS the interface's settings are.
func ifaceVrfID(tx *gorm.DB, instanceID uint, name string) *uint {
	vrf := ifaceVrf(tx, instanceID, name)
	if vrf == "" {
		return nil
	}
	var v models.Vrf
	if tx.Where("instance_id = ? AND name = ?", instanceID, vrf).First(&v).Error != nil {
		return nil
	}
	return &v.ID
}
