// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"slices"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// Interface zones and interface references. Rules and NAT rules list
// interfaces and interface zones of their instance by name, and zones list
// interfaces by name (link ends included). Renaming an interface, link end
// or zone rewrites those lists; deleting one that a rule uses is refused,
// since a rule whose list lost its last entry would match any interface.

// ifaceNames returns the interface names of an instance: its interfaces and
// the ends of links in it.
func ifaceNames(tx *gorm.DB, instanceID uint) (map[string]bool, error) {
	names := map[string]bool{}
	var ifs []string
	if err := tx.Model(&models.Interface{}).Where("instance_id = ?", instanceID).Pluck("name", &ifs).Error; err != nil {
		return nil, err
	}
	var links []models.Link
	if err := tx.Where("instance_a_id = ? OR instance_b_id = ?", instanceID, instanceID).Find(&links).Error; err != nil {
		return nil, err
	}
	for _, n := range ifs {
		names[n] = true
	}
	for _, l := range links {
		if l.InstanceAID == instanceID {
			names[l.InterfaceA] = true
		}
		if l.InstanceBID == instanceID {
			names[l.InterfaceB] = true
		}
	}
	return names, nil
}

func ifaceZoneExists(tx *gorm.DB, instanceID uint, name string) bool {
	var n int64
	tx.Model(&models.InterfaceZone{}).Where("instance_id = ? AND name = ?", instanceID, name).Count(&n)
	return n > 0
}

// checkIfaceList checks a rule's interface list: names of interfaces or
// interface zones of the instance.
func checkIfaceList(tx *gorm.DB, instanceID uint, field string, list models.StringList) error {
	names, err := ifaceNames(tx, instanceID)
	if err != nil {
		return err
	}
	for _, s := range list {
		if !names[s] && !ifaceZoneExists(tx, instanceID, s) {
			return bad(fmt.Sprintf("%s: %q is not an interface or interface zone of this instance", field, s))
		}
	}
	return nil
}

// dedupe drops repeated entries, keeping the first.
func dedupe(list models.StringList) models.StringList {
	out := models.StringList{}
	for _, s := range list {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// checkNewIfaceName refuses an interface or link end name that an
// interface zone of the instance already has.
func checkNewIfaceName(tx *gorm.DB, instanceID uint, name, field string) error {
	if ifaceZoneExists(tx, instanceID, name) {
		return bad(fmt.Sprintf("%s: an interface zone is named %s", field, name))
	}
	return nil
}

func prepareInterfaceZone(tx *gorm.DB, z, old *models.InterfaceZone) error {
	if err := instanceExists(tx, z.InstanceID); err != nil {
		return err
	}
	if old != nil && old.InstanceID != z.InstanceID {
		return bad("an interface zone cannot move to another instance")
	}
	z.Name = strings.TrimSpace(z.Name)
	if !fwconfig.ValidZoneName(z.Name) {
		return bad("name: lowercase letters, digits and _, starting with a letter, at most 24 characters")
	}
	names, err := ifaceNames(tx, z.InstanceID)
	if err != nil {
		return err
	}
	if names[z.Name] {
		return bad(fmt.Sprintf("name: %s is an interface of this instance", z.Name))
	}
	z.Interfaces = dedupe(cleanList(z.Interfaces))
	for _, m := range z.Interfaces {
		if !names[m] {
			return bad(fmt.Sprintf("interfaces: %q is not an interface of this instance", m))
		}
	}
	if old != nil && old.Name != z.Name {
		return renameIfaceRefs(tx, z.InstanceID, old.Name, z.Name, false)
	}
	return nil
}

func deleteInterfaceZone(tx *gorm.DB, z *models.InterfaceZone) error {
	return refuseIfaceInUse(tx, z.InstanceID, z.Name)
}

// ifaceLists visits every interface list of the instance's rules and NAT
// rules (and, with zones, of its interface zones). Rows where visit
// returns true are saved.
func ifaceLists(tx *gorm.DB, instanceID uint, zones bool, visit func(where string, list *models.StringList) bool) error {
	save := func(model any, id uint, cols map[string]any) error {
		return tx.Model(model).Where("id = ?", id).UpdateColumns(cols).Error
	}
	var rules []models.Rule
	if err := tx.Where("instance_id = ?", instanceID).Order("position, id").Find(&rules).Error; err != nil {
		return err
	}
	names := ruleNamer{}
	for _, r := range rules {
		where := names.rule(r)
		a, b := visit(where, &r.InInterfaces), visit(where, &r.OutInterfaces)
		if a || b {
			if err := save(&models.Rule{}, r.ID, map[string]any{"in_interfaces": r.InInterfaces, "out_interfaces": r.OutInterfaces}); err != nil {
				return err
			}
		}
	}
	var nat []models.NatRule
	if err := tx.Where("instance_id = ?", instanceID).Order("position, id").Find(&nat).Error; err != nil {
		return err
	}
	for _, n := range nat {
		where := names.nat(n)
		a, b := visit(where, &n.InInterfaces), visit(where, &n.OutInterfaces)
		if a || b {
			if err := save(&models.NatRule{}, n.ID, map[string]any{"in_interfaces": n.InInterfaces, "out_interfaces": n.OutInterfaces}); err != nil {
				return err
			}
		}
	}
	if !zones {
		return nil
	}
	var zs []models.InterfaceZone
	if err := tx.Where("instance_id = ?", instanceID).Find(&zs).Error; err != nil {
		return err
	}
	for _, z := range zs {
		if visit("interface zone "+z.Name, &z.Interfaces) {
			if err := save(&models.InterfaceZone{}, z.ID, map[string]any{"interfaces": z.Interfaces}); err != nil {
				return err
			}
		}
	}
	return nil
}

// renameIfaceRefs rewrites old to name in the instance's rule lists and,
// for an interface (zones true), in its interface zones.
func renameIfaceRefs(tx *gorm.DB, instanceID uint, old, name string, zones bool) error {
	return ifaceLists(tx, instanceID, zones, func(_ string, list *models.StringList) bool {
		changed := false
		for i := range *list {
			if (*list)[i] == old {
				(*list)[i] = name
				changed = true
			}
		}
		if changed {
			*list = dedupe(*list)
		}
		return changed
	})
}

// refuseIfaceInUse refuses removing an interface or zone name that rules
// of the instance use.
func refuseIfaceInUse(tx *gorm.DB, instanceID uint, name string) error {
	var users []string
	err := ifaceLists(tx, instanceID, false, func(where string, list *models.StringList) bool {
		if slices.Contains(*list, name) && !slices.Contains(users, where) {
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
		return bad(fmt.Sprintf("%s is used by %s", name, strings.Join(users, ", ")))
	}
	return nil
}

// removeIface handles an interface or link end leaving an instance: it is
// refused while rules use the name, and dropped from interface zones.
func removeIface(tx *gorm.DB, instanceID uint, name string) error {
	if err := refuseIfaceInUse(tx, instanceID, name); err != nil {
		return err
	}
	var zs []models.InterfaceZone
	if err := tx.Where("instance_id = ?", instanceID).Find(&zs).Error; err != nil {
		return err
	}
	for _, z := range zs {
		if i := slices.Index(z.Interfaces, name); i >= 0 {
			z.Interfaces = slices.Delete(z.Interfaces, i, i+1)
			if err := tx.Model(&models.InterfaceZone{}).Where("id = ?", z.ID).UpdateColumn("interfaces", z.Interfaces).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// ifaceMoved updates references when an interface or link end changes
// name (rewritten) or instance (treated as removed from the old one).
func ifaceMoved(tx *gorm.DB, oldInst uint, oldName string, inst uint, name string) error {
	switch {
	case oldInst == inst && oldName == name:
		return nil
	case oldInst == inst:
		return renameIfaceRefs(tx, inst, oldName, name, true)
	default:
		return removeIface(tx, oldInst, oldName)
	}
}

// refuseIfaceMove refuses to move an interface to another instance while
// its old instance still refers to it: routes (by id, they belong to that
// instance) and VLANs and bridges (by name). Rules and zones are handled
// by ifaceMoved; the interface's addresses move with it.
func refuseIfaceMove(tx *gorm.DB, i *models.Interface) error {
	var users []string
	var routes []string
	tx.Model(&models.Route{}).Where("interface_id = ?", i.ID).Order("destination").Pluck("destination", &routes)
	for _, r := range routes {
		users = append(users, "route "+r)
	}
	var others []models.Interface
	if err := tx.Where("instance_id = ? AND id <> ?", i.InstanceID, i.ID).Order("name").Find(&others).Error; err != nil {
		return err
	}
	for _, o := range others {
		if (o.Kind == fwconfig.KindVLAN && o.Parent == i.Name) || (o.Kind == fwconfig.KindBridge && slices.Contains(o.Members, i.Name)) {
			users = append(users, "interface "+o.Name)
		}
	}
	if len(users) == 0 {
		return nil
	}
	if len(users) > 5 {
		users = append(users[:5], "...")
	}
	return bad(fmt.Sprintf("%s cannot move to another instance while it is used by %s", i.Name, strings.Join(users, ", ")))
}

func deleteInterface(tx *gorm.DB, i *models.Interface) error {
	if err := refuseDyndnsIface(tx, i); err != nil {
		return err
	}
	if err := refuseDelegatedUsers(tx, i, "be deleted"); err != nil {
		return err
	}
	return removeIface(tx, i.InstanceID, i.Name)
}

func deleteLink(tx *gorm.DB, l *models.Link) error {
	if err := removeIface(tx, l.InstanceAID, l.InterfaceA); err != nil {
		return err
	}
	return removeIface(tx, l.InstanceBID, l.InterfaceB)
}
