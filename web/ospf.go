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

// OSPF, per instance and version (2: OSPFv2, IPv4; 3: OSPFv3, IPv6): the
// configuration, and the interfaces it runs on. Interfaces are referred to
// by name (renaming one rewrites them, deleting one in use is refused,
// web/ifzones.go), route maps as BGP does (eachRoutingRef).

func ospfVersion(v int) error {
	if v != 2 && v != 3 {
		return bad("version must be 2 (OSPFv2) or 3 (OSPFv3)")
	}
	return nil
}

// ospfArea reads an area id and returns it dotted.
func ospfArea(what, s string) (string, error) {
	a, ok := fwconfig.ParseOSPFArea(strings.TrimSpace(s))
	if !ok {
		return "", bad(fmt.Sprintf("%s: area %q must be dotted (0.0.0.0) or a number (0-4294967295)", what, s))
	}
	return a, nil
}

// ospfPrefix reads a prefix and returns it masked.
func ospfPrefix(what, s string) (string, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return "", bad(fmt.Sprintf("%s %q is not a prefix", what, s))
	}
	return p.Masked().String(), nil
}

func prepareOspfConfig(tx *gorm.DB, c, old *models.OspfConfig) error {
	if old != nil {
		// Rows stay in their instance and version.
		c.InstanceID, c.Version = old.InstanceID, old.Version
	}
	if err := instanceExists(tx, c.InstanceID); err != nil {
		return err
	}
	if err := ospfVersion(c.Version); err != nil {
		return err
	}
	c.RouterID = strings.TrimSpace(c.RouterID)
	if !c.DefaultOriginate {
		c.DefaultAlways = false
	}
	if c.Areas == nil {
		c.Areas = models.JSONList[fwconfig.OSPFArea]{}
	}
	if c.Ranges == nil {
		c.Ranges = models.JSONList[fwconfig.OSPFRange]{}
	}
	if c.Summaries == nil {
		c.Summaries = models.JSONList[fwconfig.OSPFSummary]{}
	}
	if c.Networks == nil {
		c.Networks = models.JSONList[fwconfig.OSPFNetwork]{}
	}
	if c.Redistribute == nil {
		c.Redistribute = models.JSONList[fwconfig.OSPFRedistribute]{}
	}
	var err error
	for i := range c.Areas {
		a := &c.Areas[i]
		if a.ID, err = ospfArea("areas", a.ID); err != nil {
			return err
		}
		if a.Type == "" {
			a.Type = fwconfig.AreaNormal
		}
		if a.Type == fwconfig.AreaNormal {
			a.NoSummary = false
		}
	}
	for i := range c.Ranges {
		r := &c.Ranges[i]
		if r.Area, err = ospfArea("range "+r.Prefix, r.Area); err != nil {
			return err
		}
		if r.Prefix, err = ospfPrefix("range", r.Prefix); err != nil {
			return err
		}
		if r.NotAdvertise {
			r.Cost = 0
		}
	}
	for i := range c.Summaries {
		if c.Summaries[i].Prefix, err = ospfPrefix("summary address", c.Summaries[i].Prefix); err != nil {
			return err
		}
	}
	for i := range c.Networks {
		n := &c.Networks[i]
		if n.Prefix, err = ospfPrefix("network", n.Prefix); err != nil {
			return err
		}
		if n.Area, err = ospfArea("network "+n.Prefix, n.Area); err != nil {
			return err
		}
	}
	for i := range c.Redistribute {
		c.Redistribute[i].RouteMap = strings.TrimSpace(c.Redistribute[i].RouteMap)
	}
	o := &fwconfig.OSPF{
		RouterID: c.RouterID, ReferenceBandwidth: c.ReferenceBandwidth, MaximumPaths: c.MaximumPaths,
		DefaultOriginate: c.DefaultOriginate, DefaultAlways: c.DefaultAlways,
		Areas: c.Areas, Ranges: c.Ranges, Summaries: c.Summaries, Networks: c.Networks, Redistribute: c.Redistribute,
	}
	if err := problems(fwconfig.CheckOSPF(o, c.Version)); err != nil {
		return err
	}
	if len(c.Networks) > 0 {
		var ifs []string
		tx.Model(&models.OspfInterface{}).Where("instance_id = ? AND version = ? AND area <> ''", c.InstanceID, c.Version).Order("name").Pluck("name", &ifs)
		if len(ifs) > 0 {
			return bad(fmt.Sprintf("network statements can't be used while interfaces have an area (%s); FRR enables OSPF one way or the other", strings.Join(ifs, ", ")))
		}
	}
	objs, err := loadRoutingObjects(tx, c.InstanceID)
	if err != nil {
		return err
	}
	var errs []string
	for _, r := range c.Redistribute {
		errs = append(errs, objs.check("redistribute "+r.Source, refRouteMap, r.RouteMap, "")...)
	}
	return problems(errs)
}

func prepareOspfInterface(tx *gorm.DB, i, old *models.OspfInterface) error {
	if old != nil {
		i.InstanceID, i.Version = old.InstanceID, old.Version
	}
	if err := instanceExists(tx, i.InstanceID); err != nil {
		return err
	}
	if err := ospfVersion(i.Version); err != nil {
		return err
	}
	i.Name = strings.TrimSpace(i.Name)
	names, err := ifaceNames(tx, i.InstanceID)
	if err != nil {
		return err
	}
	if !names[i.Name] {
		return bad(fmt.Sprintf("%q is not an interface of this virtual firewall", i.Name))
	}
	if strings.TrimSpace(i.Area) != "" {
		if i.Area, err = ospfArea("interface "+i.Name, i.Area); err != nil {
			return err
		}
		var cfg models.OspfConfig
		if tx.Where("instance_id = ? AND version = ?", i.InstanceID, i.Version).First(&cfg).Error == nil && len(cfg.Networks) > 0 {
			return bad("an interface can't have an area while there are network statements; leave the area empty to set the interface's options only, or remove the network statements")
		}
	} else {
		i.Area = ""
	}
	if i.Version != 2 {
		i.NewAuthKey, i.ClearAuthKey, i.AuthKey = "", true, ""
	}
	switch {
	case i.ClearAuthKey:
		i.AuthKey = ""
	case i.NewAuthKey != "":
		i.AuthKey = i.NewAuthKey
	case old != nil:
		i.AuthKey = old.AuthKey
	}
	i.NewAuthKey, i.ClearAuthKey = "", false
	if i.AuthKey == "" {
		i.AuthKeyID = 0
	} else if i.AuthKeyID == 0 {
		i.AuthKeyID = 1
	}
	return problems(fwconfig.CheckOSPFInterface(i.Interface(), i.Version))
}

func presentOspfInterface(i *models.OspfInterface) {
	i.HasAuthKey = i.AuthKey != ""
	i.NewAuthKey, i.ClearAuthKey = "", false
}

// ospfIfaceUsers lists the OSPF interfaces named name.
func ospfIfaceUsers(tx *gorm.DB, instanceID uint, name string) []string {
	var versions []int
	tx.Model(&models.OspfInterface{}).Where("instance_id = ? AND name = ?", instanceID, name).Order("version").Pluck("version", &versions)
	var users []string
	for _, v := range slices.Compact(versions) {
		users = append(users, fmt.Sprintf("OSPFv%d", v))
	}
	return users
}
