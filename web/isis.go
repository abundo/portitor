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

// IS-IS, per instance: the configuration, and the interfaces it runs on.
// Interfaces are referred to by name (renaming one rewrites them, deleting
// one in use is refused, web/ifzones.go), route maps as BGP does
// (eachRoutingRef).

func prepareIsisConfig(tx *gorm.DB, c, old *models.IsisConfig) error {
	if old != nil {
		// Rows stay in their instance and VRF.
		c.InstanceID, c.VrfID = old.InstanceID, old.VrfID
	}
	if err := instanceExists(tx, c.InstanceID); err != nil {
		return err
	}
	v, err := rowVrf(tx, c.InstanceID, c.VrfID)
	if err != nil {
		return err
	}
	c.Net, _ = fwconfig.ParseISISNet(c.Net)
	c.NetInterface = strings.TrimSpace(c.NetInterface)
	if c.NetInterface == "" {
		c.NetArea = ""
	} else {
		// The NET from the interface's IPv4 address; the builder makes it
		// again on deploy, so it follows the address.
		area, ok := fwconfig.ParseISISArea(c.NetArea)
		if !ok {
			return bad(fmt.Sprintf("area %q must be an AFI byte and up to 12 more bytes in groups of two (49.0001)", c.NetArea))
		}
		c.NetArea = area
		var ifc models.Interface
		if err := tx.Where("instance_id = ? AND name = ?", c.InstanceID, c.NetInterface).First(&ifc).Error; err != nil {
			return bad(fmt.Sprintf("%q is not an interface of this virtual firewall", c.NetInterface))
		}
		if err := checkIfaceVrf(tx, c.InstanceID, "NET interface", c.NetInterface, v); err != nil {
			return err
		}
		net, ok := fwconfig.ISISNetFromAddresses(area, ifc.Addresses)
		if !ok {
			return bad(fmt.Sprintf("%s has no static IPv4 address to make the NET from", c.NetInterface))
		}
		c.Net = net
	}
	var oldArea, oldDomain string
	if old != nil {
		oldArea, oldDomain = old.AreaPassword, old.DomainPassword
	}
	c.AreaPassword = newSecret(c.NewAreaPassword, c.ClearAreaPassword, oldArea)
	c.DomainPassword = newSecret(c.NewDomainPassword, c.ClearDomainPassword, oldDomain)
	c.NewAreaPassword, c.ClearAreaPassword, c.NewDomainPassword, c.ClearDomainPassword = "", false, "", false
	if c.AreaPasswordType == "" {
		c.AreaPasswordType = fwconfig.ISISAuthMD5
	}
	if c.DomainPasswordType == "" {
		c.DomainPasswordType = fwconfig.ISISAuthMD5
	}
	if c.Enabled && c.Net == "" {
		return bad("a NET is required (49.0001.1921.6800.1001.00: area, system id, 00)")
	}
	if c.DefaultOriginate == nil {
		c.DefaultOriginate = models.JSONList[fwconfig.ISISDefault]{}
	}
	if c.Redistribute == nil {
		c.Redistribute = models.JSONList[fwconfig.ISISRedistribute]{}
	}
	for i := range c.DefaultOriginate {
		c.DefaultOriginate[i].RouteMap = strings.TrimSpace(c.DefaultOriginate[i].RouteMap)
	}
	for i := range c.Redistribute {
		c.Redistribute[i].RouteMap = strings.TrimSpace(c.Redistribute[i].RouteMap)
	}
	s := &fwconfig.ISIS{
		NET: c.Net, Level: c.Level, MetricStyle: c.MetricStyle, IPv6Topology: c.IPv6Topology,
		AreaPassword: c.AreaPassword, AreaPasswordType: c.AreaPasswordType,
		DomainPassword: c.DomainPassword, DomainPasswordType: c.DomainPasswordType,
		DefaultOriginate: c.DefaultOriginate, Redistribute: c.Redistribute,
	}
	if s.NET == "" {
		// Not enabled yet: the rest is checked all the same.
		s.NET = "49.0001.0000.0000.0001.00"
	}
	if err := problems(fwconfig.CheckISIS(s)); err != nil {
		return err
	}
	// Narrow metrics cap the interfaces' metrics too.
	if max := fwconfig.ISISMaxMetric(c.MetricStyle); max < fwconfig.ISISMaxMetric("") {
		var all, ifs []string
		tx.Model(&models.IsisInterface{}).Where("instance_id = ? AND metric > ?", c.InstanceID, max).Order("name").Pluck("name", &all)
		for _, name := range all {
			if ifaceVrf(tx, c.InstanceID, name) == vrfName(v) {
				ifs = append(ifs, name)
			}
		}
		if len(ifs) > 0 {
			return bad(fmt.Sprintf("narrow metrics go up to %d; lower the metric of %s first", max, strings.Join(ifs, ", ")))
		}
	}
	objs, err := loadRoutingObjects(tx, c.InstanceID)
	if err != nil {
		return err
	}
	var errs []string
	for _, d := range c.DefaultOriginate {
		errs = append(errs, objs.check("default originate "+d.Family, refRouteMap, d.RouteMap, "")...)
	}
	for _, r := range c.Redistribute {
		errs = append(errs, objs.check("redistribute "+r.Family+" "+r.Source, refRouteMap, r.RouteMap, "")...)
	}
	return problems(errs)
}

func prepareIsisInterface(tx *gorm.DB, i, old *models.IsisInterface) error {
	if old != nil {
		i.InstanceID = old.InstanceID
	}
	if err := instanceExists(tx, i.InstanceID); err != nil {
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
	var oldPassword string
	if old != nil {
		oldPassword = old.Password
	}
	i.Password = newSecret(i.NewPassword, i.ClearPassword, oldPassword)
	i.NewPassword, i.ClearPassword = "", false
	if i.PasswordType == "" {
		i.PasswordType = fwconfig.ISISAuthMD5
	}
	var ifc models.Interface
	if tx.Where("instance_id = ? AND name = ?", i.InstanceID, i.Name).First(&ifc).Error == nil && fwconfig.ISISLayer3(ifc.Kind) && !i.Passive {
		return bad(fmt.Sprintf("%s is a %s interface, which carries no IS-IS (IS-IS is not IP); it can only be passive, to announce its networks", i.Name, ifc.Kind))
	}
	// The IS-IS of the interface's VRF.
	var cfg models.IsisConfig
	whereVrf(tx.Where("instance_id = ?", i.InstanceID), ifaceVrfID(tx, i.InstanceID, i.Name)).First(&cfg)
	return problems(fwconfig.CheckISISInterface(i.Interface(), cfg.MetricStyle))
}

// newSecret is a write-only secret after a save: the new value, none
// when cleared, or else the stored one.
func newSecret(value string, clear bool, stored string) string {
	switch {
	case clear:
		return ""
	case value != "":
		return value
	}
	return stored
}

func presentIsisConfig(c *models.IsisConfig) {
	c.HasAreaPassword, c.HasDomainPassword = c.AreaPassword != "", c.DomainPassword != ""
	c.NewAreaPassword, c.ClearAreaPassword, c.NewDomainPassword, c.ClearDomainPassword = "", false, "", false
}

func presentIsisInterface(i *models.IsisInterface) {
	i.HasPassword = i.Password != ""
	i.NewPassword, i.ClearPassword = "", false
}

// isisIfaceUsers lists IS-IS when it runs on the interface named name.
func isisIfaceUsers(tx *gorm.DB, instanceID uint, name string) []string {
	var users []string
	var n int64
	tx.Model(&models.IsisInterface{}).Where("instance_id = ? AND name = ?", instanceID, name).Count(&n)
	if n > 0 {
		users = append(users, "IS-IS")
	}
	tx.Model(&models.IsisConfig{}).Where("instance_id = ? AND net_interface = ?", instanceID, name).Count(&n)
	if n > 0 {
		users = append(users, "IS-IS's NET")
	}
	return users
}
