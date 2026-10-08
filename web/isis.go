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
		// Rows stay in their instance.
		c.InstanceID = old.InstanceID
	}
	if err := instanceExists(tx, c.InstanceID); err != nil {
		return err
	}
	c.Net, _ = fwconfig.ParseISISNet(c.Net)
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
		var ifs []string
		tx.Model(&models.IsisInterface{}).Where("instance_id = ? AND metric > ?", c.InstanceID, max).Order("name").Pluck("name", &ifs)
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
	var ifc models.Interface
	if tx.Where("instance_id = ? AND name = ?", i.InstanceID, i.Name).First(&ifc).Error == nil && fwconfig.ISISLayer3(ifc.Kind) && !i.Passive {
		return bad(fmt.Sprintf("%s is a %s interface, which carries no IS-IS (IS-IS is not IP); it can only be passive, to announce its networks", i.Name, ifc.Kind))
	}
	var cfg models.IsisConfig
	tx.Where("instance_id = ?", i.InstanceID).First(&cfg)
	return problems(fwconfig.CheckISISInterface(i.Interface(), cfg.MetricStyle))
}

// isisIfaceUsers lists IS-IS when it runs on the interface named name.
func isisIfaceUsers(tx *gorm.DB, instanceID uint, name string) []string {
	var n int64
	tx.Model(&models.IsisInterface{}).Where("instance_id = ? AND name = ?", instanceID, name).Count(&n)
	if n > 0 {
		return []string{"IS-IS"}
	}
	return nil
}
