// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"cmp"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/confview"
	"github.com/abundo/portitor/models"
)

// Reads of lists of the configuration as rows (confview), with their
// ids, for the GUI's pages that still read them that way:
//
//	GET /api/<name>          list, filtered by ?<column>=<uint>
//	GET /api/<name>/:id
//
// The configuration is written through /api/config.
type viewRead[T any, PT model[T]] struct {
	rows func(v *confview.View) []T
	// of is the instances a row belongs to, which decides who reads it;
	// nil: a shared row, everyone reads it.
	of func(v *confview.View, item *T) []uint
	// shared, if set, tells a row everyone reads although it belongs to
	// instances (a global DNS template).
	shared  func(item *T) bool
	filters []string // columns usable as ?column=id filters
	order   string   // columns, as SQL's ORDER BY without desc
	present func(item PT)
}

func (r *viewRead[T, PT]) register(s *Server, g *echo.Group, path string) {
	g.GET(path, func(c *echo.Context) error { return r.list(s, c) })
	g.GET(path+"/:id", func(c *echo.Context) error { return r.get(s, c) })
}

// readable tells whether the user reads the row.
func (r *viewRead[T, PT]) readable(v *confview.View, a *access, item *T) bool {
	if r.of == nil || a.readsAll() || (r.shared != nil && r.shared(item)) {
		return true
	}
	return a.canReadAny(r.of(v, item))
}

func (r *viewRead[T, PT]) list(s *Server, c *echo.Context) error {
	v, err := s.view(c.Request().Context())
	if err != nil {
		return err
	}
	a := currentAccess(c)
	want := map[string]uint64{}
	for _, f := range r.filters {
		if q := c.QueryParam(f); q != "" {
			id, err := strconv.ParseUint(q, 10, 64)
			if err != nil {
				return errJSON(c, http.StatusBadRequest, "invalid filter "+f)
			}
			want[f] = id
		}
	}
	items := []T{}
	for _, item := range r.rows(v) {
		if !r.readable(v, a, &item) {
			continue
		}
		if len(want) > 0 {
			_, row, err := confview.RowOf(&item)
			if err != nil {
				return err
			}
			ok := true
			for f, id := range want {
				n, isInt := row[f].(int64)
				ok = ok && isInt && uint64(n) == id
			}
			if !ok {
				continue
			}
		}
		items = append(items, item)
	}
	if r.order != "" {
		if err := sortRows(items, r.order); err != nil {
			return err
		}
	}
	if r.present != nil {
		for i := range items {
			r.present(PT(&items[i]))
		}
	}
	return c.JSON(http.StatusOK, items)
}

func (r *viewRead[T, PT]) get(s *Server, c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	v, err := s.view(c.Request().Context())
	if err != nil {
		return err
	}
	item := confview.ByID[T, PT](r.rows(v), id)
	if item == nil || !r.readable(v, currentAccess(c), item) {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	if r.present != nil {
		r.present(PT(item))
	}
	return c.JSON(http.StatusOK, item)
}

// sortRows sorts rows by the columns of order ("firewall_id, name"), a
// column followed by "desc" descending.
func sortRows[T any](rows []T, order string) error {
	type keyed struct {
		row  T
		cols []any
	}
	var cols []string
	var desc []bool
	for _, c := range strings.Split(order, ",") {
		f := strings.Fields(c)
		cols = append(cols, f[0])
		desc = append(desc, len(f) > 1 && strings.EqualFold(f[1], "desc"))
	}
	ks := make([]keyed, len(rows))
	for i := range rows {
		_, row, err := confview.RowOf(&rows[i])
		if err != nil {
			return err
		}
		ks[i].row = rows[i]
		for _, c := range cols {
			ks[i].cols = append(ks[i].cols, row[c])
		}
	}
	slices.SortStableFunc(ks, func(a, b keyed) int {
		for i := range cols {
			if n := compareValue(a.cols[i], b.cols[i]); n != 0 {
				if desc[i] {
					return -n
				}
				return n
			}
		}
		return 0
	})
	for i := range ks {
		rows[i] = ks[i].row
	}
	return nil
}

func compareValue(a, b any) int {
	switch x := a.(type) {
	case int64:
		y, _ := b.(int64)
		return cmp.Compare(x, y)
	case string:
		y, _ := b.(string)
		return strings.Compare(x, y)
	case bool:
		y, _ := b.(bool)
		switch {
		case x == y:
			return 0
		case !x:
			return -1
		}
		return 1
	}
	return 0
}

// inInstance: the row has the instance id in InstanceID.
func inInstance[T any](_ *confview.View, item *T) []uint {
	return []uint{uint(reflect.ValueOf(item).Elem().FieldByName("InstanceID").Uint())}
}

// registerViewReads registers the reads of the configuration as rows.
func (s *Server) registerViewReads(g *echo.Group) {
	(&viewRead[models.Instance, *models.Instance]{rows: func(v *confview.View) []models.Instance { return v.Instances },
		of:    func(_ *confview.View, in *models.Instance) []uint { return []uint{in.ID} },
		order: "firewall_id, is_default desc, name", present: presentInstance}).register(s, g, "/instances")
	(&viewRead[models.InterfaceZone, *models.InterfaceZone]{rows: func(v *confview.View) []models.InterfaceZone { return v.InterfaceZones },
		of: inInstance[models.InterfaceZone], filters: []string{"instance_id"}, order: "name"}).register(s, g, "/interface-zones")
	(&viewRead[models.Interface, *models.Interface]{rows: func(v *confview.View) []models.Interface { return v.Interfaces },
		of: inInstance[models.Interface], filters: []string{"instance_id"}, order: "name", present: presentInterface}).register(s, g, "/interfaces")
	(&viewRead[models.Link, *models.Link]{rows: func(v *confview.View) []models.Link { return v.Links },
		of:    func(_ *confview.View, l *models.Link) []uint { return []uint{l.InstanceAID, l.InstanceBID} },
		order: "name"}).register(s, g, "/links")
	(&viewRead[models.Route, *models.Route]{rows: func(v *confview.View) []models.Route { return v.Routes },
		of: inInstance[models.Route], filters: []string{"instance_id"}, order: "destination"}).register(s, g, "/routes")
	(&viewRead[models.BgpPeerGroup, *models.BgpPeerGroup]{rows: func(v *confview.View) []models.BgpPeerGroup { return v.BgpPeerGroups },
		of: inInstance[models.BgpPeerGroup], filters: []string{"instance_id"}, order: "name", present: presentPeerGroup}).register(s, g, "/bgp/peer-groups")
	(&viewRead[models.BgpNeighbor, *models.BgpNeighbor]{rows: func(v *confview.View) []models.BgpNeighbor { return v.BgpNeighbors },
		of: inInstance[models.BgpNeighbor], filters: []string{"instance_id"}, order: "address", present: presentNeighbor}).register(s, g, "/bgp/neighbors")
	(&viewRead[models.OspfInterface, *models.OspfInterface]{rows: func(v *confview.View) []models.OspfInterface { return v.OspfInterfaces },
		of: inInstance[models.OspfInterface], filters: []string{"instance_id", "version"}, order: "name", present: presentOspfInterface}).register(s, g, "/ospf/interfaces")
	(&viewRead[models.IsisInterface, *models.IsisInterface]{rows: func(v *confview.View) []models.IsisInterface { return v.IsisInterfaces },
		of: inInstance[models.IsisInterface], filters: []string{"instance_id"}, order: "name", present: presentIsisInterface}).register(s, g, "/isis/interfaces")
	(&viewRead[models.Vrf, *models.Vrf]{rows: func(v *confview.View) []models.Vrf { return v.Vrfs },
		of: inInstance[models.Vrf], filters: []string{"instance_id"}, order: "name"}).register(s, g, "/vrfs")
	(&viewRead[models.IpamPrefix, *models.IpamPrefix]{rows: func(v *confview.View) []models.IpamPrefix { return v.IpamPrefixes },
		of: inInstance[models.IpamPrefix], filters: []string{"instance_id"}, order: "prefix"}).register(s, g, "/ipam/prefixes")
	(&viewRead[models.Certificate, *models.Certificate]{rows: func(v *confview.View) []models.Certificate { return v.Certificates },
		of: inInstance[models.Certificate], filters: []string{"instance_id"}, order: "name", present: presentCertificate}).register(s, g, "/certificates")
	(&viewRead[models.IpList, *models.IpList]{rows: func(v *confview.View) []models.IpList { return v.IpLists },
		order: "name", present: presentIpList}).register(s, g, "/ip-lists")
}
