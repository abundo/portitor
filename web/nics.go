// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// nicSync is what syncNICs did with the agent's list of physical
// interfaces.
type nicSync struct {
	// Imported: new interfaces created in the default instance.
	Imported []string `json:"imported"`
	// Missing: physical interfaces in the database the firewall does not have.
	Missing []missingNIC `json:"missing"`
	// Problems: interfaces or addresses that could not be imported.
	Problems []string `json:"problems"`
}

type missingNIC struct {
	Instance string `json:"instance"`
	Name     string `json:"name"`
}

// syncNICs imports physical interfaces of a firewall's root namespace
// that have not been seen before into its default instance, and lists the
// physical interfaces of its instances that the firewall does not have.
//
// An imported interface mirrors what is configured now (link state,
// static addresses), so that deploying does not take down, say,
// the management port. Each name is imported once (models.KnownInterface):
// deleting the interface afterwards sticks. Interfaces in instance
// namespaces were put there by a deploy, so they are declared already.
func (s *Server) syncNICs(firewallID uint, nics []agentapi.NICStatus) (*nicSync, error) {
	s.nicMu.Lock()
	defer s.nicMu.Unlock()
	ctx := context.Background()
	res := &nicSync{Imported: []string{}, Missing: []missingNIC{}, Problems: []string{}}
	v, err := s.view(ctx)
	if err != nil {
		return nil, err
	}
	present := map[string]bool{}
	for _, n := range nics {
		present[n.Name] = true
	}
	instName := map[uint]string{}
	var def *models.Instance
	for i := range v.Instances {
		if v.Instances[i].FirewallID != firewallID {
			continue
		}
		instName[v.Instances[i].ID] = v.Instances[i].Name
		if v.Instances[i].IsDefault {
			def = &v.Instances[i]
		}
	}
	inConfig := map[string]bool{}
	for _, i := range v.Interfaces {
		if _, ok := instName[i.InstanceID]; !ok {
			continue
		}
		inConfig[i.Name] = true
		if i.Kind == fwconfig.KindPhysical && !present[i.Name] {
			res.Missing = append(res.Missing, missingNIC{Instance: instName[i.InstanceID], Name: i.Name})
		}
	}
	sort.Slice(res.Missing, func(a, b int) bool {
		ma, mb := res.Missing[a], res.Missing[b]
		return ma.Instance < mb.Instance || (ma.Instance == mb.Instance && ma.Name < mb.Name)
	})
	if def == nil {
		return res, nil
	}
	// Names seen for the first time: rows of known_interfaces (not
	// configuration), written once the change is made.
	var known []string
	if err := s.db.Model(&models.KnownInterface{}).Where("firewall_id = ?", firewallID).Pluck("name", &known).Error; err != nil {
		return nil, err
	}
	var fresh []agentapi.NICStatus
	for _, n := range nics {
		if n.Netns == "" && !slices.Contains(known, n.Name) {
			known = append(known, n.Name)
			fresh = append(fresh, n)
		}
	}
	if len(fresh) == 0 {
		return res, nil
	}
	err = s.editConfig(ctx, func(work *datastore.Tree) error {
		res.Imported, res.Problems = []string{}, []string{}
		for _, n := range fresh {
			if inConfig[n.Name] {
				continue
			}
			notes, err := importNIC(work, def.Name, n)
			var br *badRequest
			switch {
			case errors.As(err, &br):
				res.Problems = append(res.Problems, fmt.Sprintf("%s: %s", n.Name, br.msg))
				continue
			case err != nil:
				return err
			}
			res.Imported = append(res.Imported, n.Name)
			res.Problems = append(res.Problems, notes...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, n := range fresh {
		if err := s.db.Create(&models.KnownInterface{FirewallID: firewallID, Name: n.Name}).Error; err != nil {
			return nil, err
		}
	}
	return res, nil
}

// importNIC adds a physical interface to the instance as the agent found
// it, with its static addresses. It returns notes on addresses it could
// not carry over; an interface the checks refuse is a *badRequest.
func importNIC(work *datastore.Tree, instance string, n agentapi.NICStatus) ([]string, error) {
	at := datastore.Path{{Name: "instance", Keys: []string{instance}}}
	in, _, err := work.Find(at)
	if err != nil || in == nil {
		return nil, fmt.Errorf("no instance %s", instance)
	}
	taken := map[netip.Addr]string{}
	for _, o := range in.Lists["interface"] {
		for _, a := range o.LeafLists["addresses"] {
			if p, err := netip.ParsePrefix(a); err == nil {
				taken[p.Addr()] = o.Leaf("name")
			}
		}
	}
	var notes []string
	addrs := []string{}
	has4 := false
	for _, a := range n.Addresses {
		p, err := fwconfig.ParseInterfaceAddress(a)
		switch {
		case err != nil:
			notes = append(notes, fmt.Sprintf("%s: %s not added: %v", n.Name, a, err))
		case taken[p.Addr()] != "":
			notes = append(notes, fmt.Sprintf("%s: %s is on %s in the configuration; not added", n.Name, p, taken[p.Addr()]))
		default:
			addrs = append(addrs, p.String())
			has4 = has4 || p.Addr().Is4()
		}
	}
	mode := fwconfig.ModeStatic
	if n.DHCPv4 && !has4 {
		// Something on the host runs DHCP for it; "none" leaves that
		// address alone, where the agent's DHCP client would compete.
		mode = fwconfig.ModeNone
	}
	body, err := json.Marshal(map[string]any{
		"name": n.Name, "kind": fwconfig.KindPhysical, "description": "found on the firewall",
		"enabled": n.Up, "ipv4-mode": mode, "addresses": addrs, "ipv6-accept-ra": n.SLAAC,
	})
	if err != nil {
		return nil, err
	}
	list := append(slices.Clone(at), datastore.Elem{Name: "interface"})
	if err := work.EditJSON(list, datastore.EditCreate, body); err != nil {
		return nil, bad(err.Error())
	}
	e := in.Entry("interface", []string{n.Name})
	if problems := entryProblems(work, e); len(problems) > 0 {
		if err := work.Delete(datastore.PathOf(e)); err != nil {
			return nil, err
		}
		return nil, bad(problems[0].Error())
	}
	return notes, nil
}
