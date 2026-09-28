// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/ipam"
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

// syncNICs imports physical interfaces of the firewall's root namespace
// that have not been seen before into the default instance, and lists the
// physical interfaces in the database that the firewall does not have.
//
// An imported interface mirrors what is configured now (link state,
// static addresses into IPAM), so that deploying does not take down, say,
// the management port. Each name is imported once (models.KnownInterface):
// deleting the interface afterwards sticks. Interfaces in instance
// namespaces were put there by a deploy, so they are declared already.
func (s *Server) syncNICs(nics []agentapi.NICStatus) (*nicSync, error) {
	s.nicMu.Lock()
	defer s.nicMu.Unlock()
	res := &nicSync{Imported: []string{}, Missing: []missingNIC{}, Problems: []string{}}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var instances []models.Instance
		var ifaces []models.Interface
		var known []models.KnownInterface
		if err := tx.Find(&instances).Error; err != nil {
			return err
		}
		if err := tx.Find(&ifaces).Error; err != nil {
			return err
		}
		if err := tx.Find(&known).Error; err != nil {
			return err
		}

		present := map[string]bool{}
		for _, n := range nics {
			present[n.Name] = true
		}
		instName := map[uint]string{}
		var def *models.Instance
		for i := range instances {
			instName[instances[i].ID] = instances[i].Name
			if instances[i].IsDefault {
				def = &instances[i]
			}
		}
		inDB := map[string]bool{}
		for _, i := range ifaces {
			inDB[i.Name] = true
			if i.Kind == fwconfig.KindPhysical && !present[i.Name] {
				res.Missing = append(res.Missing, missingNIC{Instance: instName[i.InstanceID], Name: i.Name})
			}
		}
		sort.Slice(res.Missing, func(a, b int) bool {
			ma, mb := res.Missing[a], res.Missing[b]
			return ma.Instance < mb.Instance || (ma.Instance == mb.Instance && ma.Name < mb.Name)
		})

		if def == nil {
			return nil
		}
		seen := map[string]bool{}
		for _, k := range known {
			seen[k.Name] = true
		}
		for _, n := range nics {
			if n.Netns != "" || seen[n.Name] {
				continue
			}
			seen[n.Name] = true
			if err := tx.Create(&models.KnownInterface{Name: n.Name}).Error; err != nil {
				return err
			}
			if inDB[n.Name] {
				continue
			}
			var notes []string
			err := tx.Transaction(func(tx *gorm.DB) error {
				var err error
				notes, err = importNIC(tx, def.ID, n)
				return err
			})
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
	return res, nil
}

// importNIC creates a physical interface in the instance as the agent
// found it. Its static addresses go into IPAM, with a prefix of the same
// length when there is none. It returns notes on addresses it could not
// carry over exactly.
func importNIC(tx *gorm.DB, instanceID uint, n agentapi.NICStatus) ([]string, error) {
	var addrs []netip.Prefix
	has4 := false
	for _, a := range n.Addresses {
		if p, err := netip.ParsePrefix(a); err == nil {
			addrs = append(addrs, p)
			has4 = has4 || p.Addr().Is4()
		}
	}
	ifc := models.Interface{
		InstanceID:   instanceID,
		Name:         n.Name,
		Kind:         fwconfig.KindPhysical,
		Description:  "found on the firewall",
		Enabled:      n.Up,
		Ipv4Mode:     fwconfig.ModeStatic,
		Ipv6AcceptRA: n.SLAAC,
		Members:      models.StringList{},
	}
	if n.DHCPv4 && !has4 {
		// Something on the host runs DHCP for it; "none" leaves that
		// address alone, where the agent's DHCP client would compete.
		ifc.Ipv4Mode = fwconfig.ModeNone
	}
	if err := prepareInterface(tx, &ifc, nil); err != nil {
		return nil, err
	}
	if err := tx.Create(&ifc).Error; err != nil {
		return nil, err
	}

	var prefixes []models.IpamPrefix
	if err := tx.Where("instance_id = ?", instanceID).Find(&prefixes).Error; err != nil {
		return nil, err
	}
	var notes []string
	for _, p := range addrs {
		masked := p.Masked().String()
		exists := false
		for _, have := range prefixes {
			if pp, err := netip.ParsePrefix(have.Prefix); err == nil && pp.Masked().String() == masked {
				exists = true
			}
		}
		if !exists {
			np := models.IpamPrefix{InstanceID: instanceID, Prefix: masked, Description: "found on " + n.Name, DhcpDnsServers: models.StringList{}}
			if err := prepareIpamPrefix(tx, &np, nil); err != nil {
				return nil, err
			}
			if err := tx.Create(&np).Error; err != nil {
				return nil, err
			}
			prefixes = append(prefixes, np)
		}
		if enc, _ := ipam.Enclosing(prefixes, p.Addr()); enc.Bits() != p.Bits() {
			notes = append(notes, fmt.Sprintf("%s: %s would be deployed as /%d (IPAM prefix %s)", n.Name, p, enc.Bits(), enc))
		}

		var a models.IpamAddress
		err := tx.Where("instance_id = ? AND address = ?", instanceID, p.Addr().String()).First(&a).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			a = models.IpamAddress{InstanceID: instanceID, Address: p.Addr().String(), InterfaceID: &ifc.ID}
			if err := prepareIpamAddress(tx, &a, nil); err != nil {
				return nil, err
			}
			if err := tx.Create(&a).Error; err != nil {
				return nil, err
			}
		case err != nil:
			return nil, err
		case a.InterfaceID == nil:
			if err := tx.Model(&a).Update("interface_id", ifc.ID).Error; err != nil {
				return nil, err
			}
		case *a.InterfaceID != ifc.ID:
			notes = append(notes, fmt.Sprintf("%s: %s is assigned to another interface in IPAM; not added", n.Name, p.Addr()))
		}
	}
	return notes, nil
}
