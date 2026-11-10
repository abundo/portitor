// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// A bundle is one virtual firewall as configuration (RFC 7951 JSON of the
// tree, its secrets included): its entry, the shared objects
// (bundleShared, imported by name, reused when equal) and its links, each
// to the other instance by name. The firewall's DNS templates it uses
// (top-level lists) are named (Refs), and must be there where it imports.
// Import gives the lists keyed by an id (rules, routes, records) new ids,
// and the folders those of the folders of the same kind, name and parent
// there. A bundle holds every secret of the virtual firewall, like a
// backup.
//
// Links (they join two instances) come with the instance's name at the
// other end: import makes a link when that instance is there by name and
// the link is not, so it comes with whichever of the two arrives last.
//
// Left out: the instance's role (import makes one), OpenVPN's role (the
// roles are the installation's), and what belongs to the installation
// (deployments, firewalls, known interfaces, users).

const bundleFormat = 2

// bundleShared are the top-level lists of objects shared by all
// instances, which rules refer to by name, parents (folders) first.
var bundleShared = []string{"object-folder", "host", "address-list", "service", "port-name", "ip-list"}

type Bundle struct {
	Format int `json:"format"`
	// Instance is the instance's name in the source.
	Instance string `json:"instance"`
	// Config is the configuration: the instance, the shared objects and
	// its links.
	Config json.RawMessage `json:"config"`
	// Refs are the firewall's entries it names (its DNS templates, SOA
	// templates and DNSSEC policies), found by name on import.
	Refs []bundleRef `json:"refs"`
	// Left lists what was left out.
	Left []string `json:"left"`
}

type bundleRef struct {
	List string `json:"list"`
	Name string `json:"name"`
}

// exportBundle is the bundle of the instance of tree.
func exportBundle(tree *datastore.Tree, instance string) (*Bundle, error) {
	in := tree.Root.Entry("instance", []string{instance})
	if in == nil {
		return nil, bad("no such virtual firewall")
	}
	out := datastore.New(tree.Root.S)
	keep := map[string]bool{"instance": true, "link": true}
	for _, l := range bundleShared {
		keep[l] = true
	}
	all := tree.Clone()
	for name := range all.Root.Lists {
		if !keep[name] {
			delete(all.Root.Lists, name)
		}
	}
	all.Root.Containers = map[string]*datastore.Node{}
	all.Root.Lists["instance"] = slices.DeleteFunc(all.Root.Lists["instance"], func(e *datastore.Node) bool { return e.Leaf("name") != instance })
	all.Root.Lists["link"] = slices.DeleteFunc(all.Root.Lists["link"], func(e *datastore.Node) bool {
		return e.Leaf("instance-a") != instance && e.Leaf("instance-b") != instance
	})
	out.Root = all.Root
	data, err := out.JSON(datastore.JSONOptions{Secrets: true})
	if err != nil {
		return nil, err
	}
	b := &Bundle{Format: bundleFormat, Instance: instance, Config: data, Refs: []bundleRef{}, Left: []string{}}
	// The firewall's entries it names that the bundle leaves out (its DNS
	// templates).
	in.Walk(func(n *datastore.Node) {
		for _, s := range n.S.Children {
			v := n.Leaves[s.Name]
			if v == "" || len(s.Type.Leafrefs()) == 0 {
				continue
			}
			tg := tree.Referenced(n, s, v)
			if tg == nil || tg.Parent != tree.Root || keep[tg.S.Name] {
				continue
			}
			if r := (bundleRef{tg.S.Name, v}); !slices.Contains(b.Refs, r) {
				b.Refs = append(b.Refs, r)
			}
		}
	})
	return b, nil
}

// bundleConflict is a shared object the target has otherwise.
type bundleConflict struct{ msg string }

func (e *bundleConflict) Error() string { return e.msg }

// importBundle adds the bundle's instance to work as a new instance named
// name on the firewall, with its shared objects and links.
func (s *Server) importBundle(work *datastore.Tree, b *Bundle, name string, fw *models.Firewall) error {
	if b.Format != bundleFormat {
		return bad(fmt.Sprintf("bundle format %d, this version reads %d", b.Format, bundleFormat))
	}
	if !fwconfig.ValidInstanceName(name) {
		return bad("name: lowercase letters and digits, starting with a letter, at most 12 characters")
	}
	if work.Root.Entry("instance", []string{name}) != nil {
		return bad(fmt.Sprintf("name: a virtual firewall is named %s", name))
	}
	if fw.HAPrimaryID != nil {
		return bad("firewall: " + fw.Name + " is an HA secondary; it runs its primary's virtual firewalls")
	}
	src := datastore.New(work.Root.S)
	if err := src.UnmarshalJSON(b.Config); err != nil {
		return bad("the bundle: " + err.Error())
	}
	in := src.Root.Entry("instance", []string{b.Instance})
	if in == nil {
		return bad("the bundle holds no virtual firewall")
	}

	// Folders by kind, parent and name, parents first; the entries that
	// are in one follow the folder's id here.
	folders := map[string]string{}
	pending := slices.Clone(src.Root.Lists["object-folder"])
	for len(pending) > 0 {
		var later []*datastore.Node
		for _, f := range pending {
			parent := f.Leaf("parent")
			if parent != "" {
				var ok bool
				if parent, ok = folders[parent]; !ok {
					later = append(later, f)
					continue
				}
			}
			var have *datastore.Node
			for _, h := range work.Root.Lists["object-folder"] {
				if h.Leaf("kind") == f.Leaf("kind") && h.Leaf("name") == f.Leaf("name") && h.Leaf("parent") == parent {
					have = h
				}
			}
			if have == nil {
				id, err := s.nextID(work, f.S, "id")
				if err != nil {
					return err
				}
				obj := map[string]any{"id": id, "kind": f.Leaf("kind"), "name": f.Leaf("name")}
				if parent != "" {
					obj["parent"] = parent
				}
				body, _ := json.Marshal(obj)
				if err := work.EditJSON(datastore.Path{{Name: "object-folder"}}, datastore.EditCreate, body); err != nil {
					return err
				}
				folders[f.Leaf("id")] = strconv.FormatUint(id, 10)
			} else {
				folders[f.Leaf("id")] = have.Leaf("id")
			}
		}
		if len(later) == len(pending) {
			return bad("the bundle's folders refer to folders it doesn't hold")
		}
		pending = later
	}
	// The shared objects: the same here, or added.
	for _, list := range bundleShared[1:] {
		for _, e := range src.Root.Lists[list] {
			if f := e.Leaf("folder"); f != "" {
				e.Leaves["folder"] = folders[f]
			}
			data, err := datastore.NodeJSON(e, datastore.JSONOptions{Secrets: true})
			if err != nil {
				return err
			}
			if have := work.Root.Entry(list, e.Keys()); have != nil {
				mine, err := datastore.NodeJSON(have, datastore.JSONOptions{Secrets: true})
				if err != nil {
					return err
				}
				if !bytes.Equal(mine, data) {
					return &bundleConflict{fmt.Sprintf("%s %s exists here with other values", list, strings.Join(e.Keys(), " "))}
				}
				continue
			}
			if err := work.EditJSON(datastore.Path{{Name: list}}, datastore.EditCreate, data); err != nil {
				return err
			}
		}
	}
	// The firewall's entries it names.
	for _, r := range b.Refs {
		if work.Root.Entry(r.List, []string{r.Name}) == nil {
			return &bundleConflict{fmt.Sprintf("it uses the firewall's %s %s, which is not here", strings.ReplaceAll(r.List, "-", " "), r.Name)}
		}
	}

	// The instance, on the firewall: its host if it has none (a new
	// database).
	isDefault := !slices.ContainsFunc(work.Root.Lists["instance"], func(e *datastore.Node) bool {
		return e.Leaf("firewall") == fw.Name && e.Leaf("is-default") == "true"
	})
	if !isDefault {
		if st := work.Root.Containers["settings"]; st == nil || st.Leaf("virtual-firewalls") != "true" {
			return bad("virtual firewalls are turned off (Settings)")
		}
	}
	in.Leaves["name"], in.Leaves["firewall"] = name, fw.Name
	delete(in.Leaves, "is-default")
	if isDefault {
		in.Leaves["is-default"] = "true"
	}
	for _, ifc := range in.Lists["interface"] {
		// The roles are this installation's: an OpenVPN server that
		// required one lets no one in until one is chosen.
		delete(ifc.Leaves, "ovpn-role")
	}
	// New ids for the lists keyed by one.
	var rekey error
	in.Walk(func(n *datastore.Node) {
		if rekey != nil || n == in || !slices.Equal(n.S.Keys, []string{"id"}) || n.S.Ext["json"] != "" || !n.S.Child("id").Type.Numeric() {
			return
		}
		id, err := s.nextID(work, n.S, "id")
		if err != nil {
			rekey = err
			return
		}
		n.Leaves["id"] = strconv.FormatUint(id, 10)
	})
	if rekey != nil {
		return rekey
	}
	data, err := datastore.NodeJSON(in, datastore.JSONOptions{Secrets: true})
	if err != nil {
		return err
	}
	if err := work.EditJSON(datastore.Path{{Name: "instance"}}, datastore.EditCreate, data); err != nil {
		return err
	}
	// Links to an instance that is here by name, unless there already.
	for _, l := range src.Root.Lists["link"] {
		side, other := "instance-a", l.Leaf("instance-b")
		if l.Leaf("instance-a") != b.Instance {
			side, other = "instance-b", l.Leaf("instance-a")
		}
		if work.Root.Entry("instance", []string{other}) == nil || work.Root.Entry("link", l.Keys()) != nil {
			continue
		}
		l.Leaves[side] = name
		data, err := datastore.NodeJSON(l, datastore.JSONOptions{Secrets: true})
		if err != nil {
			return err
		}
		if err := work.EditJSON(datastore.Path{{Name: "link"}}, datastore.EditCreate, data); err != nil {
			return err
		}
	}
	return nil
}

// bundleProblems are what a commit would refuse in the imported instance
// (it is imported anyway).
func (s *Server) bundleProblems(ctx context.Context, name string) []string {
	in, err := s.candidateInput(ctx)
	if err != nil {
		return []string{err.Error()}
	}
	_, err = builder.BuildInstances(in, 0, map[string]bool{name: true})
	var ve *fwconfig.ValidationError
	if errors.As(err, &ve) {
		return ve.Problems
	}
	return []string{}
}

// handleExportBundle downloads a virtual firewall as a bundle (global
// admins: it holds its secrets).
func (s *Server) handleExportBundle(c *echo.Context) error {
	// It holds the virtual firewall's secrets: global admins only.
	if !currentAccess(c).isAdmin() {
		return errJSON(c, http.StatusForbidden, "a bundle holds the virtual firewall's secrets: global admins only")
	}
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	ctx := c.Request().Context()
	v, err := s.view(ctx)
	if err != nil {
		return err
	}
	inst := v.InstanceByID(id)
	if inst == nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	b, err := exportBundle(v.Tree, inst.Name)
	if err != nil {
		return dbError(c, err)
	}
	return c.JSON(http.StatusOK, b)
}

// handleImportBundle adds a bundle as a new virtual firewall.
func (s *Server) handleImportBundle(c *echo.Context) error {
	var req struct {
		Name       string  `json:"name"`
		FirewallID uint    `json:"firewall_id"`
		Bundle     *Bundle `json:"bundle"`
	}
	if err := c.Bind(&req); err != nil || req.Bundle == nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	fw, err := s.bundleFirewall(req.FirewallID)
	if err != nil {
		return dbError(c, err)
	}
	name := strings.TrimSpace(req.Name)
	ws, err := s.userEdit(c, func(work *datastore.Tree) error { return s.importBundle(work, req.Bundle, name, fw) })
	var conflict *bundleConflict
	switch {
	case errors.As(err, &conflict):
		return errJSON(c, http.StatusConflict, conflict.msg)
	case err != nil:
		return editError(c, err)
	}
	warn(c, ws)
	ctx := c.Request().Context()
	id, _, err := s.entryID(ctx, datastore.Path{{Name: "instance", Keys: []string{name}}})
	if err != nil {
		return err
	}
	return c.JSON(http.StatusCreated, map[string]any{"id": id, "problems": s.bundleProblems(ctx, name), "left": req.Bundle.Left})
}

// bundleFirewall is the firewall a bundle imports to: the one with the
// id, or the first.
func (s *Server) bundleFirewall(id uint) (*models.Firewall, error) {
	var err error
	if id == 0 {
		if id, err = firstFirewallID(s.db); err != nil {
			return nil, err
		}
	}
	var fw models.Firewall
	if err := s.db.First(&fw, id).Error; err != nil {
		return nil, bad("firewall: no such firewall")
	}
	return &fw, nil
}
