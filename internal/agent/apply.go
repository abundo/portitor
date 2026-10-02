// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	dnsmgr "github.com/abundo/dnsmgr2/dnsmgr"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

const netnsPrefix = "fw-"

// managedState records virtual interfaces the agent created in the root
// namespace, so it removes only its own. Non-default instance namespaces
// belong to the agent entirely.
type managedState struct {
	RootVirtual []string `json:"root_virtual"`
}

func (a *Agent) managedFile() string { return filepath.Join(a.cfg.Paths.StateDir, "managed.json") }

// applyLocked makes the system match doc. Caller holds a.mu.
func (a *Agent) applyLocked(ctx context.Context, doc fwconfig.Document) error {
	opt := a.renderOptions()
	bundle, err := render.Render(doc, opt)
	if err != nil {
		return err
	}
	doc = doc.ResolveDelegated(opt.Delegated)
	exp := doc.Expand()
	a.log.Infof("applying generation %d", doc.Generation)

	// Preflight: the programs it needs are installed and every ruleset
	// parses, before anything changes.
	if !a.cfg.DryRun {
		if err := checkPrograms(&exp); err != nil {
			return err
		}
	}
	// The rulesets include the IP lists' elements files.
	if err := a.prepareIPLists(&doc); err != nil {
		return err
	}
	if err := a.checkRulesets(ctx, &exp, bundle); err != nil {
		return err
	}

	changed, err := a.writeBundle(bundle)
	if err != nil {
		return err
	}

	existing, err := a.listNamespaces(ctx)
	if err != nil {
		return err
	}
	wantNS := map[string]bool{}
	for i := range exp.Instances {
		in := &exp.Instances[i]
		if ns := in.NetnsName(); ns != "" {
			wantNS[ns] = true
			if !slices.Contains(existing, ns) {
				if err := a.do(ctx, ipCmd("", "netns", "add", ns)); err != nil {
					return err
				}
				existing = append(existing, ns)
			}
			// Checked every time: an apply that failed right after
			// creating the namespace leaves lo down.
			links, err := a.links(ctx, ns)
			if err != nil {
				return err
			}
			if lo, ok := links["lo"]; !ok || !lo.up() {
				if err := a.do(ctx, ipCmd(ns, "link", "set", "dev", "lo", "up")); err != nil {
					return err
				}
			}
		}
		if err := atomicWrite(filepath.Join(a.cfg.Paths.InstanceState(in.Name), "netns"), []byte(in.NetnsName()+"\n"), 0o644); err != nil {
			return err
		}
	}

	// Each instance's ruleset is loaded before its interfaces move in or
	// come up, and before forwarding is turned on, so a new namespace
	// (or the host at boot) never forwards or accepts unfiltered. The
	// rules match interfaces by name (iifname), which need not exist
	// yet; only lo is matched by index, and every namespace has it.
	for i := range exp.Instances {
		in := &exp.Instances[i]
		path := filepath.Join(a.cfg.Paths.InstanceEtc(in.Name), "nftables.nft")
		if err := a.do(ctx, command{Netns: in.NetnsName(), Name: "nft", Args: []string{"-f", path}}); err != nil {
			return fmt.Errorf("instance %s: %w", in.Name, err)
		}
	}

	// Stop services of instances that are going away before their
	// namespace disappears under them.
	for _, ns := range existing {
		if strings.HasPrefix(ns, netnsPrefix) && !wantNS[ns] {
			name := strings.TrimPrefix(ns, netnsPrefix)
			a.stopServices(ctx, name)
		}
	}

	if err := a.placePhysical(ctx, &exp, existing); err != nil {
		return err
	}
	if err := a.placeLinks(ctx, doc); err != nil {
		return err
	}

	var root managedState
	_ = readJSON(a.managedFile(), &root)
	var newRoot []string
	var dhcpWant []dhcpKey
	var dhcp6Want []dhcp6Key
	var ddnsWant []dyndnsItem
	var certsWant []certItem
	var lldpWant []lldpKey
	pktsWant := map[string]string{}
	dnsqWant := map[string]queryLogItem{}

	for i := range exp.Instances {
		in := &exp.Instances[i]
		ns := in.NetnsName()
		etc := a.cfg.Paths.InstanceEtc(in.Name)

		links, err := a.links(ctx, ns)
		if err != nil {
			return err
		}
		if err := a.doAll(ctx, planCreate(ns, in.Interfaces, links)); err != nil {
			return err
		}

		// Remove stale virtual interfaces: anything non-physical in our
		// own namespaces, and in root only what we created earlier.
		want := map[string]bool{}
		for _, ifc := range in.Interfaces {
			want[ifc.Name] = true
			if ns == "" && ifc.Kind != fwconfig.KindPhysical {
				newRoot = append(newRoot, ifc.Name)
			}
		}
		for name, l := range links {
			if want[name] || name == "lo" || l.kind() == "" {
				continue
			}
			if ns != "" || slices.Contains(root.RootVirtual, name) {
				if err := a.do(ctx, ipCmd(ns, "link", "del", "dev", name)); err != nil {
					return err
				}
			}
		}

		for _, ifc := range in.Interfaces {
			if ifc.Kind == fwconfig.KindWireGuard {
				// Fed on stdin: the AppArmor profile for wg (Ubuntu,
				// Debian) only lets it open files under /etc/wireguard,
				// and pipes are not path-mediated.
				conf := bundle.File(filepath.Join(etc, "wireguard", ifc.Name+".conf"))
				if conf == nil {
					return fmt.Errorf("instance %s: %s: no rendered WireGuard config", in.Name, ifc.Name)
				}
				if err := a.do(ctx, command{Netns: ns, Name: "wg", Args: []string{"syncconf", ifc.Name, "/dev/stdin"}, Stdin: []byte(conf.Content)}); err != nil {
					return err
				}
			}
		}

		if links, err = a.links(ctx, ns); err != nil {
			return err
		}
		if err := a.doAll(ctx, planLinkSettings(ns, in.Interfaces, links)); err != nil {
			return err
		}

		// -e: an interface with IPv6 disabled has no accept_ra key.
		// Conntrack timestamps give the Connections page start times.
		sysctls := []string{"net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1", "net.netfilter.nf_conntrack_timestamp=1"}
		for _, ifc := range in.Interfaces {
			ra := "0"
			if ifc.IPv6AcceptRA {
				ra = "2" // accept RAs even though forwarding is on
			}
			sysctls = append(sysctls, "net.ipv6.conf."+strings.ReplaceAll(ifc.Name, ".", "/")+".accept_ra="+ra)
		}
		if err := a.do(ctx, command{Netns: ns, Name: "sysctl", Args: append([]string{"-q", "-e", "-w"}, sysctls...)}); err != nil {
			return err
		}

		for _, ifc := range in.Interfaces {
			if err := a.doAll(ctx, planAddresses(ns, ifc, links[ifc.Name])); err != nil {
				return err
			}
			if ifc.IPv4Mode == fwconfig.ModeDHCP && ifc.Enabled {
				dhcpWant = append(dhcpWant, dhcpKey{instance: in.Name, netns: ns, iface: ifc.Name, noRoute: ifc.DHCPNoDefaultRoute})
			}
			if ifc.LLDP && ifc.Enabled {
				lldpWant = append(lldpWant, lldpKey{instance: in.Name, netns: ns, iface: ifc.Name, descr: ifc.Description})
			}
			if ifc.DHCPv6 && ifc.Enabled {
				dhcp6Want = append(dhcp6Want, dhcp6Key{instance: in.Name, netns: ns, iface: ifc.Name, pd: ifc.DHCPv6PD, pdLen: ifc.DHCPv6PDLength})
			}
		}

		for _, d := range in.DynDNS {
			ddnsWant = append(ddnsWant, dyndnsItem{instance: in.Name, netns: ns, cfg: d})
		}
		for _, c := range in.Certificates {
			certsWant = append(certsWant, certItem{instance: in.Name, netns: ns, cfg: c})
		}
		if logsPackets(in) {
			pktsWant[in.Name] = ns
		}
		if in.DNS.Enabled && in.DNS.QueryLog != nil {
			dnsqWant[in.Name] = queryLogItem{unit: a.cfg.Units.Named(in.Name), filter: *in.DNS.QueryLog}
		}

		var routes []ipRoute
		for _, fam := range []string{"-4", "-6"} {
			out, err := a.run.Run(ctx, ns, "ip", "-j", fam, "route", "show", "proto", RouteProto)
			if err != nil {
				return err
			}
			r, err := parseRoutes(out)
			if err != nil {
				return err
			}
			routes = append(routes, r...)
		}
		if err := a.doAll(ctx, planRoutes(ns, slices.Concat(in.Routes, in.WireGuardRoutes()), routes)); err != nil {
			return err
		}

	}

	slices.Sort(newRoot)
	if err := writeJSON(a.managedFile(), managedState{RootVirtual: newRoot}, 0o644); err != nil {
		return err
	}

	a.dhcp.Reconcile(dhcpWant)
	a.dhcp6.Reconcile(dhcp6Want)
	a.ddns.Reconcile(ddnsWant)
	a.certs.Reconcile(ctx, certsWant)
	a.pkts.Reconcile(pktsWant)
	a.dnsq.Reconcile(dnsqWant)
	a.lldp.Reconcile(lldpWant)

	for i := range exp.Instances {
		if err := a.applyServices(ctx, &exp.Instances[i], bundle, changed); err != nil {
			return err
		}
	}

	for _, ns := range existing {
		if strings.HasPrefix(ns, netnsPrefix) && !wantNS[ns] {
			// Physical interfaces return to the root namespace when the
			// namespace is deleted; virtual ones are destroyed.
			if err := a.do(ctx, ipCmd("", "netns", "del", ns)); err != nil {
				return err
			}
			os.RemoveAll(a.cfg.Paths.InstanceEtc(strings.TrimPrefix(ns, netnsPrefix)))
		}
	}

	if err := writeJSON(a.appliedFile(), doc, 0o600); err != nil {
		return err
	}
	d := doc
	a.applied = &d
	a.lastApply = time.Now()
	a.reconcileIPLists(&d)
	a.tasks.Reconcile(d.Tasks)
	return nil
}

func (a *Agent) checkRulesets(ctx context.Context, exp *fwconfig.Document, b *render.Bundle) error {
	if a.cfg.DryRun {
		a.log.Infof("dry-run: skipping nft -c")
		return nil
	}
	dir, err := os.MkdirTemp(a.cfg.Paths.StateDir, "check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	for _, in := range exp.Instances {
		f := b.File(filepath.Join(a.cfg.Paths.InstanceEtc(in.Name), "nftables.nft"))
		path := filepath.Join(dir, in.Name+".nft")
		if err := os.WriteFile(path, []byte(f.Content), 0o600); err != nil {
			return err
		}
		// Checked in the root namespace: nft -c needs no interfaces to
		// exist, and the instance namespace may not exist yet.
		if _, err := a.run.Run(ctx, "", "nft", "-c", "-f", path); err != nil {
			return fmt.Errorf("instance %s: ruleset rejected: %w", in.Name, err)
		}
	}
	return nil
}

// writeBundle writes rendered files that changed and removes files of
// ours that are no longer rendered. Returns the changed paths.
func (a *Agent) writeBundle(b *render.Bundle) (map[string]bool, error) {
	changed := map[string]bool{}
	keep := map[string]bool{}
	for _, f := range b.Files {
		keep[f.Path] = true
		c, err := a.writeFile(f)
		if err != nil {
			return nil, err
		}
		if c {
			changed[f.Path] = true
		}
	}
	// Stale WireGuard configs hold private keys: remove them.
	matches, _ := filepath.Glob(filepath.Join(a.cfg.Paths.EtcDir, "instances", "*", "wireguard", "*.conf"))
	for _, m := range matches {
		if !keep[m] {
			os.Remove(m)
		}
	}
	return changed, nil
}

func (a *Agent) writeFile(f render.File) (bool, error) {
	if old, err := os.ReadFile(f.Path); err == nil && bytes.Equal(old, []byte(f.Content)) {
		return false, nil
	}
	if a.cfg.DryRun {
		a.log.Infof("dry-run: would write %s (%d bytes)", f.Path, len(f.Content))
		return true, nil
	}
	if err := atomicWrite(f.Path, []byte(f.Content), f.Mode); err != nil {
		return false, err
	}
	a.log.Infof("wrote %s", f.Path)
	return true, nil
}

func (a *Agent) do(ctx context.Context, c command) error {
	_, err := a.run.RunInput(ctx, c.Netns, c.Stdin, c.Name, c.Args...)
	return err
}

func (a *Agent) doAll(ctx context.Context, cmds []command) error {
	for _, c := range cmds {
		if err := a.do(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

func (a *Agent) listNamespaces(ctx context.Context) ([]string, error) {
	out, err := a.run.Run(ctx, "", "ip", "-j", "netns", "list")
	if err != nil {
		return nil, err
	}
	var list []struct {
		Name string `json:"name"`
	}
	if len(bytes.TrimSpace(out)) > 0 {
		if err := json.Unmarshal(out, &list); err != nil {
			return nil, fmt.Errorf("parse netns list: %w", err)
		}
	}
	var names []string
	for _, n := range list {
		if strings.HasPrefix(n.Name, netnsPrefix) {
			names = append(names, n.Name)
		}
	}
	return names, nil
}

func (a *Agent) links(ctx context.Context, ns string) (map[string]ipLink, error) {
	out, err := a.run.Run(ctx, ns, "ip", "-j", "-d", "addr", "show")
	if err != nil {
		return nil, err
	}
	list, err := parseLinks(out)
	if err != nil {
		return nil, err
	}
	m := make(map[string]ipLink, len(list))
	for _, l := range list {
		m[l.Ifname] = l
	}
	return m, nil
}

// placePhysical moves physical interfaces into the namespace of the
// instance that owns them, and returns unowned ones from instance
// namespaces to root.
func (a *Agent) placePhysical(ctx context.Context, exp *fwconfig.Document, namespaces []string) error {
	owner := map[string]string{} // ifname -> netns ("" = root)
	for _, in := range exp.Instances {
		for _, ifc := range in.Interfaces {
			if ifc.Kind == fwconfig.KindPhysical {
				owner[ifc.Name] = in.NetnsName()
			}
		}
	}
	for _, ns := range append([]string{""}, namespaces...) {
		links, err := a.links(ctx, ns)
		if err != nil {
			return err
		}
		for name, l := range links {
			if name == "lo" {
				continue
			}
			// A declared physical interface moves whatever its kind: in a
			// container or VM host it may be a veth. Undeclared ones only
			// go back to root if they are real NICs, never the agent's own
			// virtual interfaces.
			dst, owned := owner[name]
			if !owned {
				if ns == "" || l.kind() != "" {
					continue
				}
				dst = ""
			}
			if dst == ns {
				continue
			}
			target := dst
			if target == "" {
				target = "1" // PID 1's namespace: root
			}
			if err := a.do(ctx, ipCmd(ns, "link", "set", "dev", name, "netns", target)); err != nil {
				return err
			}
		}
	}
	return nil
}

// placeLinks creates veth pairs for Links. A pair is created in the root
// namespace and each end moved to its instance.
func (a *Agent) placeLinks(ctx context.Context, doc fwconfig.Document) error {
	for _, l := range doc.Links {
		inA, inB := doc.Instance(l.A.Instance), doc.Instance(l.B.Instance)
		nsA, nsB := inA.NetnsName(), inB.NetnsName()
		linksA, err := a.links(ctx, nsA)
		if err != nil {
			return err
		}
		linksB, err := a.links(ctx, nsB)
		if err != nil {
			return err
		}
		ea, okA := linksA[l.A.Interface]
		eb, okB := linksB[l.B.Interface]
		if okA && okB && ea.kind() == "veth" && eb.kind() == "veth" {
			continue
		}
		if okA {
			if err := a.do(ctx, ipCmd(nsA, "link", "del", "dev", l.A.Interface)); err != nil {
				return err
			}
		}
		if okB && eb.kind() == "veth" {
			// Deleting one end of a veth deletes the other; ignore errors.
			_, _ = a.run.Run(ctx, nsB, "ip", "link", "del", "dev", l.B.Interface)
		}
		// Create both ends directly in their namespaces.
		args := []string{"link", "add", l.A.Interface}
		if nsA != "" {
			args = append(args, "netns", nsA)
		}
		args = append(args, "type", "veth", "peer", "name", l.B.Interface)
		if nsB != "" {
			args = append(args, "netns", nsB)
		}
		if err := a.do(ctx, ipCmd("", args...)); err != nil {
			return err
		}
	}
	return nil
}

// applyServices runs dnsmgr2 and starts/stops/reloads BIND, Kea and radvd
// for an instance.
func (a *Agent) applyServices(ctx context.Context, in *fwconfig.Instance, b *render.Bundle, changed map[string]bool) error {
	etc := a.cfg.Paths.InstanceEtc(in.Name)
	state := a.cfg.Paths.InstanceState(in.Name)
	named := a.cfg.Units.Named(in.Name)

	cfg, ok := b.Dnsmgr[in.Name]
	if ok {
		if !a.cfg.DryRun {
			// named's own directories (the unit mounts them over the
			// standard ones), and dnsmgr2's scratch directory.
			p := a.cfg.Paths
			bindDirs := []string{
				render.InstanceDir(p.BindCacheDir, in.Name),
				p.BindZones(in.Name),
				render.InstanceDir(p.BindRunDir, in.Name),
			}
			for _, d := range append(bindDirs, filepath.Join(state, "tmp")) {
				if err := os.MkdirAll(d, 0o750); err != nil {
					return err
				}
			}
			for _, d := range bindDirs {
				a.chownBind(d)
			}
			// named's include file dnsmgr2 writes on its first sync;
			// make sure it exists before named starts.
			ensureFile(filepath.Join(etc, "named.conf.dnsmgr2"), "")
		}
		if err := a.do(ctx, command{Name: "systemctl", Args: []string{"enable", "--now", named}}); err != nil {
			return err
		}
		if err := a.dnsmgrSync(cfg); err != nil {
			return fmt.Errorf("instance %s: dnsmgr2: %w", in.Name, err)
		}
	}

	if in.DNS.Enabled {
		if changed[filepath.Join(etc, "named.conf")] {
			if err := a.do(ctx, command{Name: "systemctl", Args: []string{"reload-or-restart", named}}); err != nil {
				return err
			}
		}
	} else {
		a.disable(ctx, named)
	}

	// Kea and radvd are rendered in full (no dnsmgr2).
	kea4, kea6, radvd := a.cfg.Units.Kea4(in.Name), a.cfg.Units.Kea6(in.Name), a.cfg.Units.Radvd(in.Name)
	for _, svc := range []struct {
		unit, conf string
		on         bool
		reload     string
	}{
		{kea4, "kea-dhcp4.conf", in.DHCP.Enabled, "restart"},
		{kea6, "kea-dhcp6.conf", len(render.DHCP6Subnets(in)) > 0, "restart"},
		{radvd, "radvd.conf", len(in.RA) > 0, "reload-or-restart"},
	} {
		if !svc.on {
			a.disable(ctx, svc.unit)
			continue
		}
		if err := a.do(ctx, command{Name: "systemctl", Args: []string{"enable", "--now", svc.unit}}); err != nil {
			return err
		}
		if changed[filepath.Join(etc, svc.conf)] {
			if err := a.do(ctx, command{Name: "systemctl", Args: []string{svc.reload, svc.unit}}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *Agent) dnsmgrSync(cfg dnsmgr.ConfigRoot) error {
	if a.cfg.DryRun {
		a.log.Infof("dry-run: skipping dnsmgr2 sync (%s)", cfg.ConfigDir)
		return nil
	}
	dm, err := dnsmgr.NewDnsManager(cfg)
	if err != nil {
		return err
	}
	if err := dm.Load(); err != nil {
		return err
	}
	if err := dm.Sync(); err != nil {
		return err
	}
	a.log.Infof("dnsmgr2 sync done (%s)", cfg.ConfigDir)
	return nil
}

func (a *Agent) stopServices(ctx context.Context, instance string) {
	a.disable(ctx, a.cfg.Units.Named(instance))
	a.disable(ctx, a.cfg.Units.Kea4(instance))
	a.disable(ctx, a.cfg.Units.Kea6(instance))
	a.disable(ctx, a.cfg.Units.Radvd(instance))
}

// disable stops a unit if it is enabled or running. Errors are ignored:
// the unit may simply not exist.
func (a *Agent) disable(ctx context.Context, unit string) {
	enabled, _ := a.run.Run(ctx, "", "systemctl", "is-enabled", unit)
	active, _ := a.run.Run(ctx, "", "systemctl", "is-active", unit)
	if strings.TrimSpace(string(enabled)) == "enabled" || strings.TrimSpace(string(active)) == "active" {
		_, _ = a.run.Run(ctx, "", "systemctl", "disable", "--now", unit)
	}
}

func (a *Agent) chownBind(path string) {
	u, err := user.Lookup(a.cfg.BindUser)
	if err != nil {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	_ = os.Chown(path, uid, gid)
}

func ensureFile(path, content string) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		_ = atomicWrite(path, []byte(content), 0o644)
	}
}
