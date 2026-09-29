// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbmigrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/netip"
	"sort"

	"github.com/pressly/goose/v3"
)

// interfaceAddresses (migration 10) moves the IPAM addresses assigned to
// an interface into interfaces.addresses (added by 9; 11 drops
// ipam_addresses.interface_id). The prefix length is the one the builder
// used: the smallest IPAM prefix of the instance around the address, or a
// host route when there is none. An address row that carried nothing but
// the assignment goes; one with a DNS name, MAC or description stays in
// IPAM.
var interfaceAddresses = func() *goose.Migration {
	m := goose.NewGoMigration(10,
		&goose.GoFunc{RunTx: interfaceAddressesUp},
		&goose.GoFunc{RunTx: interfaceAddressesDown})
	m.Source = "00010_interface_addresses.go" // the name goose logs
	return m
}()

func interfaceAddressesUp(ctx context.Context, tx *sql.Tx) error {
	prefixes := map[int64][]netip.Prefix{} // by instance
	rows, err := tx.QueryContext(ctx, `SELECT instance_id, prefix FROM ipam_prefixes`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var inst int64
		var s string
		if err := rows.Scan(&inst, &s); err != nil {
			rows.Close()
			return err
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes[inst] = append(prefixes[inst], p.Masked())
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	type assigned struct {
		id, inst, iface int64
		addr            netip.Addr
		keep            bool
	}
	var list []assigned
	rows, err = tx.QueryContext(ctx, `SELECT id, instance_id, interface_id, address, dns_name <> '' OR mac <> '' OR description <> ''
		FROM ipam_addresses WHERE interface_id IS NOT NULL`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var a assigned
		var s string
		if err := rows.Scan(&a.id, &a.inst, &a.iface, &s, &a.keep); err != nil {
			rows.Close()
			return err
		}
		if a.addr, err = netip.ParseAddr(s); err != nil {
			slog.Warn("migration: invalid IPAM address dropped", "address", s)
			continue
		}
		list = append(list, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	byIface := map[int64][]netip.Prefix{}
	for _, a := range list {
		bits := a.addr.BitLen()
		found := false
		for _, p := range prefixes[a.inst] {
			if p.Contains(a.addr) && (!found || p.Bits() > bits) {
				bits, found = p.Bits(), true
			}
		}
		if !found {
			slog.Warn("migration: interface address in no IPAM prefix, kept as a host address", "address", a.addr)
		}
		byIface[a.iface] = append(byIface[a.iface], netip.PrefixFrom(a.addr, bits))
		if !a.keep {
			if _, err := tx.ExecContext(ctx, `DELETE FROM ipam_addresses WHERE id = ?`, a.id); err != nil {
				return err
			}
		}
	}
	for iface, pfxs := range byIface {
		sort.Slice(pfxs, func(i, j int) bool { return pfxs[i].Addr().Less(pfxs[j].Addr()) })
		out := make([]string, len(pfxs))
		for i, p := range pfxs {
			out[i] = p.String()
		}
		b, _ := json.Marshal(out)
		if _, err := tx.ExecContext(ctx, `UPDATE interfaces SET addresses = ? WHERE id = ?`, string(b), iface); err != nil {
			return err
		}
	}
	return nil
}

// interfaceAddressesDown assigns the interfaces' addresses in IPAM again;
// the prefix lengths are lost.
func interfaceAddressesDown(ctx context.Context, tx *sql.Tx) error {
	type iface struct {
		id, inst int64
		addrs    []string
	}
	var ifaces []iface
	rows, err := tx.QueryContext(ctx, `SELECT id, instance_id, addresses FROM interfaces`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var i iface
		var s string
		if err := rows.Scan(&i.id, &i.inst, &s); err != nil {
			rows.Close()
			return err
		}
		_ = json.Unmarshal([]byte(s), &i.addrs)
		ifaces = append(ifaces, i)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, i := range ifaces {
		for _, a := range i.addrs {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO ipam_addresses (instance_id, address, interface_id) VALUES (?, ?, ?)
				ON CONFLICT (instance_id, address) DO UPDATE SET interface_id = excluded.interface_id`,
				i.inst, p.Addr().String(), i.id); err != nil {
				return err
			}
		}
	}
	return nil
}
