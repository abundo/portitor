// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbmigrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"

	"github.com/pressly/goose/v3"
)

// openVPNTCPAddresses (migration 83) gives an adaptive OpenVPN server's TCP
// tunnel addresses of their own (interfaces.ovpn_tcp_addresses). Before,
// each prefix of the interface's addresses was split in two: the half its
// address is in for the UDP clients, the other half's first address for
// the TCP tunnel. The migration keeps that: the address gets the half's
// prefix length, and the other half becomes the TCP tunnel's.
var openVPNTCPAddresses = func() *goose.Migration {
	m := goose.NewGoMigration(83, &goose.GoFunc{RunTx: openVPNTCPAddressesUp}, &goose.GoFunc{RunTx: openVPNTCPAddressesDown})
	m.Source = "00083_openvpn_tcp_addresses.go" // the name goose logs
	return m
}()

func openVPNTCPAddressesUp(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `ALTER TABLE interfaces ADD COLUMN ovpn_tcp_addresses TEXT NOT NULL DEFAULT '[]'`); err != nil {
		return err
	}
	type row struct {
		id    int64
		addrs []string
	}
	var list []row
	rows, err := tx.QueryContext(ctx, `SELECT id, addresses FROM interfaces WHERE kind = 'openvpn' AND ovpn_mode = 'adaptive'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var r row
		var s string
		if err := rows.Scan(&r.id, &s); err != nil {
			rows.Close()
			return err
		}
		if json.Unmarshal([]byte(s), &r.addrs) == nil {
			list = append(list, r)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range list {
		udp, tcp := []string{}, []string{}
		for _, a := range r.addrs {
			p, err := netip.ParsePrefix(a)
			if err != nil || p.Bits() >= p.Addr().BitLen() {
				udp = append(udp, a)
				continue
			}
			lo := netip.PrefixFrom(p.Masked().Addr(), p.Bits()+1)
			hi := netip.PrefixFrom(lastOf(p), p.Bits()+1).Masked()
			own, other := lo, hi
			if !lo.Contains(p.Addr()) {
				own, other = hi, lo
			}
			udp = append(udp, netip.PrefixFrom(p.Addr(), own.Bits()).String())
			tcp = append(tcp, netip.PrefixFrom(other.Addr().Next(), other.Bits()).String())
		}
		u, _ := json.Marshal(udp)
		t, _ := json.Marshal(tcp)
		if _, err := tx.ExecContext(ctx, `UPDATE interfaces SET addresses = ?, ovpn_tcp_addresses = ? WHERE id = ?`, string(u), string(t), r.id); err != nil {
			return err
		}
	}
	return nil
}

func openVPNTCPAddressesDown(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `ALTER TABLE interfaces DROP COLUMN ovpn_tcp_addresses`)
	return err
}

// lastOf is the last address of a prefix.
func lastOf(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
