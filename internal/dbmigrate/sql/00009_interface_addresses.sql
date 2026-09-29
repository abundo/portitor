-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- An interface's static addresses in CIDR form (192.168.1.1/24), set on the
-- interface itself. Migration 10 (Go, interface_addresses.go) moves the
-- addresses IPAM assigned to interfaces here.
ALTER TABLE interfaces ADD COLUMN addresses TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE interfaces DROP COLUMN addresses;
