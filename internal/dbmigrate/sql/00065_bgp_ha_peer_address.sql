-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- A BGP neighbour's address as the HA secondary sees it: a neighbour on
-- the pair itself (another virtual firewall over a link) has the
-- secondary's own address there. Empty: the address.
ALTER TABLE bgp_neighbors ADD COLUMN ha_peer_address TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE bgp_neighbors DROP COLUMN ha_peer_address;
