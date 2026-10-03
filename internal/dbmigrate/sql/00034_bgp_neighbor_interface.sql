-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The interface of a BGP neighbour with a link-local address.
ALTER TABLE bgp_neighbors ADD COLUMN interface TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE bgp_neighbors DROP COLUMN interface;
