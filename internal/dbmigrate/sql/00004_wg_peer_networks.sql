-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The networks behind a site-to-site peer: allowed IPs that the agent also
-- routes through the WireGuard interface.
ALTER TABLE wg_peers ADD COLUMN networks TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE wg_peers DROP COLUMN networks;
