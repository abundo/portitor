-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- How BIND uses the forwarders: first (fall back to the root servers), only,
-- or off (resolve from the root servers).
ALTER TABLE instances ADD COLUMN dns_forward_mode TEXT NOT NULL DEFAULT 'first';

-- +goose Down
ALTER TABLE instances DROP COLUMN dns_forward_mode;
