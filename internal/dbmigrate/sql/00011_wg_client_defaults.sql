-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Defaults for generated WireGuard client configs, per interface:
-- the public endpoint (host:port) and the client's persistent keepalive.
ALTER TABLE interfaces ADD COLUMN wg_endpoint TEXT NOT NULL DEFAULT '';
ALTER TABLE interfaces ADD COLUMN wg_keepalive INTEGER NOT NULL DEFAULT 25;

-- +goose Down
ALTER TABLE interfaces DROP COLUMN wg_keepalive;
ALTER TABLE interfaces DROP COLUMN wg_endpoint;
