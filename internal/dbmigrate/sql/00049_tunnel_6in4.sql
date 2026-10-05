-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- 6in4 tunnels (interfaces of kind 6in4): the tunnel server's IPv4
-- address and the local one (empty: any), and the Hurricane Electric
-- tunnel broker account that keeps the endpoint up to date (empty tunnel
-- id: none); the update key is a secret.
ALTER TABLE interfaces ADD COLUMN tunnel_remote TEXT NOT NULL DEFAULT '';
ALTER TABLE interfaces ADD COLUMN tunnel_local TEXT NOT NULL DEFAULT '';
ALTER TABLE interfaces ADD COLUMN he_tunnel_id TEXT NOT NULL DEFAULT '';
ALTER TABLE interfaces ADD COLUMN he_username TEXT NOT NULL DEFAULT '';
ALTER TABLE interfaces ADD COLUMN he_update_key TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE interfaces DROP COLUMN he_update_key;
ALTER TABLE interfaces DROP COLUMN he_username;
ALTER TABLE interfaces DROP COLUMN he_tunnel_id;
ALTER TABLE interfaces DROP COLUMN tunnel_local;
ALTER TABLE interfaces DROP COLUMN tunnel_remote;
