-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- LLDP on the interface: the agent sends LLDP frames on it and lists the
-- neighbours it hears there. Off by default.
ALTER TABLE interfaces ADD COLUMN lldp BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE interfaces DROP COLUMN lldp;
