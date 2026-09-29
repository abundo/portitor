-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- A short name for an interface in the GUI, e.g. WAN for ens18. It stays in
-- the database; rules keep naming the interface.
ALTER TABLE interfaces ADD COLUMN label TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE interfaces DROP COLUMN label;
