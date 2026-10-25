-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- An HA pair's number of promotions (on the secondary, with its secret),
-- and its witness (on the primary): its portitor-config, or an external
-- one, which votes with its own secret.
ALTER TABLE firewalls ADD COLUMN ha_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE firewalls ADD COLUMN ha_witness TEXT NOT NULL DEFAULT 'local';
ALTER TABLE firewalls ADD COLUMN ha_witness_secret TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE firewalls DROP COLUMN ha_witness_secret;
ALTER TABLE firewalls DROP COLUMN ha_witness;
ALTER TABLE firewalls DROP COLUMN ha_epoch;
