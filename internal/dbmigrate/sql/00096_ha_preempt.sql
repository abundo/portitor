-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- An HA pair's primary takes over again when it is back (models.Firewall.HAPreempt).
ALTER TABLE firewalls ADD COLUMN ha_preempt BOOLEAN NOT NULL DEFAULT 1;

-- +goose Down
ALTER TABLE firewalls DROP COLUMN ha_preempt;
