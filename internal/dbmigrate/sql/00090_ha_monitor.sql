-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- A carrier that counts in an HA host's health (fwconfig.Interface.HAMonitor).
ALTER TABLE interfaces ADD COLUMN ha_monitor BOOLEAN NOT NULL DEFAULT true;

-- +goose Down
ALTER TABLE interfaces DROP COLUMN ha_monitor;
