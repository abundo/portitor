-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Hairpin NAT on port forwards.
ALTER TABLE nat_rules ADD COLUMN hairpin BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE nat_rules DROP COLUMN hairpin;
