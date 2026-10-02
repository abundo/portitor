-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- A certificate's subject CN, one of its domains (SANs); empty uses the first.
ALTER TABLE certificates ADD COLUMN common_name TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE certificates DROP COLUMN common_name;
