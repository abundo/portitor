-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- A country IP list's countries (source 'country', fwconfig.IPList.Countries):
-- ISO 3166-1 alpha-2 codes, a JSON array.
ALTER TABLE ip_lists ADD COLUMN countries TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE ip_lists DROP COLUMN countries;
