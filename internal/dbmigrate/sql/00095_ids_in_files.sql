-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The entries' ids (config_ids) and the commit counter and web certificate
-- (settings) are kept in files next to the database now (entry-ids.json,
-- state.json), seeded from these tables at the first start. The tables stay
-- until the database goes; this version only marks that they are no longer
-- written, so an older portitor-config refuses a database or copy of it.
SELECT 1;
