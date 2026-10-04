-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- How the GUI shows dates and times for the user (models.DateFormats).
ALTER TABLE users ADD COLUMN date_format TEXT NOT NULL DEFAULT 'locale';

-- +goose Down
ALTER TABLE users DROP COLUMN date_format;
