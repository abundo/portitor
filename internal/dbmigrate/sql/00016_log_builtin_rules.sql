-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The filter chains whose invalid packet drops are logged, and the auto
-- input rules (by service) whose matches are.
ALTER TABLE instances ADD COLUMN log_invalid JSONB NOT NULL DEFAULT '[]';
ALTER TABLE instances ADD COLUMN log_auto JSONB NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE instances DROP COLUMN log_auto;
ALTER TABLE instances DROP COLUMN log_invalid;
