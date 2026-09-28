-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The filter chains (input, forward, output) whose policy drops are logged.
ALTER TABLE instances ADD COLUMN log_drops JSONB NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE instances DROP COLUMN log_drops;
