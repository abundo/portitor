-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Comment rows between firewall rules (kind 'comment', text in description).
ALTER TABLE rules ADD COLUMN kind TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE rules DROP COLUMN kind;
