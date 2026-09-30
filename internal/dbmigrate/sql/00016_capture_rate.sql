-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The most a packet capture streams from the agent to portitor-web, kbit/s;
-- 0 is unlimited.
ALTER TABLE settings ADD COLUMN capture_rate_kbps INTEGER NOT NULL DEFAULT 1000;

-- +goose Down
ALTER TABLE settings DROP COLUMN capture_rate_kbps;
