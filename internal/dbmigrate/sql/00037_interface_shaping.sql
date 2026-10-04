-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Traffic shaping (CAKE) of what an interface sends and receives, Mbit/s.
ALTER TABLE interfaces ADD COLUMN shape_egress INTEGER NOT NULL DEFAULT 0;
ALTER TABLE interfaces ADD COLUMN shape_ingress INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE interfaces DROP COLUMN shape_ingress;
ALTER TABLE interfaces DROP COLUMN shape_egress;
