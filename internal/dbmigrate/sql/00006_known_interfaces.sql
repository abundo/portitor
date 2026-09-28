-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Physical interfaces the agent has reported. A new one is imported into
-- the default instance once; one the user deleted is not imported again.
CREATE TABLE known_interfaces (
    name        TEXT PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE known_interfaces;
