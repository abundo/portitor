-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The configuration's entries' ids, by path in the tree: what the API, the
-- GUI and the builder know an entry by besides its path. An entry keeps its
-- id across edits and renames; an id is never given to another entry
-- (sqlmap.AssignIDs).
CREATE TABLE config_ids (
    path TEXT PRIMARY KEY,
    tbl  TEXT NOT NULL,
    id   INTEGER NOT NULL
);
CREATE INDEX config_ids_tbl ON config_ids (tbl, id);

-- +goose Down
DROP TABLE config_ids;
