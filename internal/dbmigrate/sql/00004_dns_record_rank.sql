-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Records keep the order they are edited in (the zone editor is a grid).
-- Rows of type COMMENT and $DOMAIN are editor-only: comments are dropped
-- and $DOMAIN makes the names below it relative to a subdomain when the
-- document is built.
ALTER TABLE dns_records ADD COLUMN rank INTEGER NOT NULL DEFAULT 0;
UPDATE dns_records r SET rank = o.n
FROM (SELECT id, row_number() OVER (PARTITION BY zone_id ORDER BY name, type, id) - 1 AS n FROM dns_records) o
WHERE r.id = o.id;

-- +goose Down
DELETE FROM dns_records WHERE type IN ('COMMENT', '$DOMAIN');
ALTER TABLE dns_records DROP COLUMN rank;
