-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Hash of the full (unredacted) document a deployment sent, so the GUI can
-- tell whether the database has changes that are not deployed.
ALTER TABLE deployments ADD COLUMN doc_hash TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE deployments DROP COLUMN doc_hash;
