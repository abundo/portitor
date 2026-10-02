-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The certificate portitor-web serves HTTPS with, chosen under Settings
-- (replaces web.yaml's tls_certificate). Deleting it, or its instance,
-- falls back to tls_cert.
ALTER TABLE settings ADD COLUMN web_certificate_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE settings DROP COLUMN web_certificate_id;
