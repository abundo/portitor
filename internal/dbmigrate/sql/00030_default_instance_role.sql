-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The default instance, the host itself, has no role: only global admins
-- manage it. Its members go with it (ON DELETE CASCADE).
DELETE FROM roles WHERE instance_id IN (SELECT id FROM instances WHERE is_default);

-- +goose Down
INSERT INTO roles (name, description, instance_id)
SELECT 'vf-' || name, 'Users of virtual firewall ' || name, id FROM instances WHERE is_default;
