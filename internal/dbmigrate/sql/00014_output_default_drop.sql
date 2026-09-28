-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The output chain now drops by default. Keep existing instances open with
-- an explicit rule at the end of their rule list.
INSERT INTO rules (instance_id, position, chain, action, enabled, description)
SELECT i.id, COALESCE((SELECT MAX(r.position) FROM rules r WHERE r.instance_id = i.id), 0) + 10,
       'output', 'accept', true, 'allow all output'
FROM instances i;

-- +goose Down
DELETE FROM rules
WHERE chain = 'output' AND kind = '' AND action = 'accept' AND description = 'allow all output'
  AND in_interfaces = '[]' AND out_interfaces = '[]' AND family = '' AND protocol = ''
  AND src_addrs = '[]' AND dst_addrs = '[]' AND dst_ports = '';
