-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- A DNS template's nameservers get an optional address: each entry of the
-- JSON array becomes {"name", "address"}. A nameserver with an IPv4 and an
-- IPv6 address is two entries.
UPDATE dns_templates SET nameservers = (
    SELECT json_group_array(json_object('name', value, 'address', ''))
    FROM json_each(dns_templates.nameservers)
) WHERE json_type(nameservers, '$[0]') = 'text';

-- +goose Down
UPDATE dns_templates SET nameservers = (
    SELECT json_group_array(name) FROM (
        SELECT json_extract(value, '$.name') AS name, min(key) AS k
        FROM json_each(dns_templates.nameservers) GROUP BY name ORDER BY k
    )
) WHERE json_type(nameservers, '$[0]') = 'object';
