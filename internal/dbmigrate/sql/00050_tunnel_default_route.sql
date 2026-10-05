-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- A 6in4 tunnel may carry the instance's IPv6 default route (::/0 through
-- the tunnel, render.TunnelRouteMetric).
ALTER TABLE interfaces ADD COLUMN tunnel_default_route BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE interfaces DROP COLUMN tunnel_default_route;
