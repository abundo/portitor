-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The BFD timers of an instance's BFD interfaces that set none (0: FRR's).
ALTER TABLE instances ADD COLUMN bfd_detect_multiplier INTEGER NOT NULL DEFAULT 0;
ALTER TABLE instances ADD COLUMN bfd_receive_interval INTEGER NOT NULL DEFAULT 0;
ALTER TABLE instances ADD COLUMN bfd_transmit_interval INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE instances DROP COLUMN bfd_transmit_interval;
ALTER TABLE instances DROP COLUMN bfd_receive_interval;
ALTER TABLE instances DROP COLUMN bfd_detect_multiplier;
