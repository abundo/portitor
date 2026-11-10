// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { BASE } from '@/utils/base'

// Opens the service logs of an instance in their own browser window, or
// brings that instance's open window to the front, so the logs can be
// watched while the main window moves on.
export function openServiceLogWindow(instance) {
  const w = window.open(
    `${BASE}servicelog/window?instance=${encodeURIComponent(instance)}`,
    `portitor-servicelog-${instance}`,
    'popup,width=1280,height=860',
  )
  w?.focus()
}
