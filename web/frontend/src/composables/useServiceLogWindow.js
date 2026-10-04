// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Opens the service logs of an instance in their own browser window, or
// brings that instance's open window to the front, so the logs can be
// watched while the main window moves on.
export function openServiceLogWindow(instanceId) {
  const w = window.open(
    `/servicelog/window?instance=${encodeURIComponent(instanceId)}`,
    `portitor-servicelog-${instanceId}`,
    'popup,width=1280,height=860',
  )
  w?.focus()
}
