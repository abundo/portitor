// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Opens the console of an instance (a shell in its network namespace) in its
// own browser window, or brings that instance's open window to the front.
export function openConsoleWindow(instanceId) {
  const w = window.open(
    `/console/window?instance=${encodeURIComponent(instanceId)}`,
    `portitor-console-${instanceId}`,
    'popup,width=960,height=600',
  )
  w?.focus()
}
