// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Opens the console in its own browser window, or brings the open one to
// the front.
export function openConsoleWindow() {
  const w = window.open('/console/window', 'portitor-console', 'popup,width=960,height=600')
  w?.focus()
}
