// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Opens the packet capture of an instance in its own browser window, or
// brings that instance's open window to the front. Each window captures on
// its own, whatever the main window does meanwhile.
export function openCaptureWindow(instanceId) {
  const w = window.open(
    `/capture/window?instance=${encodeURIComponent(instanceId)}`,
    `portitor-capture-${instanceId}`,
    'popup,width=1280,height=860',
  )
  w?.focus()
}
