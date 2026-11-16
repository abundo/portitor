// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// The portal's tabs: its own pages first ('' here), then each firewall opened,
// its GUI (/fw/<name>/) in an iframe that stays loaded while another tab
// shows. Kept for the browser tab's session, so a reload opens them again.
import { reactive, watch } from 'vue'

const KEY = 'portal-tabs'

function restore() {
  try {
    const t = JSON.parse(sessionStorage.getItem(KEY) || '{}')
    if (Array.isArray(t.open))
      return { open: t.open, active: t.open.includes(t.active) ? t.active : '' }
  } catch {
    // none kept
  }
  return { open: [], active: '' }
}

// open: [{ name, path }]; active: a firewall's name, '' the portal's pages.
export const tabs = reactive(restore())

watch(
  tabs,
  () => {
    try {
      sessionStorage.setItem(KEY, JSON.stringify(tabs))
    } catch {
      // a convenience
    }
  },
  { deep: true },
)

export function openTab(name, path) {
  const t = tabs.open.find((x) => x.name === name)
  if (t) t.path = path
  else tabs.open.push({ name, path })
  tabs.active = name
}

// frames: the iframes by firewall name, set by the layout.
export const frames = new Map()

// mayClose asks a tab's GUI about its unsaved changes, shown first.
async function mayClose(name) {
  const w = frames.get(name)?.contentWindow
  if (!w?.portitorConfirmDiscard) return true
  tabs.active = name
  try {
    return await w.portitorConfirmDiscard()
  } catch {
    return true
  }
}

export async function closeTab(name) {
  if (!(await mayClose(name))) return
  const i = tabs.open.findIndex((t) => t.name === name)
  if (i < 0) return
  tabs.open.splice(i, 1)
  if (tabs.active === name) tabs.active = tabs.open[Math.min(i, tabs.open.length - 1)]?.name ?? ''
}

// closeAll closes every tab (logout), false when one keeps its changes.
export async function closeAll() {
  // A copy: a tab may be closed while another's discard dialog is open.
  for (const t of tabs.open.slice()) if (!(await mayClose(t.name))) return false
  tabs.open.splice(0)
  tabs.active = ''
  return true
}
