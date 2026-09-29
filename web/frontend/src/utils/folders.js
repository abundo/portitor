// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Folders of hosts and IP lists (object_folders). They nest by parent_id
// (null at the top) and only structure the Hosts & prefixes page.

// folderPath is "Servers / NAS" for folder id.
export function folderPath(folders, id) {
  const byId = new Map(folders.map((f) => [f.id, f]))
  const parts = []
  for (let f = byId.get(id); f; f = byId.get(f.parent_id)) parts.unshift(f.name)
  return parts.join(' / ')
}

// folderOptions are the USelect items for a folder field: the top level
// (0) and every folder of kind by its path, except folder `except` and
// the folders inside it (where a folder cannot move).
export function folderOptions(folders, kind, except = null) {
  const inside = (f) => {
    const byId = new Map(folders.map((x) => [x.id, x]))
    for (let p = f; p; p = byId.get(p.parent_id)) if (p.id === except) return true
    return false
  }
  const opts = folders
    .filter((f) => f.kind === kind && !(except && inside(f)))
    .map((f) => ({ label: folderPath(folders, f.id), value: f.id }))
    .sort((a, b) => a.label.localeCompare(b.label))
  return [{ label: '(top level)', value: 0 }, ...opts]
}
