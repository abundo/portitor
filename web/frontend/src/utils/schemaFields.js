// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// schemaFields makes CrudPage's fields and columns of a YANG list from the
// schema (GET /api/schema): a field per leaf, typed by its leaf's type
// (switch, select of an enumeration, number, tags for a leaf-list, a
// write-only password for a secret), with its description as help. A page
// gives labels, order and what else it wants different as overrides by
// leaf name; `only` lists the leaves to show, in order.

// label makes a leaf's name a label: "ha-gateway" is "HA gateway".
const words = { ha: 'HA', ip: 'IP', ipv4: 'IPv4', ipv6: 'IPv6', mac: 'MAC', dns: 'DNS', dhcp: 'DHCP', vrf: 'VRF', id: 'ID', mtu: 'MTU' }
export function label(name) {
  const s = name
    .split('-')
    .map((w) => words[w] ?? w)
    .join(' ')
  return s.charAt(0).toUpperCase() + s.slice(1)
}

function fieldOf(leaf) {
  const t = leaf.type ?? {}
  const f = { key: leaf.name, label: label(leaf.name), hint: leaf.description }
  if (leaf.kind === 'leaf-list') f.type = 'tags'
  else if (leaf.secret) f.type = 'password'
  else if (t.base === 'boolean') f.type = 'switch'
  else if (t.base === 'enumeration') {
    f.type = 'select'
    f.items = t.enums.map((e) => ({ label: e, value: e }))
    if (!leaf.mandatory && leaf.default == null) f.nullable = true
    f.text = true
  } else if (/^u?int/.test(t.base)) f.type = 'number'
  if (leaf.mandatory) f.required = true
  if (t.format === 'mac-address') f.type = 'mac'
  return f
}

// defaultsOf is a new entry's values: the leaves' defaults.
export function defaultsOf(list) {
  const d = {}
  for (const c of list?.children ?? []) {
    if (c.kind !== 'leaf' && c.kind !== 'leaf-list') continue
    if (c.kind === 'leaf-list') d[c.name] = []
    else if (c.default != null) {
      const t = c.type?.base
      d[c.name] = t === 'boolean' ? c.default === 'true' : /^u?int/.test(t) ? Number(c.default) : c.default
    } else if (c.type?.base === 'boolean') d[c.name] = false
  }
  return d
}

export function schemaFields(list, { only, overrides = {}, hide = [] } = {}) {
  if (!list) return []
  const leaves = list.children.filter(
    (c) => (c.kind === 'leaf' || c.kind === 'leaf-list') && !c.state && !hide.includes(c.name),
  )
  const order = only ?? leaves.map((c) => c.name)
  return order
    .map((name) => {
      const leaf = leaves.find((c) => c.name === name)
      if (!leaf) return overrides[name] ? { key: name, ...overrides[name] } : null
      return { ...fieldOf(leaf), ...(overrides[name] ?? {}) }
    })
    .filter(Boolean)
}

// schemaColumns makes CrudPage's columns of the leaves named.
export function schemaColumns(list, names, overrides = {}) {
  return names.map((name) => ({ key: name, label: label(name), ...(overrides[name] ?? {}) }))
}
