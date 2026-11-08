// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import http from './http'
import { useInstanceStore } from '@/stores/instances'

// The configuration on the datastore (web/configapi.go): RFC 8040 paths,
// "instance=main/interface=eth1/mtu", and RFC 7951 JSON (leaves by their
// YANG names) without its envelope. Writes go to the candidate.

// path joins steps into a configuration path; a step is a name, or
// [name, ...keys] for a list entry, each key percent-encoded.
export function path(...steps) {
  return steps
    .map((s) =>
      Array.isArray(s)
        ? `${encodeURIComponent(s[0])}=${s
            .slice(1)
            .map((k) => encodeURIComponent(String(k)))
            .join(',')}`
        : s,
    )
    .join('/')
}

const url = (ds, p) => `/config/${ds}/${p}`

export const config = {
  schema: () => http.get('/schema').then((r) => r.data),
  get: (p, ds = 'candidate', params = {}) => http.get(url(ds, p), { params }).then((r) => r.data),
  put: (p, body) => http.put(url('candidate', p), body).then((r) => r.data),
  patch: (p, body) => http.patch(url('candidate', p), body).then((r) => r.data),
  post: (p, body) => http.post(url('candidate', p), body).then((r) => r.data),
  remove: (p) => http.delete(url('candidate', p)),
  rename: (p, keys) =>
    http.post(url('candidate', p), { keys }, { params: { action: 'rename' } }).then((r) => r.data),
  move: (p, where, key) =>
    http
      .post(url('candidate', p), { where, key }, { params: { action: 'move' } })
      .then((r) => r.data),
  // action runs an entry's action: a view (GET) or an operation or change.
  view: (p, action, params = {}) =>
    http.get(url('candidate', p), { params: { ...params, action } }).then((r) => r.data),
  action: (p, action, body = {}) =>
    http.post(url('candidate', p), body, { params: { action } }).then((r) => r.data),
  changes: () => http.get('/config/changes').then((r) => r.data),
  discard: () => http.post('/config/discard', {}),
}

// snake and kebab rename an entry's members between the pages' names
// (the tables' columns, ha_gateway) and the leaves' (ha-gateway),
// nested entries too.
const rename = (fn) => {
  const walk = (v) => {
    if (Array.isArray(v)) return v.map(walk)
    if (v && typeof v === 'object')
      return Object.fromEntries(Object.entries(v).map(([k, x]) => [fn(k), walk(x)]))
    return v
  }
  return walk
}

export const snake = rename((k) => k.replaceAll('-', '_'))
export const kebab = rename((k) => (k.startsWith('_') ? k : k.replaceAll('_', '-')))

// Secret leaves are never read back; the API marks one that is set with
// an annotation, "@auth-password": {"portitor:set": true}. A page sees it
// as has_auth_password, and writes it as new_auth_password (empty keeps
// it) or clear_auth_password (true removes it), as the CRUD had them.
export function fromEntry(v) {
  if (Array.isArray(v)) return v.map(fromEntry)
  if (!v || typeof v !== 'object') return v
  const out = {}
  for (const [k, x] of Object.entries(v)) {
    if (k.startsWith('@')) {
      if (x?.['portitor:set']) out[`has_${k.slice(1).replaceAll('-', '_')}`] = true
      continue
    }
    out[k.replaceAll('-', '_')] = fromEntry(x)
  }
  return out
}
function secretsOf(b) {
  for (const k of Object.keys(b)) {
    const m = /^(new|clear)_(.+)$/.exec(k)
    if (!m) continue
    if (m[1] === 'new' && b[k]) b[m[2]] = b[k]
    if (m[1] === 'clear' && b[k] && !b[`new_${m[2]}`]) b[m[2]] = null
    delete b[k]
  }
  return b
}

// toEntry is a page's object as the entry's JSON: kebab-case names,
// secrets as above, and the page's own members (_*, has_*) left out. The
// API takes '' (an empty field, a select's "—") as unset, but for a
// secret, which it keeps.
export function toEntry(row) {
  const b = { ...row }
  for (const k of Object.keys(b)) if (k.startsWith('_') || k.startsWith('has_')) delete b[k]
  return kebab(secretsOf(b))
}

// vfPath is the selected virtual firewall's entry: instance=<name>.
export function vfPath() {
  const store = useInstanceStore()
  return path(['instance', store.nameOf(store.currentId)])
}

// treeApi is the list/create/update/remove CrudPage takes, of the entries
// of a YANG list: listPath() is the list's path (instance=main/syslog-server)
// and keys its key leaves. A row is the entry's JSON with `id`, its keys
// joined by ",", which CrudPage passes back to update and remove. A key
// changed in the form renames the entry first.
// Rows have the pages' member names (snake case, as the tables' columns);
// keys are named so too. With shallow, list reads the entries' own leaves
// alone, without their nested lists (a virtual firewall's rules), and
// update merges (PATCH) rather than replace, which would remove them; with
// merge, update merges too (a form that holds some of the entry's leaves).
export function treeApi(listPath, keys = ['name'], { shallow = false, merge = false } = {}) {
  // A row's id is its key's value (a number for an id), or its keys
  // joined by ",".
  const idOf = (row) => (keys.length === 1 ? row[keys[0]] : keys.map((k) => row[k]).join(','))
  const entry = (id) =>
    `${listPath()}=${(keys.length === 1 ? [String(id)] : String(id).split(','))
      .map(encodeURIComponent)
      .join(',')}`
  // Members starting with _ are the page's (CrudPage's params, which it
  // reloads on), not the entry's.
  const body = (row) => {
    const b = { ...row }
    if (!keys.includes('id')) delete b.id
    return toEntry(b)
  }
  return {
    list: async () => {
      const rows = await config.get(listPath(), 'candidate', shallow ? { shallow: '' } : {})
      return (rows ?? []).map(fromEntry).map((r) => ({ ...r, id: idOf(r) }))
    },
    get: async (id) => {
      const r = fromEntry(await config.get(entry(id)))
      return { ...r, id: idOf(r) }
    },
    create: async (row) => {
      const res = await config.post(listPath(), body(row))
      const made = {
        ...row,
        ...(res?.keys ? Object.fromEntries(keys.map((k, i) => [k, res.keys[i]])) : {}),
      }
      return { ...made, id: idOf(made) }
    },
    update: async (id, row) => {
      let target = id
      const now = idOf(row)
      if (now && now !== id) {
        await config.rename(entry(id), keys.map((k) => String(row[k])))
        target = now
      }
      await (shallow || merge ? config.patch : config.put)(entry(target), body(row))
      return { ...row, id: target }
    },
    remove: (id) => config.remove(entry(id)),
    // reorder puts a user-ordered list's entries in the order of ids, with
    // the fewest moves walking it (one for a row dragged elsewhere).
    reorder: async (ids) => {
      const cur = ((await config.get(listPath())) ?? []).map(fromEntry).map(idOf)
      for (let i = 0; i < ids.length; i++) {
        if (cur[i] === ids[i]) continue
        await config.move(
          entry(ids[i]),
          'before',
          keys.length === 1 ? [String(cur[i])] : String(cur[i]).split(','),
        )
        cur.splice(cur.indexOf(ids[i]), 1)
        cur.splice(i, 0, ids[i])
      }
    },
  }
}

// vfApi is treeApi of a list of the selected virtual firewall (the top
// bar's): instance=<name>/<list>. A page passes { _vf: store.currentId }
// as CrudPage's params, which reloads it when another is chosen.
export function vfApi(list, keys = ['name'], opts = {}) {
  return treeApi(() => `${vfPath()}/${list}`, keys, opts)
}

// The shared objects' lists (not a virtual firewall's).

// services: a page's service has `ports`, the entries of its `port` list,
// whose leaves are all keys (0: any).
const serviceList = treeApi(() => 'service')
const withPorts = (r) => ({ ...r, ports: r.port ?? [] })
const withPort = ({ ports, ...r }) => ({
  ...r,
  port:
    r.type === 'tcp/udp/sctp'
      ? (ports ?? []).map((p) => ({
          protocol: p.protocol,
          dst_lo: Number(p.dst_lo) || 0,
          dst_hi: Number(p.dst_hi) || 0,
          src_lo: Number(p.src_lo) || 0,
          src_hi: Number(p.src_hi) || 0,
        }))
      : [],
})
export const services = {
  ...serviceList,
  list: async () => (await serviceList.list()).map(withPorts),
  get: async (id) => withPorts(await serviceList.get(id)),
  create: async (r) => withPorts(await serviceList.create(withPort(r))),
  update: async (id, r) => withPorts(await serviceList.update(id, withPort(r))),
}
export const portNames = treeApi(() => 'port-name')

// vfWithGlobals is vfApi of a list of DNS templates, whose rows are the
// selected virtual firewall's and the global ones of the default virtual
// firewalls (of each firewall), read-only in the others. A row's _owner is
// its virtual firewall's name.
export function vfWithGlobals(list) {
  const own = vfApi(list)
  return {
    ...own,
    list: async () => {
      const store = useInstanceStore()
      const me = store.nameOf(store.currentId)
      const others = store.list.filter((i) => i.is_default && i.name !== me)
      const rows = (await own.list()).map((r) => ({ ...r, _owner: me }))
      for (const i of others) {
        const theirs = (await config.get(`${path(['instance', i.name])}/${list}`)) ?? []
        for (const r of theirs.map(fromEntry))
          if (r.global) rows.push({ ...r, id: `${i.name}/${r.name}`, _owner: i.name })
      }
      return rows
    },
  }
}

// withLists renames an api's nested lists between the pages' names and
// the tree's: { area: 'areas' } shows the area list as areas.
export function withLists(api, names) {
  const toPage = (r) => {
    const o = { ...r }
    for (const [tree, page] of Object.entries(names)) {
      o[page] = o[tree] ?? []
      delete o[tree]
    }
    return o
  }
  const toTree = (r) => {
    const o = { ...r }
    for (const [tree, page] of Object.entries(names)) {
      if (page in o) o[tree] = o[page] ?? []
      delete o[page]
    }
    return o
  }
  return {
    ...api,
    list: async (p) => (await api.list(p)).map(toPage),
    get: async (id) => toPage(await api.get(id)),
    create: async (r) => toPage(await api.create(toTree(r))),
    update: async (id, r) => toPage(await api.update(id, toTree(r))),
  }
}

// The routing objects of the selected virtual firewall; their entries are
// the page's `entries`. Prefix-list and route-map entries are keyed by seq:
// one without (0) gets the next after the highest, in steps of 5 as FRR
// does, before it is written.
const numbered = (api) => {
  const number = (r) => {
    let high = Math.max(0, ...(r.entries ?? []).map((e) => Number(e.seq) || 0))
    const entries = (r.entries ?? []).map((e) => (Number(e.seq) ? e : { ...e, seq: (high += 5) }))
    return { ...r, entries: entries.sort((a, b) => a.seq - b.seq) }
  }
  return {
    ...api,
    create: (r) => api.create(number(r)),
    update: (id, r) => api.update(id, number(r)),
  }
}
const entries = { entry: 'entries' }
export const prefixLists = numbered(withLists(vfApi('prefix-list'), entries))
export const asPathLists = withLists(vfApi('as-path-list'), entries)
export const communityLists = withLists(vfApi('community-list'), entries)
export const routeMaps = numbered(withLists(vfApi('route-map'), entries))

// withNames renames an api's leaves between the pages' names and the
// tree's: { folder: 'folder_id' }. A page's 0 (a select's "none") is unset.
export function withNames(api, names) {
  const toPage = (r) => {
    const o = { ...r }
    for (const [tree, page] of Object.entries(names)) {
      if (tree in o) o[page] = o[tree]
      delete o[tree]
    }
    return o
  }
  const toTree = (r) => {
    const o = { ...r }
    for (const [tree, page] of Object.entries(names)) {
      if (page in o) o[tree] = o[page] || null
      delete o[page]
    }
    return o
  }
  return {
    ...api,
    list: async (p) => (await api.list(p)).map(toPage),
    get: async (id) => toPage(await api.get(id)),
    create: async (r) => toPage(await api.create(toTree(r))),
    update: async (id, r) => toPage(await api.update(id, toTree(r))),
  }
}

// Hosts, address lists, IP lists and the folders they are in (folder_id,
// parent_id: a folder's id, 0 none).
export const hosts = withNames(treeApi(() => 'host'), { folder: 'folder_id' })
export const addressLists = withNames(treeApi(() => 'address-list'), { folder: 'folder_id' })
export const ipLists = withNames(treeApi(() => 'ip-list'), { folder: 'folder_id' })
export const objectFolders = withNames(treeApi(() => 'object-folder', ['id']), {
  parent: 'parent_id',
})
// The IPAM prefixes and addresses of the selected virtual firewall, merged
// on update: the DHCP page sets a prefix's DHCP settings.
export const ipamPrefixes = vfApi('ipam-prefix', ['prefix'], { merge: true })
export const ipamAddresses = vfApi('ipam-address', ['address'], { merge: true })
