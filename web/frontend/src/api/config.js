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
  // Reads report the defaults of unset leaves, as a form shows them.
  get: (p, ds = 'candidate', params = {}) =>
    http
      .get(url(ds, p), { params: { 'with-defaults': 'report-all', ...params } })
      .then((r) => r.data),
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
  // download is a view's whole response, its body a Blob (a file).
  download: (p, action, params = {}) =>
    http.get(url('candidate', p), { params: { ...params, action }, responseType: 'blob' }),
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
  return path(['instance', store.currentName])
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
// bar's): instance=<name>/<list>. A page passes { _vf: store.currentName }
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
      const me = store.currentName
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

// DNS update clients of the selected virtual firewall (the dynamic zones):
// a page's provider_settings ({ key: value }) are the provider-setting
// list's entries, whose values are secrets (provider_secrets_set names
// those set; an empty one keeps it). Rows hold their records, so a form's
// save keeps them; dnsUpdatesShallow lists them without.
const dnsUpdateList = vfApi('dns-update')
const withSettings = ({ provider_setting: ps, ...r }) => ({
  ...r,
  provider_settings: Object.fromEntries((ps ?? []).map((s) => [s.name, s.value ?? ''])),
  provider_secrets_set: (ps ?? []).filter((s) => s.has_value).map((s) => s.name),
})
 
const withSetting = ({ provider_settings: ps, provider_secrets_set, ...r }) => ({
  ...r,
  provider_setting: Object.entries(ps ?? {}).map(([name, value]) => ({ name, value })),
})
export const dnsUpdates = {
  ...dnsUpdateList,
  list: async () => (await dnsUpdateList.list()).map(withSettings),
  get: async (id) => withSettings(await dnsUpdateList.get(id)),
  create: async (r) => withSettings(await dnsUpdateList.create(withSetting(r))),
  update: async (id, r) => withSettings(await dnsUpdateList.update(id, withSetting(r))),
}
export const dnsUpdatesShallow = vfApi('dns-update', ['name'], { shallow: true })
export const dnsUpdatePath = (name) => `${vfPath()}/${path(['dns-update', name])}`
// The DNS zones of the selected virtual firewall, without their records
// (the zone's page edits them).
export const dnsZones = vfApi('dns-zone', ['name'], { shallow: true })

// certificatesOf is the certificates of the virtual firewall instance()
// names, as the certificates page has them: each row with what its chain
// says (is_ca, issuer, chain, not_before, not_after; the chain view) and
// has_privkey; fullchain and privkey for the chain and the (write-only)
// key. A create with generate makes the certificate here (the generate
// action), one with import_ca refuses a certificate that is no CA.
export function certificatesOf(instance) {
  const listPath = () => `${path(['instance', instance()])}/certificate`
  const entryPath = (name) => `${listPath()}=${encodeURIComponent(name)}`
  const base = treeApi(listPath, ['name'], { merge: true })
  const derived = ['is_ca', 'issuer', 'chain', 'not_before', 'not_after', 'has_key']
  const toTree = ({ fullchain, privkey, ...r }) => {
    for (const k of derived) delete r[k]
    return {
      ...r,
      ...(fullchain !== undefined ? { full_chain: fullchain } : {}),
      new_priv_key: privkey || '',
    }
  }
  const withChain = (r, info = {}) => {
    const { full_chain: fullchain, ...o } = r
    return { ...o, fullchain: fullchain ?? '', ...fromEntry(info), has_privkey: !!info['has-key'] }
  }
  return {
    ...base,
    list: async () => {
      const [rows, chains] = await Promise.all([
        base.list(),
        config.view(listPath(), 'chain').catch(() => ({})),
      ])
      return rows.map((r) => withChain(r, chains[r.name]))
    },
    get: async (name) => withChain(await base.get(name), await config.view(entryPath(name), 'chain')),
    create: async (body) => {
      const { generate, import_ca, ...rest } = body
      if (generate) {
        await config.action(entryPath(rest.name), 'generate', {
          domains: generate.domains ?? [],
          'common-name': generate.common_name || '',
          ...(generate.key_type ? { 'key-type': generate.key_type } : {}),
          ...(Number(generate.days) ? { days: Number(generate.days) } : {}),
          ca: !!generate.ca,
          ...(generate.signed_by ? { 'signed-by': generate.signed_by } : {}),
        })
        await config.patch(
          entryPath(rest.name),
          toEntry({ description: rest.description, enabled: rest.enabled }),
        )
        return { ...rest, id: rest.name }
      }
      const made = await base.create(toTree({ ...rest, source: 'import' }))
      if (import_ca && !(await config.view(entryPath(rest.name), 'chain'))['is-ca']) {
        await config.remove(entryPath(rest.name))
        throw new Error(`${rest.name} is not a certificate authority`)
      }
      return made
    },
    update: (id, body) => base.update(id, toTree(body)),
    download: (name, format) => config.download(entryPath(name), 'download', { format }),
    renew: (name) => config.action(entryPath(name), 'renew'),
  }
}
