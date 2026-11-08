// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import http from './http'

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
  get: (p, ds = 'candidate') => http.get(url(ds, p)).then((r) => r.data),
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

// treeApi is the list/create/update/remove CrudPage takes, of the entries
// of a YANG list: listPath() is the list's path (instance=main/syslog-server)
// and keys its key leaves. A row is the entry's JSON with `id`, its keys
// joined by ",", which CrudPage passes back to update and remove. A key
// changed in the form renames the entry first.
export function treeApi(listPath, keys = ['name']) {
  const idOf = (row) => keys.map((k) => row[k]).join(',')
  const entry = (id) => `${listPath()}=${id.split(',').map(encodeURIComponent).join(',')}`
  // Members starting with _ are the page's (CrudPage's params, which it
  // reloads on), not the entry's.
  const body = (row) => {
    const b = { ...row }
    delete b.id
    for (const k of Object.keys(b)) if (k.startsWith('_')) delete b[k]
    return b
  }
  return {
    list: async () => {
      const rows = await config.get(listPath())
      return (rows ?? []).map((r) => ({ ...r, id: idOf(r) }))
    },
    get: (id) => config.get(entry(id)),
    create: async (row) => {
      const res = await config.post(listPath(), body(row))
      return { ...row, ...(res?.keys ? Object.fromEntries(keys.map((k, i) => [k, res.keys[i]])) : {}) }
    },
    update: async (id, row) => {
      let target = id
      const now = idOf(row)
      if (now && now !== id) {
        await config.rename(entry(id), keys.map((k) => String(row[k])))
        target = now
      }
      await config.put(entry(target), body(row))
      return row
    },
    remove: (id) => config.remove(entry(id)),
  }
}
