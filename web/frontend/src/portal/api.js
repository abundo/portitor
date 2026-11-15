// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// The portal's API (/portal/v1, web/portalapi.go). Every write is JSON
// (with the SameSite=Strict cookie, the CSRF defence). A 401 ends the
// session: the router goes to the login page.
import { reactive } from 'vue'

export const session = reactive({ user: '' })

let onUnauthorized = () => {}
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn
}

// PortalError carries the server's message and status (409: the login to
// the other host of an HA firewall is needed).
export class PortalError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

async function call(method, path, body) {
  const opts = { method, credentials: 'same-origin' }
  if (body !== undefined) {
    opts.headers = { 'Content-Type': 'application/json' }
    opts.body = JSON.stringify(body)
  }
  const res = await fetch(`/portal/v1/${path}`, opts)
  let data = {}
  try {
    data = await res.json()
  } catch {
    // no body
  }
  if (res.status === 401 && path !== 'login') {
    session.user = ''
    onUnauthorized()
  }
  if (!res.ok) throw new PortalError(data.error || `HTTP ${res.status}`, res.status)
  return data
}

const enc = encodeURIComponent

export const portal = {
  async session() {
    try {
      session.user = (await call('GET', 'session')).user
    } catch {
      session.user = ''
    }
  },
  async login(user, password) {
    session.user = (await call('POST', 'login', { user, password })).user
  },
  async logout() {
    await call('POST', 'logout', {}).catch(() => {})
    session.user = ''
  },
  version: () => call('GET', 'version'),
  firewalls: () => call('GET', 'firewalls'),
  addFirewall: (f) => call('POST', 'firewalls', f),
  putFirewall: (f) => call('PUT', `firewalls/${enc(f.name)}`, f),
  deleteFirewall: (name) => call('DELETE', `firewalls/${enc(name)}`),
  probe: (req) => call('POST', 'probe', req),
  addHA: (ha) => call('POST', 'ha', ha),
  putHA: (ha) => call('PUT', `ha/${enc(ha.name)}`, ha),
  deleteHA: (name) => call('DELETE', `ha/${enc(name)}`),
  addHAHost: (name, role, req) => call('POST', `ha/${enc(name)}/${role}`, req),
  removeHAHost: (name, role) => call('DELETE', `ha/${enc(name)}/${role}`),
  witnesses: () => call('GET', 'witness'),
  addWitness: (string) => call('POST', 'witness', { string }),
  deleteWitness: (pair) => call('DELETE', `witness/${enc(pair)}`),
}
