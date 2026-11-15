// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// BASE is the GUI's path: '/' on portitor-config itself, '/fw/<name>/'
// behind portitor-web, which portitor-config writes into index.html's
// <base>. Every URL of the API, the console and the router starts with it.
export const BASE = document.querySelector('base')?.getAttribute('href') || '/'

// apiURL is the API path ('/agent/trace') under BASE, for fetch and
// WebSocket; axios has it as its baseURL.
export const apiURL = (path) => `${BASE}api${path}`

// portal: served by portitor-web, which lists its firewalls at
// /portal/v1/firewalls.
export const portal = /^\/fw\/[A-Za-z0-9][A-Za-z0-9._-]*(@(primary|secondary))?\/$/.test(BASE)

// framed: the GUI is a tab of the portal's page (an iframe of its own origin),
// whose tabs switch firewalls; its own firewall pick is left out then.
export const framed = (() => {
  try {
    return window.self !== window.top
  } catch {
    return true
  }
})()
