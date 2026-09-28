// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import http from './http'

// crud returns list/create/update/remove for a REST resource.
export function crud(path) {
  return {
    list: (params) => http.get(path, { params }).then((r) => r.data ?? []),
    get: (id) => http.get(`${path}/${id}`).then((r) => r.data),
    create: (body) => http.post(path, body).then((r) => r.data),
    update: (id, body) => http.put(`${path}/${id}`, body).then((r) => r.data),
    remove: (id) => http.delete(`${path}/${id}`),
  }
}

export const instances = crud('/instances')
export const interfaceZones = crud('/interface-zones')
export const interfaces = crud('/interfaces')
export const wgPeers = crud('/wg/peers')
export const links = crud('/links')
export const routes = crud('/routes')
export const rules = crud('/rules')
export const nat = crud('/nat')
export const ipamPrefixes = crud('/ipam/prefixes')
export const ipamAddresses = crud('/ipam/addresses')
export const dnsZones = crud('/dns/zones')
export const dnsRecords = crud('/dns/records')
export const dnsTemplates = crud('/dns/templates')
export const dnsSoaTemplates = crud('/dns/soa-templates')
export const dnsDnssecPolicies = crud('/dns/dnssec-policies')
export const addressObjects = crud('/objects')
export const dyndnsClients = crud('/dyndns/clients')
export const dyndnsRecords = crud('/dyndns/records')
export const ipLists = crud('/ip-lists')
export const tasks = crud('/tasks')

export const api = {
  login: (username, password, remember) =>
    http.post('/login', { username, password, remember }).then((r) => r.data),
  logout: () => http.post('/logout', {}),
  me: () => http.get('/me').then((r) => r.data),
  updateMe: (body) => http.put('/me', body).then((r) => r.data),
  changePassword: (current, next) => http.post('/me/password', { current, new: next }),
  version: () => http.get('/version').then((r) => r.data),

  ipamTree: (instanceId) =>
    http.get('/ipam/tree', { params: { instance_id: instanceId } }).then((r) => r.data),
  // The zone editor saves a zone's whole record grid, in order.
  saveZoneRecords: (zoneId, records) =>
    http.put(`/dns/zones/${zoneId}/records`, records).then((r) => r.data),
  nextFree: (prefixId) =>
    http.get(`/ipam/prefixes/${prefixId}/next-free`).then((r) => r.data.address),
  // Input rules the agent adds for the instance's services, read-only.
  autoRules: (instanceId) =>
    http.get('/rules/auto', { params: { instance_id: instanceId } }).then((r) => r.data ?? []),
  reorder: (kind, ids) => http.post(`/${kind}/reorder`, { ids }),
  wgClientConfig: (peerId, split) =>
    http
      .get(`/wg/peers/${peerId}/config`, { params: split ? { split: 1 } : {} })
      .then((r) => r.data),
  wgRekey: (ifaceId) => http.post(`/interfaces/${ifaceId}/wg-rekey`, {}).then((r) => r.data),
  wgNextFree: (ifaceId) => http.get(`/interfaces/${ifaceId}/wg-next-free`).then((r) => r.data),
  // Start a deployed task, or the download of a deployed IP list, now.
  runTask: (id) => http.post(`/tasks/${id}/run`, {}).then((r) => r.data),
  refreshIPList: (id) => http.post(`/ip-lists/${id}/refresh`, {}).then((r) => r.data),
  // The next runs of a cron schedule ({ next: [...] } or { error }).
  schedulePreview: (schedule) =>
    http.get('/schedule/preview', { params: { schedule } }).then((r) => r.data),

  settings: () => http.get('/settings').then((r) => r.data),
  saveSettings: (body) => http.put('/settings', body).then((r) => r.data),
  users: () => http.get('/users').then((r) => r.data),
  createUser: (username, password) =>
    http.post('/users', { username, password }).then((r) => r.data),
  deleteUser: (id) => http.delete(`/users/${id}`),

  deployCheck: () => http.get('/deploy/check').then((r) => r.data),
  deployChanges: () => http.get('/deploy/changes').then((r) => r.data),
  deployPreview: () => http.post('/deploy/preview', {}).then((r) => r.data),
  deployApply: (confirmTimeout) =>
    http.post('/deploy/apply', { confirm_timeout: confirmTimeout }).then((r) => r.data),
  deployConfirm: () => http.post('/deploy/confirm', {}).then((r) => r.data),
  deployRollback: () => http.post('/deploy/rollback', {}).then((r) => r.data),
  deployments: () => http.get('/deployments').then((r) => r.data),
  agentStatus: () => http.get('/agent/status').then((r) => r.data),
  agentLeases: () => http.get('/agent/leases').then((r) => r.data),
  agentRuleCounters: () => http.get('/agent/rule-counters').then((r) => r.data),
  agentLogs: (after) => http.get('/agent/logs', { params: { after } }).then((r) => r.data),
  agentPacketLog: (after) =>
    http.get('/agent/packet-log', { params: { after } }).then((r) => r.data),

  // Updates of the firewall's Debian and of Portitor (UpdatesPage).
  system: () => http.get('/system').then((r) => r.data),
  systemJob: (job, release) => http.post('/system/jobs', { job, release }).then((r) => r.data),
  systemReboot: () => http.post('/system/reboot', {}).then((r) => r.data),
}
