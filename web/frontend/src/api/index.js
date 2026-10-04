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
// Rate limits rules name, per instance.
export const rateLimits = crud('/rate-limits')
export const interfaces = crud('/interfaces')
export const wgPeers = crud('/wg/peers')
export const links = crud('/links')
export const routes = crud('/routes')
export const prefixLists = crud('/routing/prefix-lists')
export const asPathLists = crud('/routing/as-path-lists')
export const communityLists = crud('/routing/community-lists')
export const routeMaps = crud('/routing/route-maps')
export const bgpConfig = crud('/bgp/config')
export const bgpPeerGroups = crud('/bgp/peer-groups')
export const bgpNeighbors = crud('/bgp/neighbors')
export const ospfConfig = crud('/ospf/config')
export const ospfInterfaces = crud('/ospf/interfaces')
export const vrrpRouters = crud('/vrrp/routers')
export const bfdInterfaces = crud('/bfd/interfaces')
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
// Address lists: addresses, prefixes and names of hosts and other lists.
export const addressLists = crud('/address-lists')
export const dyndnsClients = crud('/dyndns/clients')
export const dyndnsRecords = crud('/dyndns/records')
export const certificates = crud('/certificates')
export const ipLists = crud('/ip-lists')
// Folders of hosts (kind hosts), address lists (kind address_lists) and IP
// lists (kind ip_lists), for the GUI only.
export const objectFolders = crud('/object-folders')
export const tasks = crud('/tasks')
// Custom services: protocol matches rules name next to the predefined ones.
export const customServices = crud('/custom-services')

export const api = {
  login: (username, password, remember) =>
    http.post('/login', { username, password, remember }).then((r) => r.data),
  logout: () => http.post('/logout', {}),
  me: () => http.get('/me').then((r) => r.data),
  updateMe: (body) => http.put('/me', body).then((r) => r.data),
  changePassword: (current, next) => http.post('/me/password', { current, new: next }),
  version: () => http.get('/version').then((r) => r.data),
  acmeCAs: () => http.get('/certificates/cas').then((r) => r.data ?? []),
  certificateDownload: (id, format) =>
    http.get(`/certificates/${id}/download`, { params: { format }, responseType: 'blob' }),
  dnsProviders: () => http.get('/dyndns/providers').then((r) => r.data ?? []),

  ipamTree: (instanceId) =>
    http.get('/ipam/tree', { params: { instance_id: instanceId } }).then((r) => r.data),
  // The zone editor saves a zone's whole record grid, in order.
  saveZoneRecords: (zoneId, records) =>
    http.put(`/dns/zones/${zoneId}/records`, records).then((r) => r.data),
  // The dynamic zone editor saves a DNS update client's whole record grid.
  saveDyndnsRecords: (clientId, records) =>
    http.put(`/dyndns/clients/${clientId}/records`, records).then((r) => r.data),
  nextFree: (prefixId) =>
    http.get(`/ipam/prefixes/${prefixId}/next-free`).then((r) => r.data.address),
  // Input rules the agent adds for the instance's services, read-only.
  autoRules: (instanceId) =>
    http.get('/rules/auto', { params: { instance_id: instanceId } }).then((r) => r.data ?? []),
  // Built-in port names that NAT port fields accept ([{ name, port,
  // description }], fwconfig.Services).
  services: () => http.get('/services').then((r) => r.data),
  // The predefined services rules name (netobj.Predefined), shaped like
  // custom services.
  predefinedServices: () => http.get('/predefined-services').then((r) => r.data),
  icmpTypes: () => http.get('/icmp-types').then((r) => r.data),
  reorder: (kind, ids) => http.post(`/${kind}/reorder`, { ids }),
  wgClientConfig: (peerId, split) =>
    http
      .get(`/wg/peers/${peerId}/config`, { params: split ? { split: 1 } : {} })
      .then((r) => r.data),
  wgRekey: (ifaceId) => http.post(`/interfaces/${ifaceId}/wg-rekey`, {}).then((r) => r.data),
  wgImport: (body) => http.post('/wg/import', body).then((r) => r.data),
  wgNextFree: (ifaceId) => http.get(`/interfaces/${ifaceId}/wg-next-free`).then((r) => r.data),
  // Start a deployed task, or the download of a deployed IP list, now.
  runTask: (id) => http.post(`/tasks/${id}/run`, {}).then((r) => r.data),
  refreshIPList: (id) => http.post(`/ip-lists/${id}/refresh`, {}).then((r) => r.data),
  // The next runs of a cron schedule ({ next: [...] } or { error }).
  schedulePreview: (schedule) =>
    http.get('/schedule/preview', { params: { schedule } }).then((r) => r.data),

  settings: () => http.get('/settings').then((r) => r.data),
  saveSettings: (body) => http.put('/settings', body).then((r) => r.data),
  // backup returns the axios response: data is a Blob, the file name is in
  // Content-Disposition.
  backup: (passphrase) => http.post('/backup', { passphrase }, { responseType: 'blob' }),
  // data is the backup file, base64 encoded.
  restore: (data, passphrase) =>
    http.post('/backup/restore', { data, passphrase }).then((r) => r.data),
  users: () => http.get('/users').then((r) => r.data),
  createUser: (username, password, role) =>
    http.post('/users', { username, password, role }).then((r) => r.data),
  // Changing a user's role ends their sessions.
  setUserRole: (id, role) => http.put(`/users/${id}`, { role }).then((r) => r.data),
  // Setting a user's password ends their sessions.
  setUserPassword: (id, password) => http.post(`/users/${id}/password`, { password }),
  deleteUser: (id) => http.delete(`/users/${id}`),
  // A role's members are [{ user_id, level }]; saving replaces them.
  roles: () => http.get('/roles').then((r) => r.data),
  createRole: (body) => http.post('/roles', body).then((r) => r.data),
  updateRole: (id, body) => http.put(`/roles/${id}`, body).then((r) => r.data),
  deleteRole: (id) => http.delete(`/roles/${id}`),

  // instances: the names to deploy; empty is everything the user may.
  deployCheck: (instances = []) =>
    http
      .get('/deploy/check', { params: instances.length ? { instances: instances.join(',') } : {} })
      .then((r) => r.data),
  deployChanges: () => http.get('/deploy/changes').then((r) => r.data),
  deployPreview: (instances = []) =>
    http.post('/deploy/preview', { instances }).then((r) => r.data),
  // from: 'live' (deployed) or '' (what a commit would load).
  exportNftables: (instance, from = '') =>
    http.get('/deploy/nftables', { params: { instance, from }, responseType: 'blob' }),
  importNftables: (body) => http.post('/import/nftables', body).then((r) => r.data),
  deployApply: (confirmTimeout, instances = []) =>
    http.post('/deploy/apply', { confirm_timeout: confirmTimeout, instances }).then((r) => r.data),
  deployConfirm: () => http.post('/deploy/confirm', {}).then((r) => r.data),
  deployRollback: () => http.post('/deploy/rollback', {}).then((r) => r.data),
  deployRevert: () => http.post('/deploy/revert', {}).then((r) => r.data),
  deployments: () => http.get('/deployments').then((r) => r.data),
  agentStatus: () => http.get('/agent/status').then((r) => r.data),
  agentLeases: () => http.get('/agent/leases').then((r) => r.data),
  agentNeighbours: () => http.get('/agent/neighbours').then((r) => r.data),
  agentRoutingTable: () => http.get('/agent/routing-table').then((r) => r.data),
  agentBgp: () => http.get('/agent/bgp').then((r) => r.data),
  agentOspf: () => http.get('/agent/ospf').then((r) => r.data),
  agentVrrp: () => http.get('/agent/vrrp').then((r) => r.data),
  agentBfd: () => http.get('/agent/bfd').then((r) => r.data),
  agentRuleCounters: () => http.get('/agent/rule-counters').then((r) => r.data),
  agentLogs: (after) => http.get('/agent/logs', { params: { after } }).then((r) => r.data),
  agentPacketLog: (after) =>
    http.get('/agent/packet-log', { params: { after } }).then((r) => r.data),
  agentDnsQueryLog: (after) =>
    http.get('/agent/dns-query-log', { params: { after } }).then((r) => r.data),

  // Updates of the firewall's Debian and of Portitor (UpdatesPage).
  system: () => http.get('/system').then((r) => r.data),
  systemJob: (job, release) => http.post('/system/jobs', { job, release }).then((r) => r.data),
  systemReboot: () => http.post('/system/reboot', {}).then((r) => r.data),
}
