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

// reads returns list/get of a configuration table: the tree's read model
// (the configuration is written through /api/config, api/config.js).
export function reads(path) {
  return {
    list: (params) => http.get(path, { params }).then((r) => r.data ?? []),
    get: (id) => http.get(`${path}/${id}`).then((r) => r.data),
  }
}

export const firewalls = crud('/firewalls')
export const instances = reads('/instances')
export const interfaceZones = reads('/interface-zones')
export const interfaces = reads('/interfaces')
export const links = reads('/links')
export const routes = reads('/routes')
export const bgpPeerGroups = reads('/bgp/peer-groups')
export const bgpNeighbors = reads('/bgp/neighbors')
export const ospfInterfaces = reads('/ospf/interfaces')
export const isisInterfaces = reads('/isis/interfaces')
// VRFs of an instance (Routing → VRF).
export const vrfs = reads('/vrfs')
export const directoryServers = crud('/directory/servers')
export const directoryMappings = crud('/directory/mappings')
export const ipamPrefixes = reads('/ipam/prefixes')
export const certificates = reads('/certificates')
export const ipLists = reads('/ip-lists')

export const api = {
  // code: a TOTP or recovery code, for a user with two-factor login on (a
  // 401 with totp_required asks for it).
  login: (username, password, remember, code = '') =>
    http.post('/login', { username, password, remember, code }).then((r) => r.data),
  logout: () => http.post('/logout', {}),
  me: () => http.get('/me').then((r) => r.data),
  updateMe: (body) => http.put('/me', body).then((r) => r.data),
  changePassword: (current, next) => http.post('/me/password', { current, new: next }),
  // Two-factor login: setup makes a pending secret ({ secret, uri }), on once
  // enable checks a code from it; enable and recoveryCodes answer with new
  // recovery codes ({ recovery_codes }).
  totpStatus: () => http.get('/me/totp').then((r) => r.data),
  totpSetup: (password) => http.post('/me/totp/setup', { password }).then((r) => r.data),
  totpEnable: (code) => http.post('/me/totp/enable', { code }).then((r) => r.data),
  totpDisable: (password) => http.post('/me/totp/disable', { password }),
  recoveryCodes: (password) =>
    http.post('/me/totp/recovery-codes', { password }).then((r) => r.data),
  version: () => http.get('/version').then((r) => r.data),
  acmeCAs: () => http.get('/certificates/cas').then((r) => r.data ?? []),
  dnsProviders: () => http.get('/dyndns/providers').then((r) => r.data ?? []),

  ipamTree: (instanceId) =>
    http.get('/ipam/tree', { params: { instance_id: instanceId } }).then((r) => r.data),
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
  wgImport: (body) => http.post('/wg/import', body).then((r) => r.data),
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
  // createUser takes { username, full_name, email, password, role,
  // totp_required }.
  createUser: (body) => http.post('/users', body).then((r) => r.data),
  // updateUser sets { role, totp_required, full_name, email }; changing the
  // role ends their sessions.
  updateUser: (id, body) => http.put(`/users/${id}`, body).then((r) => r.data),
  // Setting a user's password ends their sessions.
  setUserPassword: (id, password) => http.post(`/users/${id}/password`, { password }),
  deleteUser: (id) => http.delete(`/users/${id}`),
  // Turns off another user's two-factor login.
  resetUserTotp: (id) => http.delete(`/users/${id}/totp`),
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
  // The HA pair: this portitor-config's place, the promotion of a
  // secondary, and the pair's witness string (its primary).
  haStatus: () => http.get('/ha').then((r) => r.data),
  haPromote: (force) => http.post('/ha/promote', { force }).then((r) => r.data),
  haSwitchover: (firewallId) =>
    http.post(`/firewalls/${firewallId}/switchover`).then((r) => r.data),
  witnessString: (firewallId) =>
    http.get(`/firewalls/${firewallId}/witness`).then((r) => r.data.witness),
  agentLeases: () => http.get('/agent/leases').then((r) => r.data),
  agentNeighbours: () => http.get('/agent/neighbours').then((r) => r.data),
  agentRoutingTable: () => http.get('/agent/routing-table').then((r) => r.data),
  agentBgp: () => http.get('/agent/bgp').then((r) => r.data),
  // vrf: the neighbour's VRF, '' for the main table.
  agentBgpRoutes: (instance, vrf, neighbor) =>
    http.get('/agent/bgp/routes', { params: { instance, vrf, neighbor } }).then((r) => r.data),
  agentBgpNeighbor: (instance, vrf, neighbor) =>
    http.get('/agent/bgp/neighbor', { params: { instance, vrf, neighbor } }).then((r) => r.data),
  agentOspf: () => http.get('/agent/ospf').then((r) => r.data),
  agentIsis: () => http.get('/agent/isis').then((r) => r.data),
  agentVrrp: () => http.get('/agent/vrrp').then((r) => r.data),
  agentBfd: () => http.get('/agent/bfd').then((r) => r.data),
  agentNtp: () => http.get('/agent/ntp').then((r) => r.data),
  // rsyslog and the journal of a firewall (firewall_id).
  agentSyslog: (firewallId) =>
    http.get('/agent/syslog', { params: { firewall_id: firewallId } }).then((r) => r.data),
  agentNat64: () => http.get('/agent/nat64').then((r) => r.data),
  agentOpenvpn: () => http.get('/agent/openvpn').then((r) => r.data),
  reorderDirectoryServers: (ids) => http.post('/directory/servers/reorder', { ids }),
  testDirectoryServer: (body) => http.post('/directory/servers/test', body).then((r) => r.data),
  browseDirectoryServer: (id, dn) =>
    http.get(`/directory/servers/${id}/browse`, { params: { dn } }).then((r) => r.data),
  agentRuleCounters: () => http.get('/agent/rule-counters').then((r) => r.data),
  agentRateLimits: () => http.get('/agent/rate-limits').then((r) => r.data),
  // The logs are one firewall's (firewall_id; null: the first).
  agentLogs: (after, firewall_id) =>
    http.get('/agent/logs', { params: { after, firewall_id } }).then((r) => r.data),
  agentPacketLog: (after, firewall_id) =>
    http.get('/agent/packet-log', { params: { after, firewall_id } }).then((r) => r.data),
  agentDnsQueryLog: (after, firewall_id) =>
    http.get('/agent/dns-query-log', { params: { after, firewall_id } }).then((r) => r.data),

  // Updates of a firewall's Debian and of Portitor (UpdatesPage); null is
  // the first firewall.
  system: (firewall_id) => http.get('/system', { params: { firewall_id } }).then((r) => r.data),
  systemJob: (job, release, firewall_id) =>
    http.post('/system/jobs', { job, release }, { params: { firewall_id } }).then((r) => r.data),
  systemReboot: (firewall_id) =>
    http.post('/system/reboot', {}, { params: { firewall_id } }).then((r) => r.data),
}
