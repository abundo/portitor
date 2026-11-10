<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import CrudPage from '@/components/CrudPage.vue'
import DhcpClientLease from '@/components/DhcpClientLease.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { computed, ref } from 'vue'
import { config, path, vfApi, vfPath } from '@/api/config'
import http, { errMsg } from '@/api/http'
import { useToast } from '@nuxt/ui/composables'
import { useStatusRefresh } from '@/composables/useAutoRefresh'
import { useInstanceRefs, withLabel } from '@/composables/useInstanceRefs'
import { useAuthStore } from '@/stores/auth'
import { useDeployStore } from '@/stores/deploy'
import { bytes } from '@/utils/bytes'
import { formatMac } from '@/utils/mac'
import { useSearch } from '@/utils/search'

const { store, ifaceList, vrfList, ifaceText, zonesOf, reload } = useInstanceRefs()
const deploy = useDeployStore()
const auth = useAuthStore()
const isMissing = (row) =>
  row.kind === 'physical' &&
  deploy.missingNics.some((n) => n.name === row.name && n.instance === store.current?.name)
// The MAC address the firewall reports; a physical port not yet moved into
// the instance is looked up among all NICs.
function macOf(row) {
  const inst = deploy.status?.instances?.find((i) => i.name === store.current?.name)
  const mac = inst?.interfaces?.find((i) => i.name === row.name)?.mac
  if (mac || row.kind !== 'physical') return mac ?? ''
  return deploy.status?.nics?.find((n) => n.name === row.name)?.mac ?? ''
}

const kinds = [
  { label: 'Physical', value: 'physical' },
  { label: 'VLAN', value: 'vlan' },
  { label: 'Bridge', value: 'bridge' },
  { label: 'WireGuard', value: 'wireguard' },
  { label: 'Loopback', value: 'loopback' },
  { label: '6in4 tunnel (Hurricane Electric)', value: '6in4' },
  { label: 'VXLAN', value: 'vxlan' },
  { label: 'OpenVPN server', value: 'openvpn' },
]
const is6in4 = (f) => f.kind === '6in4'
const isVxlan = (f) => f.kind === 'vxlan'
// LLDP runs on the ethernet kinds.
const lldpKinds = ['physical', 'vlan', 'bridge', 'vxlan']
const modes = [
  { label: 'Static', value: 'static' },
  { label: 'DHCP client', value: 'dhcp' },
  { label: 'None', value: 'none' },
]

const columns = [
  { key: 'name', label: 'Interface', class: 'font-mono font-medium' },
  { key: 'label', label: 'Label', class: 'font-medium' },
  {
    key: 'kind',
    label: 'Kind',
    format: (r) =>
      r.kind === 'vlan'
        ? `vlan ${r.vlan_id} on ${ifaceText(r.parent)}`
        : r.kind === '6in4'
          ? `6in4 to ${r.tunnel_remote}`
          : r.kind === 'vxlan'
            ? `vxlan ${r.vxlan_vni}${r.vxlan_device ? ` on ${ifaceText(r.vxlan_device)}` : ''}`
            : r.kind,
  },
  { key: 'mac', label: 'MAC', class: 'font-mono text-xs', format: (r) => formatMac(macOf(r)) },
  { key: 'zones', label: 'Zones', format: (r) => zonesOf(r.name).join(', ') },
  { key: 'vrf', label: 'VRF', class: 'font-mono' },
  { key: 'ipv4_mode', label: 'IPv4', format: (r) => (is6in4(r) ? '' : r.ipv4_mode) },
  { key: 'broker', label: 'Endpoint update' },
  { key: 'addresses', label: 'Addresses' },
  { key: 'enabled', label: 'Up' },
  { key: 'description', label: 'Description' },
]

// Other interfaces of the instance, as items that show their labels, for a
// VLAN's parent and a bridge's members; a name the form holds but the
// instance lacks stays listed.
function otherIfaces(f, keep = []) {
  const names = ifaceList.value.filter((i) => i.name !== f.id).map((i) => i.name)
  return [...new Set([...names, ...keep.filter(Boolean)])].map((n) => ({
    label: ifaceText(n),
    value: n,
  }))
}

// Interfaces are in the configuration tree, under their virtual firewall;
// _instance, the form's choice of it, moves one to another (move-to) once
// it is saved.
const ifaceApi = vfApi('interface')
const here = () => store.currentName
const interfaces = {
  ...ifaceApi,
  list: async () => (await ifaceApi.list()).map((r) => ({ ...r, _instance: here() })),
  create: async (r) => {
    const made = await ifaceApi.create(r)
    await moveTo(made, r._instance)
    return made
  },
  update: async (id, r) => {
    const saved = await ifaceApi.update(id, r)
    await moveTo(saved, r._instance)
    return saved
  },
}
async function moveTo(row, instance) {
  if (instance && instance !== here())
    await config.action(`${vfPath()}/${path(['interface', row.name])}`, 'move-to', { instance })
}

const fields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'eth0',
    hint: 'The Linux interface name.',
  },
  {
    key: 'label',
    label: 'Label',
    placeholder: 'WAN',
    hint: 'A short name shown before the interface name wherever an interface is picked: WAN (ens18).',
  },
  {
    key: '_instance',
    label: 'Virtual firewall',
    type: 'select',
    items: () => store.list.map((i) => ({ label: i.name, value: i.name })),
    show: () => store.list.length > 1,
    hint: 'Changing it moves the interface to that virtual firewall, with its addresses. Its rules, routes and VLANs must go first; it leaves its interface zones.',
  },
  { key: 'kind', label: 'Kind', type: 'select', items: kinds, disabled: (f) => !!f.id },
  { key: 'description', label: 'Description' },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  {
    key: 'ha_role',
    label: 'HA role',
    type: 'select',
    items: [
      { value: '', label: 'Traffic' },
      { value: 'ha_link', label: 'HA link' },
      { value: 'management', label: 'Management' },
    ],
    show: (f) => f.kind === 'physical' && !!store.current?.is_default,
    hint: "An HA pair needs both: the HA link, a direct cable between the hosts, and the management interface, on a network of its own with the witness. They stay up on the standby, with an address for each host. Traffic interfaces are the same on both hosts, and closed on the standby.",
  },
  {
    key: 'ha_monitor',
    label: 'HA monitor',
    type: 'switch',
    show: (f) => f.kind === 'physical' && !f.ha_role,
    hint: 'On an HA pair, counts this interface: when the standby has more monitored interfaces with a carrier for 2 s, the traffic moves to it. Turn it off for an interface a failover would not help.',
  },
  {
    key: 'ha_gateway',
    label: 'Management gateway',
    placeholder: '172.25.38.10',
    show: (f) => f.ha_role === 'management',
    hint: 'What the host itself uses while its traffic interfaces are closed. It must not be the pair: the standby reaches the witness and updates through it.',
  },
  {
    key: 'parent',
    label: 'Parent interface',
    type: 'select',
    items: (f) => otherIfaces(f, [f.parent]),
    show: (f) => f.kind === 'vlan',
  },
  { key: 'vlan_id', label: 'VLAN id', type: 'number', show: (f) => f.kind === 'vlan' },
  {
    key: 'members',
    label: 'Bridge members',
    type: 'multiselect',
    items: (f) => otherIfaces(f),
    show: (f) => f.kind === 'bridge',
  },
  {
    key: 'vrf',
    label: 'VRF',
    type: 'select',
    nullable: true,
    text: true,
    items: (f) =>
      [...new Set([...vrfList.value.map((v) => v.name), f.vrf].filter(Boolean))].map((n) => ({
        label: n,
        value: n,
      })),
    hint: 'The VRF (Routing → VRF) whose table routes this interface; — : the main table. Changing it moves the interface to that VRF. A bridge’s member goes with its bridge.',
  },
  {
    key: 'ipv4_mode',
    label: 'IPv4',
    type: 'select',
    items: (f) =>
      f.kind === 'wireguard' || f.kind === 'loopback' || f.kind === 'openvpn'
        ? modes.filter((m) => m.value !== 'dhcp')
        : modes,
    show: (f) => !is6in4(f),
    hint: 'Static: the addresses below. DHCP client: IPv4 from a DHCP server, and no addresses below.',
  },
  {
    key: 'dhcp_no_default_route',
    label: 'No default route from DHCP',
    type: 'switch',
    show: (f) => f.ipv4_mode === 'dhcp',
    hint: 'Ignore the router the DHCP server offers, e.g. on a LAN; the default route comes from the WAN.',
  },
  {
    key: 'addresses',
    label: 'IP addresses',
    type: 'tags',
    placeholder: '192.168.1.1/24',
    disabled: (f) => f.ipv4_mode === 'dhcp',
    show: (f) => !is6in4(f),
    hint: 'Addresses of the firewall on this interface with their prefix length, IPv4 and IPv6, as many as needed: 192.168.1.1/24, fd00:1::1/64. Their prefixes appear under Hosts & prefixes; DHCP and router advertisements are turned on for them under DHCP. An IPv6 address in the prefix delegated to another interface names it: <wan0>:2000::1/64 is subnet 2000 of the prefix wan0 gets, host ::1; its /64 is announced with router advertisements (SLAAC), and can get a DHCPv6 server under DHCP.',
  },
  {
    key: 'peer_addresses',
    label: 'HA peer addresses',
    type: 'tags',
    placeholder: '192.168.1.2/24',
    show: (f) => !!f.ha_role,
    hint: "The HA secondary's own addresses on this link, one for each address above in the same prefix and order. Traffic interfaces have the same addresses on both hosts.",
  },
  {
    key: 'addresses',
    label: 'IPv6 addresses',
    type: 'tags',
    placeholder: '2001:470:1f0a:12::2/64',
    show: is6in4,
    hint: "The firewall's end of the tunnel, with its prefix length (Client IPv6 Address). The routed prefixes go on LAN interfaces.",
  },
  {
    key: 'ipv6_accept_ra',
    label: 'IPv6 SLAAC (accept router advertisements)',
    type: 'switch',
    show: (f) => !is6in4(f),
  },
  {
    key: 'dhcpv6',
    label: 'DHCPv6 client',
    type: 'switch',
    show: (f) => !['wireguard', 'loopback', '6in4', 'openvpn'].includes(f.kind),
    hint: 'Ask a DHCPv6 server for an IPv6 address. Needs router advertisements accepted: the default route comes from them.',
  },
  {
    key: 'dhcpv6_pd',
    label: 'Prefix delegation',
    type: 'switch',
    show: (f) => f.dhcpv6,
    hint: 'Also ask for a delegated prefix, for the addresses of other interfaces written as <this interface>:subnet::host/64.',
  },
  {
    key: 'dhcpv6_pd_length',
    label: 'Delegated prefix length',
    type: 'number',
    show: (f) => f.dhcpv6 && f.dhcpv6_pd,
    hint: 'The prefix length to ask for, e.g. 56; 0 lets the server choose.',
  },
  {
    key: 'xlat464',
    label: '464XLAT',
    type: 'switch',
    show: (f) => f.kind !== 'loopback' && !is6in4(f),
    hint: 'For clients with a CLAT (Android, iOS, macOS), which reach IPv4 over IPv6 only: router advertisements on this interface announce the NAT64 prefix (Network → NAT64; PREF64), and its DHCPv4 tells them IPv4 is not needed (option 108, IPv6-only preferred). Needs router advertisements on the interface (DHCP).',
  },
  {
    key: 'mtu',
    label: 'MTU',
    type: 'number',
    hint: '0 keeps the default (1480 for a 6in4 tunnel, which must match the MTU set at tunnelbroker.net, Advanced tab).',
  },
  {
    key: 'lldp',
    label: 'LLDP',
    type: 'switch',
    show: (f) => lldpKinds.includes(f.kind),
    hint: 'Announce the firewall with LLDP on this interface and list the LLDP neighbours heard on it under Neighbours.',
  },
  {
    key: 'shape_egress',
    label: 'Shape upload (Mbit/s)',
    type: 'number',
    show: (f) => f.kind !== 'loopback',
    hint: 'Shapes what the interface sends with CAKE, a little below the line speed (95%), so the queue stays here instead of in the modem; 0 is off. When rules use a rate limit that shapes, an HTB tree at this rate replaces CAKE.',
  },
  {
    key: 'shape_ingress',
    label: 'Shape download (Mbit/s)',
    type: 'number',
    show: (f) => f.kind !== 'loopback',
    hint: 'Shapes what the interface receives (through an IFB device, ifb-<name>); 0 is off.',
  },
  {
    key: 'mss_clamp',
    label: 'Clamp TCP MSS',
    type: 'switch',
    show: (f) => f.kind !== 'loopback',
    hint: 'Lowers the maximum segment size in the TCP handshakes forwarded through this interface, so connections never send packets too big for it: for tunnels (WireGuard, 6in4, OpenVPN) and uplinks with a smaller MTU (PPPoE, 1492), where path MTU discovery fails when ICMP is filtered on the way. The MSS is only ever lowered.',
  },
  {
    key: 'mss_clamp_value',
    label: 'MSS',
    type: 'number',
    show: (f) => f.kind !== 'loopback' && f.mss_clamp,
    hint: "0 takes it from the MTU of the route out (and, coming in, this interface's MTU, when set or a tunnel's). Otherwise the IPv4 MSS, e.g. 1452 for PPPoE (IPv6 gets 20 less); 536-65495.",
  },
  {
    key: 'rpf',
    label: 'Reverse path check',
    type: 'switch',
    show: (f) => f.kind !== 'loopback',
    hint: "Drops packets that come in on this interface from a source the virtual firewall would not route back out of it (strict uRPF): spoofed sources. Leave it off where routing is asymmetric on purpose, such as a second uplink that isn't the default route or policy routes for incoming traffic. The Rules page shows what it dropped.",
  },
  { key: 'vxlan_heading', label: 'VXLAN', type: 'heading', show: isVxlan },
  {
    key: 'vxlan_vni',
    label: 'VNI',
    type: 'number',
    required: true,
    show: isVxlan,
    hint: 'The VXLAN network identifier (1-16777215), the same on every VTEP of the segment and unique in the virtual firewall.',
  },
  {
    key: 'vxlan_local',
    label: 'Local address',
    placeholder: '192.0.2.1',
    show: isVxlan,
    hint: "The firewall's VTEP address, the source of the VXLAN packets (an address of the virtual firewall, often a loopback's). EVPN and IPv6 remotes need it.",
  },
  {
    key: 'vxlan_device',
    label: 'Underlay interface',
    type: 'select',
    nullable: true,
    text: true,
    items: (f) => otherIfaces(f, [f.vxlan_device]),
    show: isVxlan,
    hint: 'The interface the VXLAN packets leave by, and the only one they are accepted on. — : as routed, accepted on any.',
  },
  {
    key: 'vxlan_port',
    label: 'UDP port',
    type: 'number',
    show: isVxlan,
    hint: '0 is the standard port, 4789.',
  },
  {
    key: 'vxlan_remotes',
    label: 'Remote VTEPs',
    type: 'tags',
    placeholder: '192.0.2.2',
    show: isVxlan,
    hint: "The other VTEPs' addresses: broadcast and unknown frames are sent to each. With EVPN (Routing → BGP) BGP finds the VTEPs, and this lists the ones allowed to send (empty: any). VXLAN packets from them are accepted automatically. Put the VXLAN in a bridge to join it to a LAN.",
  },
  { key: 'tunnel_heading', label: 'Tunnel', type: 'heading', show: is6in4 },
  {
    key: 'tunnel_remote',
    label: 'Server IPv4 address',
    required: true,
    placeholder: '216.66.80.90',
    show: is6in4,
    hint: "The tunnel server's IPv4 address (Server IPv4 Address on the tunnel's page at tunnelbroker.net). IPv6 in IPv4 (protocol 41) from and to it is accepted automatically.",
  },
  {
    key: 'tunnel_local',
    label: 'Local IPv4 address',
    placeholder: 'any',
    show: is6in4,
    hint: "The firewall's IPv4 address the tunnel uses. Empty (any) for an address from DHCP, or behind NAT, where the router in front must forward protocol 41 to the firewall.",
  },
  {
    key: 'tunnel_default_route',
    label: 'IPv6 default route',
    type: 'switch',
    show: is6in4,
    hint: 'Route IPv6 (::/0) through the tunnel, with metric 512: a static ::/0 under Routing → Static (metric 0) still wins, one from router advertisements (1024) loses.',
  },
  {
    key: 'broker_heading',
    label: 'Hurricane Electric tunnel broker',
    type: 'heading',
    show: is6in4,
  },
  {
    key: 'he_tunnel_id',
    label: 'Tunnel ID',
    placeholder: '123456',
    show: is6in4,
    hint: "Tells tunnelbroker.net the firewall's IPv4 address whenever it changes, so the tunnel follows a dynamic address. Empty turns it off. The Tunnel ID is on the tunnel's page.",
  },
  {
    key: 'he_username',
    label: 'User name',
    show: (f) => is6in4(f) && !!f.he_tunnel_id,
    hint: 'The tunnelbroker.net account’s user name.',
  },
  {
    key: 'new_he_update_key',
    label: 'Update key',
    type: 'password',
    show: (f) => is6in4(f) && !!f.he_tunnel_id,
    hint: "The tunnel's Update Key (Advanced tab). Stored on the server, never shown again; leave empty to keep the stored key.",
  },
  {
    key: 'ovpn_note',
    label: 'The OpenVPN server (port, certificate, logins) is set up under VPN → OpenVPN.',
    type: 'heading',
    show: (f) => f.kind === 'openvpn',
  },
  {
    key: 'wg_listen_port',
    label: 'WireGuard listen port',
    type: 'number',
    show: (f) => f.kind === 'wireguard',
    hint: 'Opened automatically in the firewall. 0 for outgoing-only tunnels.',
  },
  {
    key: 'wg_endpoint',
    label: 'Public endpoint for clients',
    placeholder: 'vpn.example.org:51820',
    show: (f) => f.kind === 'wireguard',
    hint: 'host:port written into generated client configs. Empty: the public endpoint host (WireGuard page) and the listen port.',
  },
  {
    key: 'wg_keepalive',
    label: 'Client keepalive (seconds)',
    type: 'number',
    show: (f) => f.kind === 'wireguard',
    hint: 'PersistentKeepalive in generated client configs; 0 disables it.',
  },
]

// The DHCP client's lease on the interface, if it runs one: DHCPv4
// (family '') or DHCPv6.
function leaseOf(row, family = '') {
  if (family === '' ? row.ipv4_mode !== 'dhcp' : !row.dhcpv6) return null
  return (
    deploy.status?.dhcp_client_leases?.find(
      (l) =>
        l.instance === store.current?.name &&
        l.interface === row.name &&
        (l.family ?? '') === family,
    ) ?? null
  )
}

// Asks the agent's DHCP (family '') or DHCPv6 client on the interface to
// renew its lease now; the new lease shows with the next status poll.
const toast = useToast()
const renewing = ref('')
async function renew(row, family = '') {
  const key = `${row.name}/${family}`
  renewing.value = key
  try {
    await http.post('/agent/dhcp/renew', {
      instance: store.current?.name,
      interface: row.name,
      family,
    })
    toast.add({
      title: `${family ? 'DHCPv6' : 'DHCP'} renew sent on ${withLabel(row.label, row.name)}`,
      color: 'info',
    })
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    if (renewing.value === key) renewing.value = ''
  }
}

// The agent's status (state, MAC, leases, statistics), refreshed every 5 s
// on the page and in the Statistics dialog.
const { auto, loading } = useStatusRefresh()

// Interface statistics as the firewall reports them, for the Statistics
// dialog.
const statsOpen = ref(false)
const statsRows = computed(() => {
  const inst = deploy.status?.instances?.find((i) => i.name === store.current?.name)
  return (inst?.interfaces ?? [])
    .map((i) => ({ ...i, label: ifaceText(i.name) }))
    .sort((a, b) => a.name.localeCompare(b.name))
})
// The counters, received then sent; bad ones show in warning colour when
// not zero.
const statsCols = [
  { key: 'rx_bytes', label: 'Bytes', bytes: true, first: true },
  { key: 'rx_packets', label: 'Packets' },
  { key: 'rx_errors', label: 'Errors', bad: true },
  { key: 'rx_dropped', label: 'Dropped', bad: true },
  { key: 'rx_over_errors', label: 'Overruns', bad: true },
  { key: 'rx_multicast', label: 'Multicast' },
  { key: 'tx_bytes', label: 'Bytes', bytes: true, first: true },
  { key: 'tx_packets', label: 'Packets' },
  { key: 'tx_errors', label: 'Errors', bad: true },
  { key: 'tx_dropped', label: 'Dropped', bad: true },
  { key: 'tx_carrier_errors', label: 'Carrier', bad: true },
  { key: 'tx_collisions', label: 'Collisions', bad: true },
]
// The agent's endpoint updating of a 6in4 tunnel, if it has an account.
function brokerOf(row) {
  return (
    deploy.status?.tunnel_broker?.find(
      (t) => t.instance === store.current?.name && t.interface === row.name,
    ) ?? null
  )
}
const stateColor = { ok: 'success', error: 'error', pending: 'neutral', 'dry-run': 'neutral' }

const count = (n) => (n ?? 0).toLocaleString()
const { search: statsSearch, filtered: statsFiltered } = useSearch(statsRows)
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="Interfaces"
      description="Physical ports, VLANs, bridges, loopbacks, WireGuard, 6in4 tunnels (such as Hurricane Electric's tunnel broker) and VXLANs of this virtual firewall."
      :api="interfaces"
      :params="{ _vf: store.currentName }"
      :columns="columns"
      :fields="fields"
      :item-name="(r) => `interface ${withLabel(r.label, r.name)}`"
      :search-text="
        (r) => [brokerOf(r)?.address, brokerOf(r)?.last_error].filter(Boolean).join(' ')
      "
      :defaults="{
        _instance: store.currentName,
        kind: 'physical',
        label: '',
        enabled: true,
        ha_monitor: true,
        ipv4_mode: 'static',
        addresses: [],
        members: [],
        vrf: '',
        mtu: 0,
        vlan_id: 0,
        wg_listen_port: 0,
        wg_endpoint: '',
        wg_keepalive: 25,
        dhcpv6: false,
        dhcpv6_pd: false,
        dhcpv6_pd_length: 0,
        lldp: false,
        xlat464: false,
        shape_egress: 0,
        shape_ingress: 0,
        mss_clamp: false,
        mss_clamp_value: 0,
        rpf: false,
        tunnel_remote: '',
        tunnel_local: '',
        tunnel_default_route: true,
        he_tunnel_id: '',
        he_username: '',
        new_he_update_key: '',
        vxlan_vni: 0,
        vxlan_local: '',
        vxlan_device: '',
        vxlan_port: 0,
        vxlan_remotes: [],
      }"
      new-label="New interface"
      @changed="reload()"
    >
      <template #toolbar-end>
        <AutoRefreshButton :auto="auto" :loading="loading" />
        <UButton
          icon="i-lucide-chart-column"
          label="Statistics"
          color="neutral"
          variant="outline"
          @click="statsOpen = true"
        />
      </template>
      <template #cell-name="{ row }">
        <span class="font-mono font-medium">{{ row.name }}</span>
        <UTooltip v-if="isMissing(row)" text="Not found on the firewall">
          <UIcon name="i-lucide-triangle-alert" class="ml-1 align-middle text-warning" />
        </UTooltip>
      </template>
      <template #cell-addresses="{ row }">
        <div v-for="fam in ['', 'ipv6']" :key="fam" class="flex items-center gap-1">
          <DhcpClientLease
            :lease="leaseOf(row, fam)"
            :no-default-route="fam === '' && row.dhcp_no_default_route"
          />
          <UTooltip v-if="leaseOf(row, fam)" :text="fam ? 'Renew DHCPv6' : 'Renew DHCP'">
            <UButton
              icon="i-lucide-refresh-cw"
              color="neutral"
              variant="ghost"
              size="xs"
              :label="fam ? 'v6' : 'v4'"
              :loading="renewing === `${row.name}/${fam}`"
              :disabled="!auth.canEdit"
              @click.stop="renew(row, fam)"
            />
          </UTooltip>
        </div>
        <div v-for="a in row.addresses ?? []" :key="a" class="font-mono text-xs">
          {{ a }}
        </div>
      </template>
      <template #cell-broker="{ row }">
        <template v-if="is6in4(row)">
          <span v-if="!row.he_tunnel_id" class="text-muted">off</span>
          <span v-else-if="!brokerOf(row)" class="text-muted">not deployed</span>
          <div v-else class="space-y-0.5">
            <UBadge
              :label="brokerOf(row).state"
              :color="stateColor[brokerOf(row).state] ?? 'neutral'"
              variant="subtle"
              size="sm"
            />
            <span v-if="brokerOf(row).address" class="ml-1 font-mono text-xs">
              {{ brokerOf(row).address }}
            </span>
            <div v-if="brokerOf(row).last_error" class="text-xs text-error">
              {{ brokerOf(row).last_error }}
            </div>
          </div>
        </template>
      </template>
      <template #cell-enabled="{ row }">
        <UIcon
          :name="row.enabled ? 'i-lucide-circle-check' : 'i-lucide-circle-off'"
          :class="row.enabled ? 'text-success' : 'text-muted'"
        />
      </template>
    </CrudPage>
    <UModal
      v-model:open="statsOpen"
      title="Interface statistics"
      :dismissible="false"
      :ui="{
        content:
          'w-[calc(100vw-2rem)] max-w-none sm:max-w-none sm:w-[calc(100vw-4rem)] h-[calc(100dvh-2rem)] sm:h-[calc(100dvh-4rem)]',
        body: 'overflow-y-auto',
      }"
    >
      <template #body>
        <div class="space-y-3">
          <div class="flex items-center justify-between gap-3">
            <SearchInput v-model="statsSearch" />
            <AutoRefreshButton :auto="auto" :loading="loading" />
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm whitespace-nowrap">
              <thead class="text-muted">
                <tr>
                  <th colspan="4" />
                  <th colspan="6" class="border-l border-default px-2 py-1 text-center">
                    Received
                  </th>
                  <th colspan="6" class="border-l border-default px-2 py-1 text-center">Sent</th>
                </tr>
                <tr class="border-b border-default text-left">
                  <th class="px-2 py-1">Interface</th>
                  <th class="px-2 py-1">Kind</th>
                  <th class="px-2 py-1">State</th>
                  <th class="px-2 py-1">MTU</th>
                  <th
                    v-for="c in statsCols"
                    :key="c.key"
                    class="px-2 py-1 text-right"
                    :class="{ 'border-l border-default': c.first }"
                  >
                    {{ c.label }}
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="i in statsFiltered" :key="i.name" class="border-b border-default">
                  <td class="px-2 py-1 font-mono font-medium">{{ i.label }}</td>
                  <td class="px-2 py-1">{{ i.kind }}</td>
                  <td class="px-2 py-1">
                    <span :class="i.state === 'up' ? 'text-success' : 'text-muted'">
                      {{ i.state }}
                    </span>
                  </td>
                  <td class="px-2 py-1">{{ i.mtu }}</td>
                  <td
                    v-for="c in statsCols"
                    :key="c.key"
                    class="px-2 py-1 text-right font-mono"
                    :class="{
                      'border-l border-default': c.first,
                      'text-warning': c.bad && i[c.key],
                      'text-muted': !i[c.key],
                    }"
                  >
                    {{ c.bytes ? bytes(i[c.key] ?? 0) : count(i[c.key]) }}
                  </td>
                </tr>
                <tr v-if="!statsFiltered.length">
                  <td colspan="16" class="px-2 py-3 text-center text-muted">
                    {{
                      statsRows.length ? 'No matching interfaces.' : 'No status from the firewall.'
                    }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end">
          <UButton label="Close" color="neutral" variant="outline" @click="statsOpen = false" />
        </div>
      </template>
    </UModal>
  </NeedInstance>
</template>
