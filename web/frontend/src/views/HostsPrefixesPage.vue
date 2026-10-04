<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// Hosts & prefixes: one tree of the named hosts and prefixes, the address
// lists, the IP lists and the instance's prefix tree (IPAM), each a
// top-level node. Hosts and address and IP lists can be sorted into folders
// (object_folders), which only structure the page.
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import ObjectTree from '@/components/ObjectTree.vue'
import DhcpLeasePicker from '@/components/DhcpLeasePicker.vue'
import HostDialog from '@/components/HostDialog.vue'
import IpListDialog from '@/components/IpListDialog.vue'
import AddressListDialog from '@/components/AddressListDialog.vue'
import FolderDialog from '@/components/FolderDialog.vue'
import SearchInput from '@/components/SearchInput.vue'
import {
  addressLists,
  addressObjects,
  api,
  ipamAddresses,
  ipamPrefixes,
  ipLists,
  objectFolders,
} from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useAuthStore } from '@/stores/auth'
import { useDeployStore } from '@/stores/deploy'
import { useObjectStore } from '@/stores/objects'
import { ago } from '@/utils/time'
import { useConfirm } from '@/composables/useConfirm'
import { useFormGuard } from '@/composables/useFormGuard'
import { inlineField, wideModal } from '@/utils/form'
import { matchesWords, searchWords, valuesText } from '@/utils/search'

const toast = useToast()
const router = useRouter()
const auth = useAuthStore()
const { confirmDelete } = useConfirm()
const { store, ifaceName, ifaceList } = useInstanceRefs()
const deploy = useDeployStore()
const objects = useObjectStore()
const hosts = ref([])
const addrLists = ref([])
const lists = ref([])
const folders = ref([])
const tree = ref([])
// Keys of the collapsed nodes: the top-level nodes (group:*), the folders
// (folder:<id>) and the prefixes (prefix:<cidr>). Not reactive: the tree
// folds itself, this only keeps the state when the nodes are built again.
const collapsed = new Set()
// Search: a host, IP list, folder, prefix or address matches when its row
// has every word typed. While searching, the rows that match are shown with
// the folders and prefixes above them, all open (the folded ones fold again
// once the search is cleared); a folder or prefix that matches shows all it
// holds.
const search = ref('')
const words = computed(() => searchWords(search.value))
const searching = computed(() => words.value.length > 0)
const loading = ref(true)
const infoOpen = ref(false)

const byName = (a, b) => a.name.localeCompare(b.name)
async function loadHosts() {
  hosts.value = (await addressObjects.list()).sort(byName)
}
async function loadAddrLists() {
  addrLists.value = (await addressLists.list()).sort(byName)
}
async function loadLists() {
  lists.value = (await ipLists.list()).sort(byName)
}
async function loadFolders() {
  folders.value = (await objectFolders.list()).sort(byName)
}
// The DHCP clients' leases: the tree lists them next to the static addresses.
const clientLeases = ref([])
async function loadTree() {
  if (!store.currentId) return
  const [t, leases, auto] = await Promise.all([
    api.ipamTree(store.currentId),
    api.agentLeases().catch(() => null),
    api.autoRules(store.currentId).catch(() => []),
  ])
  tree.value = t
  clientLeases.value = leases?.client ?? []
  autoRules.value = auto
}

// The sources of the auto input rules of BGP (its neighbours, TCP 179) and
// OSPF (OSPFv2's networks): nftables sets of their own (AutoRule.SourceSet,
// render.AutoSetName), shown read-only among the address lists. They come
// from the current configuration and are not rows: rules can't name them.
const autoRules = ref([])
const autoListDescriptions = {
  bgp_neighbours: 'BGP neighbours, allowed to TCP port 179',
  ospf_networks: 'OSPFv2 networks, allowed to send OSPF',
  ospf6_networks: 'OSPFv3 networks, allowed to send OSPF',
}
const autoLists = computed(() => {
  const out = []
  for (const r of autoRules.value) {
    if (!r.source_set || !r.source?.length) continue
    out.push({
      name: r.source_set,
      description: autoListDescriptions[r.source_set] ?? '',
      entries: [...r.source],
      auto: true,
    })
  }
  return out
})

// IPv4 prefix arithmetic, for placing the DHCP leases in the tree.
const v4num = (a) => a.split('.').reduce((n, o) => n * 256 + Number(o), 0)
const v4str = (n) => [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join('.')
function v4prefix(cidr) {
  const [a, bits] = cidr.split('/')
  const size = 2 ** (32 - Number(bits ?? 32))
  const start = Math.floor(v4num(a) / size) * size
  return { start, end: start + size - 1, cidr: `${v4str(start)}/${bits ?? 32}` }
}
const v4contains = (cidr, addr) => {
  if (cidr.includes(':')) return false
  const p = v4prefix(cidr)
  return addr >= p.start && addr <= p.end
}

// placeLease returns the deepest prefix of nodes that holds the address,
// null when none does, or 'listed' when the tree has the address already.
function placeLease(nodes, ip, n) {
  if (nodes.some((c) => c.kind === 'address' && c.cidr === ip)) return 'listed'
  const p = nodes.find((c) => c.kind === 'prefix' && v4contains(c.cidr, n))
  return p ? (placeLease(p.children, ip, n) ?? p) : null
}

// The tree with the DHCP client leases of the instance's interfaces:
// the address under the deepest prefix holding it, or under the lease's
// own prefix. These nodes (dhcp_lease) have no IPAM entry.
const shownTree = computed(() => {
  const nodes = JSON.parse(JSON.stringify(tree.value))
  for (const l of clientLeases.value) {
    if (l.instance !== store.current?.name || !l.address || l.address.includes(':')) continue
    const iface = ifaceList.value.find((i) => i.name === l.interface)
    if (!iface) continue
    const [ip] = l.address.split('/')
    const n = v4num(ip)
    const addrNode = {
      kind: 'address',
      id: 0,
      auto: true,
      dhcp_lease: true,
      cidr: ip,
      description: `DHCP lease (${l.state})`,
      interface_id: iface.id,
      used_frac: 0,
      children: [],
    }
    const place = placeLease(nodes, ip, n)
    if (place === 'listed') continue
    if (place) {
      place.children.push(addrNode)
      continue
    }
    const pfx = v4prefix(l.address)
    const prefixNode = {
      kind: 'prefix',
      id: 0,
      auto: true,
      dhcp_lease: true,
      cidr: pfx.cidr,
      description: 'from a DHCP lease',
      interface_id: iface.id,
      used_frac: 0,
      children: [addrNode],
    }
    // Among the top-level IPv4 prefixes by address; IPv6 ones follow.
    const at = nodes.findIndex(
      (c) => c.cidr.includes(':') || (c.kind === 'prefix' && v4prefix(c.cidr).start > pfx.start),
    )
    nodes.splice(at < 0 ? nodes.length : at, 0, prefixNode)
  }
  return nodes
})

// The tree as the search finds it: a node that matches, with all it
// holds, or one holding a node that matches.
function nodeText(n) {
  return valuesText(
    n.cidr,
    n.description,
    n.dns_name,
    n.interface_id ? ifaceName(n.interface_id) : '',
    n.mac,
  )
}
function pruneTree(nodes) {
  return nodes.flatMap((n) => {
    if (matchesWords(nodeText(n), words.value)) return [n]
    const children = pruneTree(n.children)
    return children.length ? [{ ...n, children }] : []
  })
}
const foundTree = computed(() => (searching.value ? pruneTree(shownTree.value) : shownTree.value))
onMounted(async () => {
  deploy.refresh()
  try {
    await Promise.all([loadHosts(), loadAddrLists(), loadLists(), loadFolders(), loadTree()])
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    loading.value = false
  }
})

const showError = (err) => toast.add({ title: errMsg(err), color: 'error' })
// Hosts and address and IP lists are also offered in address fields (the
// object store).
function reloadHosts() {
  loadHosts().catch(showError)
  objects.load(true).catch(() => {})
}
function reloadAddrLists() {
  loadAddrLists().catch(showError)
  objects.load(true).catch(() => {})
}
function reloadLists() {
  loadLists().catch(showError)
  objects.load(true).catch(() => {})
}
function reloadFolders() {
  loadFolders().catch(showError)
}
function reloadTree() {
  loadTree().catch(showError)
}

const hostDialog = ref(null)
const addrListDialog = ref(null)
const listDialog = ref(null)
const folderDialog = ref(null)

// The nodes of the Hosts or IP lists group: in each folder its folders,
// then its items, both by name. count is the items a folder holds, those
// in its folders included. While searching, only the items that match
// (text(item)) and the folders holding them; a folder whose name matches
// keeps all it holds.
function folderNodes(kind, items, text, itemNode) {
  const parent = (x) => x.parent_id ?? 0
  const subfolders = (id) => folders.value.filter((f) => f.kind === kind && parent(f) === id)
  const count = (id) =>
    items.filter((i) => (i.folder_id ?? 0) === id).length +
    subfolders(id).reduce((n, f) => n + count(f.id), 0)
  const hit = (t) => matchesWords(t, words.value)
  const holdsHit = (id) =>
    items.some((i) => (i.folder_id ?? 0) === id && hit(text(i))) ||
    subfolders(id).some((f) => hit(f.name) || holdsHit(f.id))
  // all: show everything in the folder (not searching, or it matches).
  const walk = (id, all) => [
    ...subfolders(id).flatMap((f) => {
      const fAll = all || hit(f.name)
      if (!fAll && !holdsHit(f.id)) return []
      const key = `folder:${f.id}`
      return [
        {
          key,
          title: f.name,
          icon: icon('folder', 'text-primary'),
          expanded: isOpen(key),
          children: walk(f.id, fAll),
          cells: { description: badge(String(count(f.id))) },
          item: { type: 'folder', kind, obj: f },
        },
      ]
    }),
    ...items.filter((i) => (i.folder_id ?? 0) === id && (all || hit(text(i)))).map(itemNode),
  ]
  return walk(0, !searching.value)
}
const isOpen = (key) => searching.value || !collapsed.has(key)

// A host has only single addresses (/32, /128); anything else is a prefix.
const single = (a) => !a.includes('/') || a.endsWith('/32') || a.endsWith('/128')
const hostKind = (o) => (o.addresses?.length && o.addresses.every(single) ? 'host' : 'prefix')
const versions = (o) => {
  const v6 = o.addresses?.some((a) => a.includes(':'))
  const v4 = o.addresses?.some((a) => !a.includes(':'))
  return v4 && v6 ? 'IPv4 + IPv6' : v6 ? 'IPv6' : 'IPv4'
}

// What the agent reports for each deployed IP list, by name.
const states = computed(() =>
  Object.fromEntries((deploy.status?.ip_lists ?? []).map((s) => [s.name, s])),
)
const stateColor = { ok: 'success', error: 'error', fetching: 'info' }
const sourceLabel = { crowdsec: 'CrowdSec LAPI', url: 'URL' }

// Whether the DNS server listens on the interface's addresses.
function dnsListen(id) {
  return !!ifaceList.value.find((i) => i.id === id)?.dns_listen
}

// The addresses the interface gets as a client: DHCP (IPv4), SLAAC (IPv6).
function ifaceClient(id) {
  const i = ifaceList.value.find((i) => i.id === id)
  return [...(i?.ipv4_mode === 'dhcp' ? ['dhcp'] : []), ...(i?.ipv6_accept_ra ? ['slaac'] : [])]
}

async function refreshList(row) {
  try {
    await api.refreshIPList(row.id)
    toast.add({ title: `Downloading @${row.name}`, color: 'info' })
    setTimeout(() => deploy.refresh(), 2000)
  } catch (err) {
    toast.add({ title: errMsg(err, 'Download failed to start'), color: 'error' })
  }
}

// ----- the tree (ObjectTree): nodes with their cells as HTML -----
const esc = (v) =>
  String(v ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  )
// Lucide icons (@iconify-json/lucide), inline: the tree's cells are HTML.
const svgPath = {
  server:
    '<rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><path d="M6 6h.01M6 18h.01"/>',
  network:
    '<rect width="6" height="6" x="16" y="16" rx="1"/><rect width="6" height="6" x="2" y="16" rx="1"/><rect width="6" height="6" x="9" y="2" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3m-7-4V8"/>',
  list: '<path d="M3 5h.01M3 12h.01M3 19h.01M8 5h13M8 12h13M8 19h13"/>',
  'list-x': '<path d="M16 5H3m8 7H3m13 7H3m12.5-9.5l5 5m0-5l-5 5"/>',
  folder:
    '<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>',
  dot: '<circle cx="12" cy="12" r="1"/>',
}
const icon = (name, cls = 'text-muted') =>
  `<i class="wb-icon ${cls}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${svgPath[name]}</svg></i>`
// A badge like UBadge's (subtle, or outline).
const badgeColor = {
  primary: 'bg-primary/10 text-primary ring-primary/25',
  success: 'bg-success/10 text-success ring-success/25',
  info: 'bg-info/10 text-info ring-info/25',
  error: 'bg-error/10 text-error ring-error/25',
  neutral: 'bg-elevated text-default ring-accented',
  outline: 'text-default ring-accented',
}
const badge = (label, color = 'neutral', title = '') =>
  `<span class="me-1 inline-flex items-center rounded-md px-1.5 py-0.5 text-xs font-medium ring ring-inset ${badgeColor[color]}"${title ? ` title="${esc(title)}"` : ''}>${esc(label)}</span>`
const muted = (text, cls = '') => `<span class="text-muted ${cls}">${esc(text)}</span>`

const columns = [
  { id: '*', title: 'Name', width: '320px', minWidth: '160px' },
  { id: 'description', title: 'Description', width: '*', minWidth: '120px' },
  { id: 'details', title: 'Addresses / source', width: '320px', minWidth: '100px' },
  { id: 'status', title: 'Status', width: '260px', minWidth: '100px' },
]

const empty = (key, text) => ({ key, title: text, icon: false, cells: {}, item: { type: 'empty' } })

function hostNode(o) {
  const kind = hostKind(o)
  return {
    key: `hosts:${o.id}`,
    title: o.name,
    icon: icon(kind === 'host' ? 'server' : 'network'),
    cells: {
      description: esc(o.description),
      details: `<span class="font-mono text-xs">${esc(o.addresses?.join(', '))}</span>`,
      status: badge(kind, kind === 'host' ? 'primary' : 'neutral') + muted(versions(o), 'text-xs'),
    },
    item: { type: 'host', obj: o },
  }
}

function addrListNode(l) {
  return {
    key: `address_lists:${l.id}`,
    title: l.name,
    icon: icon('list'),
    cells: {
      description: esc(l.description),
      details: `<span class="font-mono text-xs">${esc(l.entries?.join(', '))}</span>`,
      status: badge(`${l.entries?.length ?? 0} entries`, 'neutral'),
    },
    item: { type: 'addrlist', obj: l },
  }
}

function autoListNode(l) {
  return {
    key: `auto_lists:${l.name}`,
    title: l.name,
    icon: icon('lock'),
    cells: {
      description: esc(l.description),
      details: `<span class="font-mono text-xs">${esc(l.entries.join(', '))}</span>`,
      status:
        badge('auto', 'info', 'From the configuration; read-only') +
        badge(`${l.entries.length} entries`, 'neutral'),
    },
    item: { type: 'autolist', obj: l },
  }
}

function listStatus(l) {
  const s = states.value[l.name]
  if (!s) return muted('not deployed', 'text-xs')
  let html = badge(s.state, stateColor[s.state] ?? 'neutral', s.last_error)
  if (s.updated) {
    html += `<span class="text-xs">${s.ipv4} IPv4, ${s.ipv6} IPv6</span>`
    if (s.skipped) html += muted(` (${s.skipped} skipped)`, 'text-xs')
    html += muted(` · ${ago(s.updated)}`, 'text-xs')
  }
  if (s.last_error)
    html += ` <span class="text-xs text-error" title="${esc(s.last_error)}">${esc(s.last_error)}</span>`
  return html
}

function listNode(l) {
  return {
    key: `ip_lists:${l.id}`,
    title: `@${l.name}`,
    icon: icon('list'),
    cells: {
      description: esc(l.description),
      details: `<span class="text-xs">${esc(sourceLabel[l.source] ?? l.source)}</span> ${muted(l.url, 'font-mono text-xs')}`,
      status: listStatus(l),
    },
    item: { type: 'list', obj: l },
  }
}

// The badges of a prefix or address of the IPAM tree.
function ipamBadges(n) {
  let html = ''
  const id = n.interface_id
  if (id) html += badge(ifaceName(id), 'primary')
  if (n.kind === 'address' && id) {
    const dns = dnsListen(id)
    if (dns) html += badge('DNS', 'success', 'The DNS server listens on this address')
    const client = ifaceClient(id)
    if (client.includes('dhcp'))
      html += badge(
        'DHCP Client',
        'neutral',
        'The interface also gets an IPv4 address from a DHCP server',
      )
    if (client.includes('slaac'))
      html += badge(
        'SLAAC-C',
        'neutral',
        'The interface also takes an IPv6 address from router advertisements',
      )
  }
  if (n.zone_id)
    html += badge(
      n.cidr.includes(':') ? 'AAAA' : 'A',
      'neutral',
      'A DNS zone has an A or AAAA record for this address',
    )
  if (n.mac) html += badge(`reserved ${n.mac}`, 'outline')
  if (n.dhcp_enabled) {
    const on = !!store.current?.dhcp_enabled
    html += badge(
      'DHCP server',
      on ? 'success' : 'neutral',
      (on ? '' : "Set to serve DHCP, but the virtual firewall's DHCP server is disabled. ") +
        (n.dhcp_range ? `Range ${n.dhcp_range}` : 'No range: fixed leases only'),
    )
  }
  if (n.ra_slaac)
    html += badge('SLAAC', 'info', 'Router advertisements let clients pick their own address')
  else if (n.ra_enabled)
    html += badge('RA', 'info', 'Router advertisements are sent for this prefix')
  return html
}

function ipamNode(n) {
  const key = `${n.kind}:${n.cidr}`
  let description = esc(n.description)
  if (n.dns_name) description += ` ${muted(n.dns_name, 'font-mono text-xs')}`
  if (n.auto && !n.description && !n.dns_name)
    description = muted(
      n.kind === 'prefix' ? 'from an interface address' : 'interface address',
      'text-xs',
    )
  const pct = Math.round(n.used_frac * 100)
  return {
    key,
    title: n.cidr,
    icon: n.kind === 'prefix' ? icon('network', 'text-primary') : icon('dot'),
    expanded: isOpen(key),
    children: n.children.map(ipamNode),
    cells: {
      description,
      details: ipamBadges(n),
      status:
        n.kind === 'prefix'
          ? `<span class="inline-flex items-center gap-2"><span class="inline-block h-1.5 w-16 overflow-hidden rounded-full bg-accented"><span class="block h-full bg-primary" style="width:${pct}%"></span></span>${muted(`${pct}%`, 'text-xs tabular-nums')}</span>`
          : '',
    },
    item: { type: 'ipam', obj: n },
  }
}

function groupNode(key, title, iconName, count, description, children) {
  return {
    key,
    title,
    icon: icon(iconName, 'text-primary'),
    expanded: isOpen(key),
    children,
    cells: {
      description:
        (count !== undefined ? badge(String(count)) : '') + muted(description, 'text-xs'),
    },
    item: { type: 'group', key },
  }
}

function ipamEmpty() {
  if (searching.value && shownTree.value.length) return 'No prefix or address matches.'
  if (store.currentId) return 'No prefixes yet: give an interface an address, or add a prefix.'
  return 'No virtual firewall yet: create one under Virtual firewalls.'
}

// The top-level nodes of the tree.
const treeSource = computed(() => {
  const hostChildren = folderNodes(
    'hosts',
    hosts.value,
    (o) => valuesText(o.name, o.description, o.addresses, hostKind(o), versions(o)),
    hostNode,
  )
  const addrListChildren = folderNodes(
    'address_lists',
    addrLists.value,
    (l) => valuesText(l.name, l.description, l.entries),
    addrListNode,
  )
  addrListChildren.push(
    ...autoLists.value
      .filter(
        (l) =>
          !searching.value ||
          matchesWords(valuesText(l.name, l.description, l.entries, 'auto'), words.value),
      )
      .map(autoListNode),
  )
  const listChildren = folderNodes(
    'ip_lists',
    lists.value,
    (l) =>
      valuesText(
        `@${l.name}`,
        l.description,
        sourceLabel[l.source] ?? l.source,
        l.url,
        states.value[l.name]?.state ?? 'not deployed',
        states.value[l.name]?.last_error,
      ),
    listNode,
  )
  const ipamChildren = foundTree.value.map(ipamNode)
  return [
    groupNode(
      'group:hosts',
      'Hosts',
      'server',
      hosts.value.length,
      'Named addresses, usable wherever addresses are entered',
      hostChildren.length
        ? hostChildren
        : [empty('empty:hosts', searching.value ? 'No host matches.' : 'No hosts yet.')],
    ),
    groupNode(
      'group:addrlists',
      'Address lists',
      'list',
      addrLists.value.length + autoLists.value.length,
      'Addresses, prefixes and hosts by name; an nftables set in rules',
      addrListChildren.length
        ? addrListChildren
        : [
            empty(
              'empty:addrlists',
              searching.value ? 'No address list matches.' : 'No address lists yet.',
            ),
          ],
    ),
    groupNode(
      'group:lists',
      'IP lists',
      'list-x',
      lists.value.length,
      'Downloaded address lists, used as @name in rules',
      listChildren.length
        ? listChildren
        : [empty('empty:lists', searching.value ? 'No IP list matches.' : 'No IP lists yet.')],
    ),
    groupNode(
      'group:prefixes',
      'Prefixes & IP addresses',
      'network',
      undefined,
      store.current ? `The prefix tree of virtual firewall ${store.current.name}` : '',
      ipamChildren.length ? ipamChildren : [empty('empty:prefixes', ipamEmpty())],
    ),
  ]
})

// While searching, everything is unfolded; the folds come back after.
function onToggle(key, expanded) {
  if (searching.value) return
  if (expanded) collapsed.delete(key)
  else collapsed.add(key)
}

// A click on a row opens its form.
function onOpen(data) {
  const r = data?.item
  if (r?.type === 'folder') folderDialog.value.edit(r.obj)
  else if (r?.type === 'host') hostDialog.value.edit(r.obj)
  else if (r?.type === 'addrlist') addrListDialog.value.edit(r.obj)
  else if (r?.type === 'autolist') addrListDialog.value.edit(r.obj, { readonly: true })
  else if (r?.type === 'list') listDialog.value.edit(r.obj)
  else if (r?.type === 'ipam') onEdit(r.obj)
}

function rowMenu(data) {
  const r = data?.item
  if (r?.type === 'group') return groupMenu(r.key)
  if (r?.type === 'folder') return folderMenu(r.kind, r.obj.id)
  if (r?.type === 'host') return folderMenu('hosts', r.obj.folder_id)
  if (r?.type === 'addrlist') return folderMenu('address_lists', r.obj.folder_id)
  if (r?.type === 'list') return listMenu(r.obj)
  if (r?.type === 'ipam') return nodeMenu(r.obj)
  return []
}

// ----- prefix modal -----
const prefixOpen = ref(false)
const prefix = reactive({})
const prefixGuard = useFormGuard(prefix, prefixOpen)
function editPrefix(src) {
  Object.keys(prefix).forEach((k) => delete prefix[k])
  Object.assign(prefix, {
    prefix: '',
    description: '',
    ...src,
  })
  prefixOpen.value = true
}
// DHCP and router advertisements are set on the DHCP page; the generic PUT
// keeps them.
async function savePrefix() {
  try {
    const body = {
      prefix: prefix.prefix,
      description: prefix.description,
      instance_id: store.currentId,
    }
    if (prefix.id) await ipamPrefixes.update(prefix.id, body)
    else await ipamPrefixes.create(body)
    prefixOpen.value = false
    reloadTree()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

// ----- address modal -----
const addrOpen = ref(false)
const addr = reactive({})
const addrGuard = useFormGuard(addr, addrOpen)
// The interface the address is configured on (from the tree), if any.
const addrIface = ref(null)
const leasePickerOpen = ref(false)
function editAddress(src, ifaceId = null) {
  Object.keys(addr).forEach((k) => delete addr[k])
  Object.assign(addr, {
    address: '',
    description: '',
    dns_name: '',
    mac: '',
    ...src,
  })
  addrIface.value = ifaceId
  addrOpen.value = true
}
async function saveAddress() {
  try {
    const body = { ...addr, instance_id: store.currentId }
    if (addr.id) await ipamAddresses.update(addr.id, body)
    else await ipamAddresses.create(body)
    addrOpen.value = false
    reloadTree()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

async function onAddAddress(node) {
  let next = ''
  if (!node.auto) {
    try {
      next = await api.nextFree(node.id)
    } catch {
      // full; leave empty
    }
  }
  editAddress({ address: next })
}
function onAddPrefix(node) {
  editPrefix({ prefix: node.cidr })
}
// ----- context menu (right click on a row): the adds -----
const menuItems = ref([])
// The row's handler runs before the UContextMenu's: a row with nothing to
// add (or a viewer) stops the event and gets the browser's own menu.
function openMenu(event, items) {
  if (!items.length) {
    event.stopPropagation()
    return
  }
  menuItems.value = items
}
const addHost = (folderId) => ({
  label: 'Add host',
  icon: 'i-lucide-plus',
  onSelect: () => hostDialog.value.edit({ folder_id: folderId }),
})
const addAddrList = (folderId) => ({
  label: 'Add address list',
  icon: 'i-lucide-plus',
  onSelect: () => addrListDialog.value.edit({ folder_id: folderId }),
})
const addList = (folderId) => ({
  label: 'Add IP list',
  icon: 'i-lucide-plus',
  onSelect: () => listDialog.value.edit({ folder_id: folderId }),
})
const addFolder = (kind, parentId) => ({
  label: 'Add folder',
  icon: 'i-lucide-folder-plus',
  onSelect: () => folderDialog.value.edit({ kind, parent_id: parentId }),
})
// A folder's menu adds into it; an item's adds next to it (its folder).
function folderMenu(kind, folderId = null) {
  if (!auth.isAdmin) return []
  const add = { hosts: addHost, address_lists: addAddrList, ip_lists: addList }[kind]
  return [[add(folderId), addFolder(kind, folderId)]]
}
function listMenu(item) {
  if (!auth.isAdmin) return []
  const menu = folderMenu('ip_lists', item.folder_id)
  const s = states.value[item.name]
  menu.unshift([
    {
      label: 'Download now',
      icon: 'i-lucide-refresh-cw',
      disabled: !s || s.state === 'fetching',
      onSelect: () => refreshList(item),
    },
  ])
  return menu
}
function groupMenu(key) {
  if (key === 'group:hosts') return folderMenu('hosts')
  if (key === 'group:addrlists') return folderMenu('address_lists')
  if (key === 'group:lists') return folderMenu('ip_lists')
  if (!store.currentId || !auth.canEdit) return []
  return [
    [
      { label: 'Add prefix', icon: 'i-lucide-git-branch-plus', onSelect: () => editPrefix({}) },
      { label: 'Add address', icon: 'i-lucide-plus', onSelect: () => editAddress({}) },
    ],
  ]
}
function nodeMenu(node) {
  if (node.kind !== 'prefix' || node.dhcp_lease || !auth.canEdit) return []
  return [
    [
      { label: 'Add address', icon: 'i-lucide-plus', onSelect: () => onAddAddress(node) },
      {
        label: 'Add sub-prefix',
        icon: 'i-lucide-git-branch-plus',
        onSelect: () => onAddPrefix(node),
      },
    ],
  ]
}

// An auto node has no IPAM entry yet: editing it creates one, for a
// description on a prefix, a DNS name or MAC on an address. An
// address that is there only for a zone's A/AAAA record opens the zone.
async function onEdit(node) {
  if (node.dhcp_lease) router.push('/dhcp')
  else if (node.auto && node.zone_id && !node.interface_id)
    router.push(`/dns/zones/${node.zone_id}`)
  else if (node.kind === 'prefix')
    editPrefix(node.auto ? { prefix: node.cidr } : await ipamPrefixes.get(node.id))
  else
    editAddress(
      node.auto ? { address: node.cidr } : await ipamAddresses.get(node.id),
      node.interface_id,
    )
}
async function removePrefix() {
  const ok = await confirmDelete(
    `prefix ${prefix.prefix}`,
    'Addresses inside stay; a prefix of an interface address stays listed, without its settings.',
  )
  if (!ok) return
  try {
    await ipamPrefixes.remove(prefix.id)
    prefixOpen.value = false
    reloadTree()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
async function removeAddress() {
  if (!(await confirmDelete(`address ${addr.address}`))) return
  try {
    await ipamAddresses.remove(addr.id)
    addrOpen.value = false
    reloadTree()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
</script>

<template>
  <div>
    <div class="card">
      <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div class="flex items-center gap-1.5">
            <div class="text-lg font-semibold">Hosts & prefixes</div>
            <UPopover
              v-model:open="infoOpen"
              mode="hover"
              :open-delay="100"
              :content="{ side: 'bottom', align: 'start' }"
            >
              <UButton
                size="xs"
                color="neutral"
                variant="ghost"
                icon="i-lucide-info"
                aria-label="About this page"
                @click="infoOpen = true"
              />
              <template #content>
                <div class="max-w-md space-y-2 p-3 text-sm text-muted">
                  <p>
                    <b>Hosts</b> are named addresses. Use the name wherever addresses are entered:
                    rules, NAT, routes, DNS, DHCP and WireGuard. A rule whose addresses include IPv4
                    and IPv6 is applied to both. Renaming updates every use; a name in use cannot be
                    deleted.
                  </p>
                  <p>
                    <b>Address lists</b> hold addresses, prefixes and the names of hosts and other
                    address lists, which they follow as they change. In a rule's source or
                    destination a list becomes an nftables set (one per IP version) in the virtual
                    firewall; anywhere else it is used like a host, by its addresses.
                  </p>
                  <p>
                    <b>IP lists</b> are address lists the firewall downloads: the ban decisions of a
                    CrowdSec engine, or any list with one address or prefix per line. Use a list as
                    @name in a rule's source or destination; it becomes an nftables set in each
                    virtual firewall whose rules use it, and matches IPv4 and IPv6. A list is
                    downloaded when it is first deployed and whenever a scheduled task says so; the
                    last download stays in force if a later one fails.
                  </p>
                  <p>
                    <b>Folders</b> sort hosts, address lists and IP lists; they mean nothing to the
                    firewall. Move an entry by choosing its folder in its form. Only an empty folder
                    can be deleted.
                  </p>
                  <p>
                    <b>Prefixes & IP addresses</b> nest by containment. The addresses of the
                    firewall's interfaces and their prefixes are listed automatically. DHCP and
                    router advertisements (SLAAC) are set per interface under DHCP; a prefix they
                    serve shows a badge. An address with a DNS name gets an A/AAAA record, and with
                    a MAC also a fixed DHCP lease. The A/AAAA records of the DNS zones are listed
                    under their prefix; editing one opens its zone. So is the address of an
                    interface that is a DHCP client, from its lease.
                  </p>
                </div>
              </template>
            </UPopover>
          </div>
          <p class="max-w-3xl text-sm text-muted">
            Named hosts and prefixes, address lists, downloaded IP lists, and the virtual firewall's
            prefixes and addresses with their DNS names. Click a row to open it; right-click it to
            add to it.
          </p>
        </div>
        <div v-if="auth.isAdmin || auth.canEdit" class="flex gap-2">
          <UButton
            v-if="auth.isAdmin"
            color="neutral"
            variant="outline"
            icon="i-lucide-plus"
            label="Host"
            @click="hostDialog.edit()"
          />
          <UButton
            v-if="auth.isAdmin"
            color="neutral"
            variant="outline"
            icon="i-lucide-plus"
            label="Address list"
            @click="addrListDialog.edit()"
          />
          <UButton
            v-if="auth.isAdmin"
            color="neutral"
            variant="outline"
            icon="i-lucide-plus"
            label="IP list"
            @click="listDialog.edit()"
          />
          <UButton
            v-if="auth.canEdit"
            icon="i-lucide-plus"
            label="Prefix"
            :disabled="!store.currentId"
            @click="editPrefix({})"
          />
        </div>
      </div>
      <div class="mb-2">
        <SearchInput v-model="search" />
      </div>
      <div v-if="loading" class="flex justify-center p-6">
        <UIcon name="i-lucide-loader-2" class="size-7 animate-spin" />
      </div>
      <UContextMenu v-else :items="menuItems">
        <ObjectTree
          :source="treeSource"
          :columns="columns"
          class="h-[calc(100vh-16rem)] min-h-96"
          @open="onOpen"
          @menu="(e, data) => openMenu(e, rowMenu(data))"
          @toggle="onToggle"
        />
      </UContextMenu>
    </div>

    <HostDialog ref="hostDialog" :folders="folders" @changed="reloadHosts" />
    <AddressListDialog ref="addrListDialog" :folders="folders" @changed="reloadAddrLists" />
    <IpListDialog ref="listDialog" :folders="folders" @changed="reloadLists" />
    <FolderDialog ref="folderDialog" :folders="folders" @changed="reloadFolders" />

    <UModal
      :open="prefixOpen"
      :title="!auth.canEdit ? 'Prefix' : prefix.id ? 'Edit prefix' : 'Prefix settings'"
      :ui="wideModal"
      :dismissible="false"
      @update:open="prefixGuard.onUpdateOpen"
    >
      <template #body>
        <form id="prefix-form" @submit.prevent="savePrefix">
          <fieldset :disabled="!auth.canEdit" class="space-y-3">
            <UFormField :ui="inlineField" label="Prefix" required
              ><UInput
                v-model="prefix.prefix"
                class="w-full font-mono"
                placeholder="192.168.1.0/24 or fd00:1::/64"
            /></UFormField>
            <UFormField :ui="inlineField" label="Description"
              ><UInput v-model="prefix.description" class="w-full"
            /></UFormField>
            <p class="text-sm text-muted">
              DHCP and router advertisements are set per interface under
              <RouterLink to="/dhcp?tab=server" class="text-primary">DHCP</RouterLink>.
            </p>
          </fieldset>
        </form>
      </template>
      <template #footer>
        <div class="flex w-full gap-2">
          <UButton
            v-if="prefix.id && auth.canEdit"
            color="error"
            variant="ghost"
            icon="i-lucide-trash"
            label="Delete"
            @click="removePrefix"
          />
          <UButton class="ms-auto" color="neutral" variant="ghost" @click="prefixGuard.close">{{
            auth.canEdit ? 'Cancel' : 'Close'
          }}</UButton>
          <UButton v-if="auth.canEdit" type="submit" form="prefix-form">Save</UButton>
        </div>
      </template>
    </UModal>

    <UModal
      :open="addrOpen"
      :title="!auth.canEdit ? 'Address' : addr.id ? 'Edit address' : 'New address'"
      :ui="wideModal"
      :dismissible="false"
      @update:open="addrGuard.onUpdateOpen"
    >
      <template #body>
        <form id="addr-form" @submit.prevent="saveAddress">
          <fieldset :disabled="!auth.canEdit" class="space-y-3">
            <UFormField :ui="inlineField" label="Address" required
              ><UInput
                v-model="addr.address"
                class="w-full font-mono"
                placeholder="192.168.1.10"
                :disabled="!!addrIface"
            /></UFormField>
            <p v-if="addrIface" class="text-sm text-muted">
              The firewall's address on {{ ifaceName(addrIface) }}; it is set under
              <RouterLink to="/interfaces" class="text-primary">Interfaces</RouterLink>.
            </p>
            <UFormField
              :ui="inlineField"
              label="DNS name"
              help="Fully qualified, inside one of the virtual firewall's DNS zones."
            >
              <UInput
                v-model="addr.dns_name"
                class="w-full font-mono"
                placeholder="nas.home.arpa"
              />
            </UFormField>
            <UFormField :ui="inlineField" label="MAC address (DHCP reservation)">
              <div class="flex items-center gap-1">
                <UInput
                  v-model="addr.mac"
                  class="w-full font-mono"
                  placeholder="02:00:00:00:00:10"
                />
                <UButton
                  v-if="store.current?.dhcp_enabled"
                  type="button"
                  color="neutral"
                  variant="ghost"
                  icon="i-lucide-list"
                  aria-label="Pick MAC from DHCP leases"
                  title="Pick MAC from DHCP leases"
                  @click="leasePickerOpen = true"
                />
              </div>
            </UFormField>
            <UFormField :ui="inlineField" label="Description"
              ><UInput v-model="addr.description" class="w-full"
            /></UFormField>
          </fieldset>
        </form>
      </template>
      <template #footer>
        <div class="flex w-full gap-2">
          <UButton
            v-if="addr.id && auth.canEdit"
            color="error"
            variant="ghost"
            icon="i-lucide-trash"
            label="Delete"
            @click="removeAddress"
          />
          <UButton class="ms-auto" color="neutral" variant="ghost" @click="addrGuard.close">{{
            auth.canEdit ? 'Cancel' : 'Close'
          }}</UButton>
          <UButton v-if="auth.canEdit" type="submit" form="addr-form">Save</UButton>
        </div>
      </template>
    </UModal>

    <DhcpLeasePicker
      v-model:open="leasePickerOpen"
      :instance="store.current?.name ?? ''"
      :ip="addr.address"
      @select="(lease) => (addr.mac = lease.mac)"
    />
  </div>
</template>
