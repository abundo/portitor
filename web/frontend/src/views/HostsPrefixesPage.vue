<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// Hosts & prefixes: one tree of the named hosts and prefixes, the IP lists
// and the instance's prefix tree (IPAM), each a top-level node. Hosts and
// IP lists can be sorted into folders (object_folders), which only
// structure the page.
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import IpamTreeRows from '@/components/IpamTreeRows.vue'
import DhcpLeasePicker from '@/components/DhcpLeasePicker.vue'
import HostDialog from '@/components/HostDialog.vue'
import IpListDialog from '@/components/IpListDialog.vue'
import FolderDialog from '@/components/FolderDialog.vue'
import { addressObjects, api, ipamAddresses, ipamPrefixes, ipLists, objectFolders } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useAuthStore } from '@/stores/auth'
import { useDeployStore } from '@/stores/deploy'
import { useObjectStore } from '@/stores/objects'
import { ago } from '@/utils/time'
import { useConfirm } from '@/composables/useConfirm'
import { useFormGuard } from '@/composables/useFormGuard'
import { inlineField, wideModal } from '@/utils/form'

const toast = useToast()
const router = useRouter()
const auth = useAuthStore()
const { confirmDelete } = useConfirm()
const { store, ifaceName, ifaceList } = useInstanceRefs()
const deploy = useDeployStore()
const objects = useObjectStore()
const hosts = ref([])
const lists = ref([])
const folders = ref([])
const tree = ref([])
// Keys of the collapsed nodes: the top-level nodes (group:*), the folders
// (folder:<id>) and the prefixes (IpamTreeRows).
const collapsed = reactive(new Set())
const loading = ref(true)
const infoOpen = ref(false)

const byName = (a, b) => a.name.localeCompare(b.name)
async function loadHosts() {
  hosts.value = (await addressObjects.list()).sort(byName)
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
  const [t, leases] = await Promise.all([
    api.ipamTree(store.currentId),
    api.agentLeases().catch(() => null),
  ])
  tree.value = t
  clientLeases.value = leases?.client ?? []
}

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
onMounted(async () => {
  deploy.refresh()
  try {
    await Promise.all([loadHosts(), loadLists(), loadFolders(), loadTree()])
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    loading.value = false
  }
})

const showError = (err) => toast.add({ title: errMsg(err), color: 'error' })
// Hosts and IP lists are also offered in address fields (the object store).
function reloadHosts() {
  loadHosts().catch(showError)
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
const listDialog = ref(null)
const folderDialog = ref(null)

// The rows of the Hosts or IP lists group: in each folder its folders,
// then its items, both by name; nothing inside a collapsed folder. count
// is the items a folder holds, those in its folders included.
function folderRows(kind, items) {
  const parent = (x) => x.parent_id ?? 0
  const count = (id) =>
    items.filter((i) => (i.folder_id ?? 0) === id).length +
    folders.value
      .filter((f) => f.kind === kind && parent(f) === id)
      .reduce((n, f) => n + count(f.id), 0)
  const out = []
  const walk = (id, depth) => {
    for (const f of folders.value.filter((f) => f.kind === kind && parent(f) === id)) {
      const key = `folder:${f.id}`
      out.push({ key, folder: f, depth, count: count(f.id) })
      if (!collapsed.has(key)) walk(f.id, depth + 1)
    }
    for (const item of items.filter((i) => (i.folder_id ?? 0) === id))
      out.push({ key: `${kind}:${item.id}`, item, depth })
  }
  walk(0, 1)
  return out
}
const hostRows = computed(() => folderRows('hosts', hosts.value))
const listRows = computed(() => folderRows('ip_lists', lists.value))
const indent = (depth) => ({ paddingLeft: `${depth * 1.25}rem` })

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

// Whether the DNS server listens on the interface's addresses: 'on', 'off'
// (the interface is set to, the instance's DNS server is disabled) or null.
function dnsListen(id) {
  if (!ifaceList.value.find((i) => i.id === id)?.dns_listen) return null
  return store.current?.dns_enabled ? 'on' : 'off'
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

// The top-level nodes of the tree.
const groups = computed(() => [
  {
    key: 'group:hosts',
    label: 'Hosts',
    icon: 'i-lucide-server',
    count: hosts.value.length,
    description: 'Named addresses, usable wherever addresses are entered',
  },
  {
    key: 'group:lists',
    label: 'IP lists',
    icon: 'i-lucide-list-x',
    count: lists.value.length,
    description: 'Downloaded address lists, used as @name in rules',
  },
  {
    key: 'group:prefixes',
    label: 'Prefixes & IP addresses',
    icon: 'i-lucide-network',
    description: store.current ? `The prefix tree of instance ${store.current.name}` : '',
  },
])

function toggle(k) {
  if (collapsed.has(k)) collapsed.delete(k)
  else collapsed.add(k)
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
  if (!auth.isAdmin || !items.length) {
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
  return [[kind === 'hosts' ? addHost(folderId) : addList(folderId), addFolder(kind, folderId)]]
}
function listMenu(item) {
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
  if (key === 'group:lists') return folderMenu('ip_lists')
  if (!store.currentId) return []
  return [
    [
      { label: 'Add prefix', icon: 'i-lucide-git-branch-plus', onSelect: () => editPrefix({}) },
      { label: 'Add address', icon: 'i-lucide-plus', onSelect: () => editAddress({}) },
    ],
  ]
}
function nodeMenu(node) {
  if (node.kind !== 'prefix' || node.dhcp_lease) return []
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
                    <b>IP lists</b> are address lists the firewall downloads: the ban decisions of a
                    CrowdSec engine, or any list with one address or prefix per line. Use a list as
                    @name in a rule's source or destination; it becomes an nftables set in each
                    instance whose rules use it, and matches IPv4 and IPv6. A list is downloaded
                    when it is first deployed and whenever a scheduled task says so; the last
                    download stays in force if a later one fails.
                  </p>
                  <p>
                    <b>Folders</b> sort hosts and IP lists; they mean nothing to the firewall. Move
                    an entry by choosing its folder in its form. Only an empty folder can be
                    deleted.
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
            Named hosts and prefixes, downloaded IP lists, and the instance's prefixes and addresses
            with their DNS names. Right-click a row to add to it.
          </p>
        </div>
        <div v-if="auth.isAdmin" class="flex gap-2">
          <UButton
            color="neutral"
            variant="outline"
            icon="i-lucide-plus"
            label="Host"
            @click="hostDialog.edit()"
          />
          <UButton
            color="neutral"
            variant="outline"
            icon="i-lucide-plus"
            label="IP list"
            @click="listDialog.edit()"
          />
          <UButton
            icon="i-lucide-plus"
            label="Prefix"
            :disabled="!store.currentId"
            @click="editPrefix({})"
          />
        </div>
      </div>
      <div v-if="loading" class="flex justify-center p-6">
        <UIcon name="i-lucide-loader-2" class="size-7 animate-spin" />
      </div>
      <UContextMenu v-else :items="menuItems">
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <tbody>
              <template v-for="g in groups" :key="g.key">
                <tr
                  class="border-b border-default bg-elevated/40"
                  @contextmenu="openMenu($event, groupMenu(g.key))"
                >
                  <td class="w-px py-1 pr-2 whitespace-nowrap"></td>
                  <td class="py-1.5 pr-2">
                    <div class="flex items-center gap-1">
                      <UButton
                        size="xs"
                        color="neutral"
                        variant="ghost"
                        :icon="
                          collapsed.has(g.key) ? 'i-lucide-chevron-right' : 'i-lucide-chevron-down'
                        "
                        :aria-label="collapsed.has(g.key) ? 'Expand' : 'Collapse'"
                        @click="toggle(g.key)"
                      />
                      <UIcon :name="g.icon" class="text-primary" />
                      <span class="font-semibold whitespace-nowrap">{{ g.label }}</span>
                      <UBadge
                        v-if="g.count !== undefined"
                        color="neutral"
                        variant="subtle"
                        size="sm"
                        :label="String(g.count)"
                      />
                    </div>
                  </td>
                  <td colspan="3" class="px-2 text-xs text-muted">{{ g.description }}</td>
                </tr>

                <template v-if="!collapsed.has(g.key)">
                  <template v-if="g.key === 'group:hosts'">
                    <template v-for="r in hostRows" :key="r.key">
                      <tr
                        v-if="r.folder"
                        class="border-b border-default hover:bg-elevated/50"
                        @contextmenu="openMenu($event, folderMenu('hosts', r.folder.id))"
                      >
                        <td class="py-1 pr-2 whitespace-nowrap">
                          <UButton
                            size="xs"
                            color="neutral"
                            variant="ghost"
                            :icon="auth.isAdmin ? 'i-lucide-pencil' : 'i-lucide-eye'"
                            :aria-label="auth.isAdmin ? 'Edit' : 'View'"
                            :title="auth.isAdmin ? 'Edit' : 'View'"
                            @click="folderDialog.edit(r.folder)"
                          />
                        </td>
                        <td class="py-1.5 pr-2">
                          <div class="flex items-center gap-1" :style="indent(r.depth)">
                            <UButton
                              size="xs"
                              color="neutral"
                              variant="ghost"
                              :icon="
                                collapsed.has(r.key)
                                  ? 'i-lucide-chevron-right'
                                  : 'i-lucide-chevron-down'
                              "
                              :aria-label="collapsed.has(r.key) ? 'Expand' : 'Collapse'"
                              @click="toggle(r.key)"
                            />
                            <UIcon
                              :name="
                                collapsed.has(r.key) ? 'i-lucide-folder' : 'i-lucide-folder-open'
                              "
                              class="text-primary"
                            />
                            <span class="font-medium whitespace-nowrap">{{ r.folder.name }}</span>
                            <UBadge
                              color="neutral"
                              variant="subtle"
                              size="sm"
                              :label="String(r.count)"
                            />
                          </div>
                        </td>
                        <td colspan="3" />
                      </tr>
                      <tr
                        v-else
                        class="border-b border-default hover:bg-elevated/50"
                        @contextmenu="openMenu($event, folderMenu('hosts', r.item.folder_id))"
                      >
                        <td class="py-1 pr-2 whitespace-nowrap">
                          <UButton
                            size="xs"
                            color="neutral"
                            variant="ghost"
                            :icon="auth.isAdmin ? 'i-lucide-pencil' : 'i-lucide-eye'"
                            :aria-label="auth.isAdmin ? 'Edit' : 'View'"
                            :title="auth.isAdmin ? 'Edit' : 'View'"
                            @click="hostDialog.edit(r.item)"
                          />
                        </td>
                        <td class="py-1.5 pr-2">
                          <div class="flex items-center gap-1" :style="indent(r.depth)">
                            <span class="inline-block w-6" />
                            <UIcon
                              :name="
                                hostKind(r.item) === 'host' ? 'i-lucide-server' : 'i-lucide-network'
                              "
                              class="text-muted"
                            />
                            <span class="font-medium">{{ r.item.name }}</span>
                          </div>
                        </td>
                        <td class="px-2 text-sm">{{ r.item.description }}</td>
                        <td class="px-2 font-mono text-xs">{{ r.item.addresses?.join(', ') }}</td>
                        <td class="px-2 text-xs whitespace-nowrap">
                          <UBadge
                            :color="hostKind(r.item) === 'host' ? 'primary' : 'neutral'"
                            variant="subtle"
                            :label="hostKind(r.item)"
                          />
                          <span class="ms-1 text-muted">{{ versions(r.item) }}</span>
                        </td>
                      </tr>
                    </template>
                    <tr v-if="!hostRows.length" class="border-b border-default">
                      <td />
                      <td colspan="4" class="py-2 pl-12 text-muted">No hosts yet.</td>
                    </tr>
                  </template>

                  <template v-else-if="g.key === 'group:lists'">
                    <template v-for="r in listRows" :key="r.key">
                      <tr
                        v-if="r.folder"
                        class="border-b border-default hover:bg-elevated/50"
                        @contextmenu="openMenu($event, folderMenu('ip_lists', r.folder.id))"
                      >
                        <td class="py-1 pr-2 whitespace-nowrap">
                          <UButton
                            size="xs"
                            color="neutral"
                            variant="ghost"
                            :icon="auth.isAdmin ? 'i-lucide-pencil' : 'i-lucide-eye'"
                            :aria-label="auth.isAdmin ? 'Edit' : 'View'"
                            :title="auth.isAdmin ? 'Edit' : 'View'"
                            @click="folderDialog.edit(r.folder)"
                          />
                        </td>
                        <td class="py-1.5 pr-2">
                          <div class="flex items-center gap-1" :style="indent(r.depth)">
                            <UButton
                              size="xs"
                              color="neutral"
                              variant="ghost"
                              :icon="
                                collapsed.has(r.key)
                                  ? 'i-lucide-chevron-right'
                                  : 'i-lucide-chevron-down'
                              "
                              :aria-label="collapsed.has(r.key) ? 'Expand' : 'Collapse'"
                              @click="toggle(r.key)"
                            />
                            <UIcon
                              :name="
                                collapsed.has(r.key) ? 'i-lucide-folder' : 'i-lucide-folder-open'
                              "
                              class="text-primary"
                            />
                            <span class="font-medium whitespace-nowrap">{{ r.folder.name }}</span>
                            <UBadge
                              color="neutral"
                              variant="subtle"
                              size="sm"
                              :label="String(r.count)"
                            />
                          </div>
                        </td>
                        <td colspan="3" />
                      </tr>
                      <tr
                        v-else
                        class="border-b border-default hover:bg-elevated/50"
                        @contextmenu="openMenu($event, listMenu(r.item))"
                      >
                        <td class="py-1 pr-2 whitespace-nowrap">
                          <UButton
                            size="xs"
                            color="neutral"
                            variant="ghost"
                            :icon="auth.isAdmin ? 'i-lucide-pencil' : 'i-lucide-eye'"
                            :aria-label="auth.isAdmin ? 'Edit' : 'View'"
                            :title="auth.isAdmin ? 'Edit' : 'View'"
                            @click="listDialog.edit(r.item)"
                          />
                          <UButton
                            v-if="auth.isAdmin"
                            size="xs"
                            color="neutral"
                            variant="ghost"
                            icon="i-lucide-refresh-cw"
                            title="Download now"
                            :disabled="
                              !states[r.item.name] || states[r.item.name].state === 'fetching'
                            "
                            @click="refreshList(r.item)"
                          />
                        </td>
                        <td class="py-1.5 pr-2">
                          <div class="flex items-center gap-1" :style="indent(r.depth)">
                            <span class="inline-block w-6" />
                            <UIcon name="i-lucide-list" class="text-muted" />
                            <span class="font-medium">@{{ r.item.name }}</span>
                          </div>
                        </td>
                        <td class="px-2 text-sm">{{ r.item.description }}</td>
                        <td class="px-2 text-xs">
                          {{ sourceLabel[r.item.source] ?? r.item.source }}
                          <span class="font-mono break-all text-muted">{{ r.item.url }}</span>
                        </td>
                        <td class="px-2 py-1">
                          <div v-if="states[r.item.name]" class="space-y-0.5 text-xs">
                            <UBadge
                              :color="stateColor[states[r.item.name].state] ?? 'neutral'"
                              variant="subtle"
                              size="sm"
                            >
                              {{ states[r.item.name].state }}
                            </UBadge>
                            <div v-if="states[r.item.name].updated">
                              {{ states[r.item.name].ipv4 }} IPv4,
                              {{ states[r.item.name].ipv6 }} IPv6
                              <span v-if="states[r.item.name].skipped" class="text-muted">
                                ({{ states[r.item.name].skipped }} skipped)
                              </span>
                            </div>
                            <div class="text-muted">
                              updated {{ ago(states[r.item.name].updated) }}
                            </div>
                            <div v-if="states[r.item.name].last_error" class="text-error">
                              {{ states[r.item.name].last_error }}
                            </div>
                          </div>
                          <span v-else class="text-xs text-muted">not deployed</span>
                        </td>
                      </tr>
                    </template>
                    <tr v-if="!listRows.length" class="border-b border-default">
                      <td />
                      <td colspan="4" class="py-2 pl-12 text-muted">No IP lists yet.</td>
                    </tr>
                  </template>

                  <template v-else>
                    <IpamTreeRows
                      v-if="shownTree.length"
                      :nodes="shownTree"
                      :depth="1"
                      :collapsed="collapsed"
                      :iface-name="ifaceName"
                      :read-only="!auth.isAdmin"
                      :dns-listen="dnsListen"
                      :iface-client="ifaceClient"
                      :dhcp-on="!!store.current?.dhcp_enabled"
                      @toggle="toggle"
                      @edit="onEdit"
                      @menu="(e, node) => openMenu(e, nodeMenu(node))"
                    />
                    <tr v-else>
                      <td />
                      <td colspan="4" class="py-2 pl-12 text-muted">
                        <template v-if="store.currentId">
                          No prefixes yet. Give an interface an address under
                          <RouterLink to="/interfaces" class="text-primary">Interfaces</RouterLink>,
                          e.g. 192.168.1.1/24, or add a prefix.
                        </template>
                        <template v-else>
                          No instance yet: create one under
                          <RouterLink to="/instances" class="text-primary">Instances</RouterLink>.
                        </template>
                      </td>
                    </tr>
                  </template>
                </template>
              </template>
            </tbody>
          </table>
        </div>
      </UContextMenu>
    </div>

    <HostDialog ref="hostDialog" :folders="folders" @changed="reloadHosts" />
    <IpListDialog ref="listDialog" :folders="folders" @changed="reloadLists" />
    <FolderDialog ref="folderDialog" :folders="folders" @changed="reloadFolders" />

    <UModal
      :open="prefixOpen"
      :title="!auth.isAdmin ? 'Prefix' : prefix.id ? 'Edit prefix' : 'Prefix settings'"
      :ui="wideModal"
      :dismissible="false"
      @update:open="prefixGuard.onUpdateOpen"
    >
      <template #body>
        <form id="prefix-form" @submit.prevent="savePrefix">
          <fieldset :disabled="!auth.isAdmin" class="space-y-3">
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
            v-if="prefix.id && auth.isAdmin"
            color="error"
            variant="ghost"
            icon="i-lucide-trash"
            label="Delete"
            @click="removePrefix"
          />
          <UButton class="ms-auto" color="neutral" variant="ghost" @click="prefixGuard.close">{{
            auth.isAdmin ? 'Cancel' : 'Close'
          }}</UButton>
          <UButton v-if="auth.isAdmin" type="submit" form="prefix-form">Save</UButton>
        </div>
      </template>
    </UModal>

    <UModal
      :open="addrOpen"
      :title="!auth.isAdmin ? 'Address' : addr.id ? 'Edit address' : 'New address'"
      :ui="wideModal"
      :dismissible="false"
      @update:open="addrGuard.onUpdateOpen"
    >
      <template #body>
        <form id="addr-form" @submit.prevent="saveAddress">
          <fieldset :disabled="!auth.isAdmin" class="space-y-3">
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
              help="Fully qualified, inside one of the instance's DNS zones."
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
            v-if="addr.id && auth.isAdmin"
            color="error"
            variant="ghost"
            icon="i-lucide-trash"
            label="Delete"
            @click="removeAddress"
          />
          <UButton class="ms-auto" color="neutral" variant="ghost" @click="addrGuard.close">{{
            auth.isAdmin ? 'Cancel' : 'Close'
          }}</UButton>
          <UButton v-if="auth.isAdmin" type="submit" form="addr-form">Save</UButton>
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
