<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// Hosts & prefixes: one tree of the named hosts and prefixes, the IP lists
// and the instance's prefix tree (IPAM), each a top-level node.
import { computed, onMounted, reactive, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import IpamTreeRows from '@/components/IpamTreeRows.vue'
import AddrInput from '@/components/AddrInput.vue'
import DhcpLeasePicker from '@/components/DhcpLeasePicker.vue'
import HostDialog from '@/components/HostDialog.vue'
import IpListDialog from '@/components/IpListDialog.vue'
import { addressObjects, api, ipamAddresses, ipamPrefixes, ipLists } from '@/api'
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
const auth = useAuthStore()
const { confirmDelete } = useConfirm()
const { store, ifaceName } = useInstanceRefs()
const deploy = useDeployStore()
const objects = useObjectStore()
const hosts = ref([])
const lists = ref([])
const tree = ref([])
// Keys of the collapsed nodes: the top-level nodes (group:*) and the
// prefixes (IpamTreeRows).
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
async function loadTree() {
  if (store.currentId) tree.value = await api.ipamTree(store.currentId)
}
onMounted(async () => {
  deploy.refresh()
  try {
    await Promise.all([loadHosts(), loadLists(), loadTree()])
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
function reloadTree() {
  loadTree().catch(showError)
}

const hostDialog = ref(null)
const listDialog = ref(null)

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
    dhcp_enabled: false,
    dhcp_range_start: '',
    dhcp_range_end: '',
    dhcp_gateway: '',
    dhcp_dns_servers: [],
    ra_enabled: false,
    ra_slaac: false,
    ...src,
  })
  prefixOpen.value = true
}
const prefixIs6 = computed(() => (prefix.prefix ?? '').includes(':'))
const prefixIs64 = computed(() => (prefix.prefix ?? '').trim().endsWith('/64'))
async function savePrefix() {
  try {
    const body = { ...prefix, instance_id: store.currentId }
    if (!prefixIs6.value) body.ra_enabled = body.ra_slaac = false
    else body.dhcp_gateway = ''
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
// An auto node has no IPAM entry yet: editing it creates one, for DHCP or
// router advertisements on a prefix, a DNS name or MAC on an address.
async function onEdit(node) {
  if (node.kind === 'prefix')
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
                    <b>Prefixes & IP addresses</b> nest by containment. The addresses of the
                    firewall's interfaces and their prefixes are listed automatically. Turn on DHCP
                    on a prefix to serve it on the interface with an address in it, and router
                    advertisements (SLAAC) on an IPv6 prefix; several DHCP prefixes on one interface
                    share it. An address with a DNS name gets an A/AAAA record, and with a MAC also
                    a fixed DHCP lease.
                  </p>
                </div>
              </template>
            </UPopover>
          </div>
          <p class="max-w-3xl text-sm text-muted">
            Named hosts and prefixes, downloaded IP lists, and the instance's prefixes and addresses
            with their DHCP and DNS settings.
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
      <div v-else class="overflow-x-auto">
        <table class="w-full text-sm">
          <tbody>
            <template v-for="g in groups" :key="g.key">
              <tr class="border-b border-default bg-elevated/40">
                <td class="w-px py-1 pr-2 whitespace-nowrap">
                  <template v-if="auth.isAdmin">
                    <UButton
                      v-if="g.key === 'group:hosts'"
                      size="xs"
                      color="neutral"
                      variant="ghost"
                      icon="i-lucide-plus"
                      title="Add host"
                      @click="hostDialog.edit()"
                    />
                    <UButton
                      v-else-if="g.key === 'group:lists'"
                      size="xs"
                      color="neutral"
                      variant="ghost"
                      icon="i-lucide-plus"
                      title="Add IP list"
                      @click="listDialog.edit()"
                    />
                    <template v-else-if="store.currentId">
                      <UButton
                        size="xs"
                        color="neutral"
                        variant="ghost"
                        icon="i-lucide-plus"
                        title="Add address"
                        @click="editAddress({})"
                      />
                      <UButton
                        size="xs"
                        color="neutral"
                        variant="ghost"
                        icon="i-lucide-git-branch-plus"
                        title="Add prefix"
                        @click="editPrefix({})"
                      />
                    </template>
                  </template>
                </td>
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
                  <tr
                    v-for="h in hosts"
                    :key="`host:${h.id}`"
                    class="border-b border-default hover:bg-elevated/50"
                  >
                    <td class="py-1 pr-2 whitespace-nowrap">
                      <UButton
                        size="xs"
                        color="neutral"
                        variant="ghost"
                        :icon="auth.isAdmin ? 'i-lucide-pencil' : 'i-lucide-eye'"
                        :aria-label="auth.isAdmin ? 'Edit' : 'View'"
                        :title="auth.isAdmin ? 'Edit' : 'View'"
                        @click="hostDialog.edit(h)"
                      />
                    </td>
                    <td class="py-1.5 pr-2">
                      <div class="flex items-center gap-1 pl-5">
                        <span class="inline-block w-6" />
                        <UIcon
                          :name="hostKind(h) === 'host' ? 'i-lucide-server' : 'i-lucide-network'"
                          class="text-muted"
                        />
                        <span class="font-medium">{{ h.name }}</span>
                      </div>
                    </td>
                    <td class="px-2 text-sm">{{ h.description }}</td>
                    <td class="px-2 font-mono text-xs">{{ h.addresses?.join(', ') }}</td>
                    <td class="px-2 text-xs whitespace-nowrap">
                      <UBadge
                        :color="hostKind(h) === 'host' ? 'primary' : 'neutral'"
                        variant="subtle"
                        :label="hostKind(h)"
                      />
                      <span class="ms-1 text-muted">{{ versions(h) }}</span>
                    </td>
                  </tr>
                  <tr v-if="!hosts.length" class="border-b border-default">
                    <td />
                    <td colspan="4" class="py-2 pl-12 text-muted">No hosts yet.</td>
                  </tr>
                </template>

                <template v-else-if="g.key === 'group:lists'">
                  <tr
                    v-for="l in lists"
                    :key="`list:${l.id}`"
                    class="border-b border-default hover:bg-elevated/50"
                  >
                    <td class="py-1 pr-2 whitespace-nowrap">
                      <UButton
                        size="xs"
                        color="neutral"
                        variant="ghost"
                        :icon="auth.isAdmin ? 'i-lucide-pencil' : 'i-lucide-eye'"
                        :aria-label="auth.isAdmin ? 'Edit' : 'View'"
                        :title="auth.isAdmin ? 'Edit' : 'View'"
                        @click="listDialog.edit(l)"
                      />
                      <UButton
                        v-if="auth.isAdmin"
                        size="xs"
                        color="neutral"
                        variant="ghost"
                        icon="i-lucide-refresh-cw"
                        title="Download now"
                        :disabled="!states[l.name] || states[l.name].state === 'fetching'"
                        @click="refreshList(l)"
                      />
                    </td>
                    <td class="py-1.5 pr-2">
                      <div class="flex items-center gap-1 pl-5">
                        <span class="inline-block w-6" />
                        <UIcon name="i-lucide-list" class="text-muted" />
                        <span class="font-medium">@{{ l.name }}</span>
                      </div>
                    </td>
                    <td class="px-2 text-sm">{{ l.description }}</td>
                    <td class="px-2 text-xs">
                      {{ sourceLabel[l.source] ?? l.source }}
                      <span class="font-mono break-all text-muted">{{ l.url }}</span>
                    </td>
                    <td class="px-2 py-1">
                      <div v-if="states[l.name]" class="space-y-0.5 text-xs">
                        <UBadge
                          :color="stateColor[states[l.name].state] ?? 'neutral'"
                          variant="subtle"
                          size="sm"
                        >
                          {{ states[l.name].state }}
                        </UBadge>
                        <div v-if="states[l.name].updated">
                          {{ states[l.name].ipv4 }} IPv4, {{ states[l.name].ipv6 }} IPv6
                          <span v-if="states[l.name].skipped" class="text-muted">
                            ({{ states[l.name].skipped }} skipped)
                          </span>
                        </div>
                        <div class="text-muted">updated {{ ago(states[l.name].updated) }}</div>
                        <div v-if="states[l.name].last_error" class="text-error">
                          {{ states[l.name].last_error }}
                        </div>
                      </div>
                      <span v-else class="text-xs text-muted">not deployed</span>
                    </td>
                  </tr>
                  <tr v-if="!lists.length" class="border-b border-default">
                    <td />
                    <td colspan="4" class="py-2 pl-12 text-muted">No IP lists yet.</td>
                  </tr>
                </template>

                <template v-else>
                  <IpamTreeRows
                    v-if="tree.length"
                    :nodes="tree"
                    :depth="1"
                    :collapsed="collapsed"
                    :iface-name="ifaceName"
                    :read-only="!auth.isAdmin"
                    @toggle="toggle"
                    @add-prefix="onAddPrefix"
                    @add-address="onAddAddress"
                    @edit="onEdit"
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
    </div>

    <HostDialog ref="hostDialog" @changed="reloadHosts" />
    <IpListDialog ref="listDialog" @changed="reloadLists" />

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
            <template v-if="prefixIs6">
              <UFormField
                :ui="inlineField"
                label="Send router advertisements"
                help="Announce this prefix and the firewall as default router on the interface that has an address in it."
              >
                <USwitch v-model="prefix.ra_enabled" />
              </UFormField>
              <UFormField
                :ui="inlineField"
                v-if="prefix.ra_enabled"
                label="SLAAC: clients pick their own address"
                :help="prefixIs64 ? '' : 'Needs a /64 prefix.'"
              >
                <USwitch v-model="prefix.ra_slaac" :disabled="!prefixIs64" />
              </UFormField>
            </template>
            <UFormField
              :ui="inlineField"
              :label="prefixIs6 ? 'Serve DHCPv6 on this prefix' : 'Serve DHCP on this prefix'"
              :help="
                prefixIs6
                  ? 'Needs router advertisements (above) and the DHCP server on the instance.'
                  : 'Needs the DHCP server on the instance, and an interface address in the prefix.'
              "
            >
              <USwitch
                v-model="prefix.dhcp_enabled"
                :disabled="prefixIs6 && !prefix.ra_enabled && !prefix.dhcp_enabled"
              />
            </UFormField>
            <template v-if="prefix.dhcp_enabled">
              <UFormField :ui="inlineField" label="Range">
                <div class="flex items-center gap-2">
                  <UInput
                    v-model="prefix.dhcp_range_start"
                    class="min-w-0 flex-1 font-mono"
                    placeholder="192.168.1.100"
                    aria-label="Range start"
                  />
                  <span class="text-muted">-</span>
                  <UInput
                    v-model="prefix.dhcp_range_end"
                    class="min-w-0 flex-1 font-mono"
                    placeholder="192.168.1.199"
                    aria-label="Range end"
                  />
                </div>
              </UFormField>
              <UFormField
                :ui="inlineField"
                v-if="!prefixIs6"
                label="Gateway"
                help="Empty: the firewall's address in the prefix."
                ><UInput v-model="prefix.dhcp_gateway" class="w-full font-mono"
              /></UFormField>
            </template>
            <UFormField
              :ui="inlineField"
              v-if="prefix.dhcp_enabled || (prefixIs6 && prefix.ra_enabled)"
              label="DNS servers"
              help="Addresses or hosts; only those of the prefix's IP version are used. Empty: the firewall, when its DNS server listens on that interface."
            >
              <AddrInput v-model="prefix.dhcp_dns_servers" multiple />
            </UFormField>
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
