<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import NeedInstance from '@/components/NeedInstance.vue'
import IpamTreeRows from '@/components/IpamTreeRows.vue'
import AddrInput from '@/components/AddrInput.vue'
import DhcpLeasePicker from '@/components/DhcpLeasePicker.vue'
import { api, ipamAddresses, ipamPrefixes } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useAuthStore } from '@/stores/auth'
import { useConfirm } from '@/composables/useConfirm'
import { inlineField, wideModal } from '@/utils/form'

const toast = useToast()
const auth = useAuthStore()
const { confirmDelete } = useConfirm()
const { store, ifaceName } = useInstanceRefs()
const tree = ref([])
const collapsed = reactive(new Set())
const loading = ref(false)

async function load() {
  if (!store.currentId) return
  loading.value = true
  try {
    tree.value = await api.ipamTree(store.currentId)
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    loading.value = false
  }
}
onMounted(load)

function toggle(k) {
  if (collapsed.has(k)) collapsed.delete(k)
  else collapsed.add(k)
}

// ----- prefix modal -----
const prefixOpen = ref(false)
const prefix = reactive({})
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
    load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

// ----- address modal -----
const addrOpen = ref(false)
const addr = reactive({})
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
    load()
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
    load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
async function removeAddress() {
  if (!(await confirmDelete(`address ${addr.address}`))) return
  try {
    await ipamAddresses.remove(addr.id)
    addrOpen.value = false
    load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
</script>

<template>
  <NeedInstance>
    <div class="card">
      <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div class="text-lg font-semibold">IP addresses</div>
          <p class="max-w-3xl text-sm text-muted">
            Prefixes nest by containment. The addresses of the firewall's interfaces (set under
            <RouterLink to="/interfaces" class="text-primary">Interfaces</RouterLink>) and their
            prefixes are listed automatically. Turn on DHCP on a prefix to serve it on the interface
            with an address in it, and router advertisements (SLAAC) on an IPv6 prefix; several DHCP
            prefixes on one interface share it, and clients get addresses from all of them. An
            address with a DNS name gets an A/AAAA record, and with a MAC also a fixed DHCP lease.
          </p>
        </div>
        <div v-if="auth.isAdmin" class="flex gap-2">
          <UButton
            color="neutral"
            variant="outline"
            icon="i-lucide-plus"
            label="Address"
            @click="editAddress({})"
          />
          <UButton icon="i-lucide-plus" label="Prefix" @click="editPrefix({})" />
        </div>
      </div>
      <div v-if="loading" class="flex justify-center p-6">
        <UIcon name="i-lucide-loader-2" class="size-7 animate-spin" />
      </div>
      <div v-else-if="!tree.length" class="py-8 text-center text-muted">
        No prefixes yet. Give an interface an address, e.g. 192.168.1.1/24, or add a prefix.
      </div>
      <div v-else class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-default text-left text-xs text-muted">
              <th />
              <th class="py-2">Prefix / address</th>
              <th class="px-2">Description</th>
              <th class="px-2">Use</th>
              <th class="px-2">Utilisation</th>
            </tr>
          </thead>
          <tbody>
            <IpamTreeRows
              :nodes="tree"
              :collapsed="collapsed"
              :iface-name="ifaceName"
              :read-only="!auth.isAdmin"
              @toggle="toggle"
              @add-prefix="onAddPrefix"
              @add-address="onAddAddress"
              @edit="onEdit"
            />
          </tbody>
        </table>
      </div>
    </div>

    <UModal
      v-model:open="prefixOpen"
      :title="!auth.isAdmin ? 'Prefix' : prefix.id ? 'Edit prefix' : 'Prefix settings'"
      :ui="wideModal"
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
          <UButton class="ms-auto" color="neutral" variant="ghost" @click="prefixOpen = false">{{
            auth.isAdmin ? 'Cancel' : 'Close'
          }}</UButton>
          <UButton v-if="auth.isAdmin" type="submit" form="prefix-form">Save</UButton>
        </div>
      </template>
    </UModal>

    <UModal
      v-model:open="addrOpen"
      :title="!auth.isAdmin ? 'Address' : addr.id ? 'Edit address' : 'New address'"
      :ui="wideModal"
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
          <UButton class="ms-auto" color="neutral" variant="ghost" @click="addrOpen = false">{{
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
  </NeedInstance>
</template>
