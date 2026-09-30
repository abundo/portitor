<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// DhcpLeasePicker: pick a MAC from the instance's current Kea leases (as
// reported by the agent) for a DHCP reservation. Ported from factum2.
import { useToast } from '@nuxt/ui/composables'
import { computed, h, nextTick, ref, resolveComponent, watch } from 'vue'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { datetime } from '@/utils/time'
import SearchInput from '@/components/SearchInput.vue'

const open = defineModel('open', { type: Boolean, default: false })
const props = defineProps({
  instance: { type: String, default: '' },
  // Preselects the lease with this address (the record's value).
  ip: { type: String, default: '' },
})
const emit = defineEmits(['select'])

const UButton = resolveComponent('UButton')
const toast = useToast()
const leases = ref([])
const loading = ref(false)
const filter = ref('')
const selectedKey = ref('')
const table = ref(null)
const sorting = ref([{ id: 'ip', desc: false }])

const pickerTableUi = {
  th: 'px-3 py-2',
  td: 'px-3 py-2 font-mono text-sm',
  tr: [
    'cursor-pointer',
    'data-[selected=true]:bg-primary/25',
    'data-[selected=true]:hover:bg-primary/30',
    'data-[selected=true]:shadow-[inset_3px_0_0_0_var(--ui-primary)]',
    '[&[data-selected=true]>td]:text-highlighted',
    '[&[data-selected=true]>td]:font-medium',
  ].join(' '),
}

function sortHeader(label) {
  return ({ column }) => {
    const dir = column.getIsSorted()
    return h(UButton, {
      color: 'neutral',
      variant: 'ghost',
      size: 'xs',
      label,
      class: '-mx-2',
      trailingIcon:
        dir === 'asc'
          ? 'i-lucide-arrow-up-narrow-wide'
          : dir === 'desc'
            ? 'i-lucide-arrow-down-wide-narrow'
            : 'i-lucide-arrow-up-down',
      onClick: () => column.toggleSorting(dir === 'asc'),
    })
  }
}

const columns = [
  { accessorKey: 'mac', header: sortHeader('MAC') },
  { accessorKey: 'ip', header: sortHeader('IP'), sortingFn: (a, b) => ipOrder(a, b) },
  { accessorKey: 'hostname', header: sortHeader('Hostname') },
  { accessorKey: 'familyLabel', header: sortHeader('Family') },
  { accessorKey: 'expires', header: sortHeader('Expires') },
]

// Numeric order for IPv4, text order otherwise.
function ipOrder(a, b) {
  const key = (ip) =>
    ip.includes(':')
      ? `2${ip}`
      : `1${ip
          .split('.')
          .map((n) => n.padStart(3, '0'))
          .join('.')}`
  return key(a.original.ip).localeCompare(key(b.original.ip))
}

const rowSelection = computed(() => (selectedKey.value ? { [selectedKey.value]: true } : {}))

function leaseKey(row) {
  return `${row.ip}:${row.mac}`
}

function onSelect(_e, row) {
  selectedKey.value = leaseKey(row.original)
}

function selectedLease() {
  return leases.value.find((row) => leaseKey(row) === selectedKey.value) || null
}

function confirmSelection() {
  const lease = selectedLease()
  if (!lease?.mac) return
  emit('select', { mac: lease.mac, ip: lease.ip, hostname: lease.hostname, family: lease.family })
  open.value = false
}

async function loadLeases() {
  loading.value = true
  try {
    const data = await api.agentLeases()
    leases.value = (data?.server?.[props.instance] ?? [])
      .filter((l) => l.mac)
      .map((l) => {
        const family = l.address.includes(':') ? 'ipv6' : 'ipv4'
        return {
          ip: l.address,
          mac: l.mac,
          hostname: l.hostname ?? '',
          family,
          familyLabel: family === 'ipv6' ? 'IPv6' : 'IPv4',
          expires: datetime(l.expires),
        }
      })
    const match = leases.value.find((l) => props.ip && l.ip === props.ip.trim())
    if (match) selectedKey.value = leaseKey(match)
  } catch (err) {
    leases.value = []
    toast.add({ color: 'error', title: 'Could not load DHCP leases', description: errMsg(err) })
  } finally {
    loading.value = false
  }
}

watch(open, (isOpen) => {
  if (!isOpen) return
  filter.value = ''
  selectedKey.value = ''
  loadLeases()
})

watch(
  [loading, selectedKey],
  () => {
    if (!loading.value && selectedKey.value) {
      nextTick(() => {
        const root = table.value?.$el ?? table.value
        root?.querySelector?.('[data-selected="true"]')?.scrollIntoView({ block: 'nearest' })
      })
    }
  },
  { flush: 'post' },
)
</script>

<template>
  <UModal
    v-model:open="open"
    title="Select DHCP lease"
    :ui="{ content: 'sm:max-w-4xl' }"
    :dismissible="false"
  >
    <template #body>
      <div class="flex min-w-0 flex-col gap-2">
        <div class="flex items-center justify-between gap-2">
          <p class="text-sm text-muted">
            Current leases from Kea on instance {{ instance }}. Selecting a row copies its MAC.
          </p>
          <SearchInput v-model="filter" class="shrink-0" />
        </div>
        <UTable
          ref="table"
          v-model:sorting="sorting"
          v-model:global-filter="filter"
          :data="leases"
          :columns="columns"
          :loading="loading"
          :row-selection="rowSelection"
          :get-row-id="leaseKey"
          empty="No DHCP leases with a MAC address."
          sticky
          class="max-h-[50vh]"
          :ui="pickerTableUi"
          @select="onSelect"
          @dblclick="confirmSelection"
        >
          <template #mac-cell="{ row }">
            <span class="inline-flex items-center gap-2">
              <UIcon
                v-if="row.getIsSelected()"
                name="i-lucide-check"
                class="size-4 shrink-0 text-primary"
              />
              <span v-else class="size-4 shrink-0" />
              {{ row.original.mac }}
            </span>
          </template>
        </UTable>
      </div>
    </template>
    <template #footer>
      <div class="flex w-full justify-end gap-2">
        <UButton label="Cancel" icon="i-lucide-x" variant="ghost" @click="open = false" />
        <UButton
          label="Select"
          icon="i-lucide-check"
          :disabled="!selectedLease()?.mac"
          @click="confirmSelection"
        />
      </div>
    </template>
  </UModal>
</template>
