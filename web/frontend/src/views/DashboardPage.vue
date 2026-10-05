<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed } from 'vue'
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import { useStatusRefresh } from '@/composables/useAutoRefresh'
import RateSparkline from '@/components/RateSparkline.vue'
import SearchInput from '@/components/SearchInput.vue'
import { useAuthStore } from '@/stores/auth'
import { useDeployStore } from '@/stores/deploy'
import { useInstanceStore } from '@/stores/instances'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { openServiceLogWindow } from '@/composables/useServiceLogWindow'
import { bytes } from '@/utils/bytes'
import { useSearch, valuesText } from '@/utils/search'

const deploy = useDeployStore()
const instances = useInstanceStore()
const auth = useAuthStore()
const { ifaceRefItems, ifaceText } = useInstanceRefs()
const { auto, loading } = useStatusRefresh()

// Descriptions of the instance's interfaces and link ends, by name.
const ifaceDesc = computed(
  () => new Map(ifaceRefItems.value.map((it) => [it.value, it.description])),
)

const st = computed(() => deploy.status)
const inst = computed(() => st.value?.instances?.find((i) => i.name === instances.current?.name))
const ifaces = computed(() =>
  [...(inst.value?.interfaces ?? [])].sort((a, b) =>
    a.name.localeCompare(b.name, undefined, { numeric: true }),
  ),
)
const { search: ifaceSearch, filtered: shownIfaces } = useSearch(ifaces, (i) =>
  valuesText(ifaceText(i.name), ifaceDesc.value.get(i.name), i.state),
)
const missing = computed(() => (st.value?.programs ?? []).filter((p) => !p.path))
const missingNeeded = computed(() => missing.value.some((p) => p.needed))
const peers = computed(() =>
  (inst.value?.wireguard ?? []).flatMap((w) => w.peers.map((p) => ({ ...p, iface: w.interface }))),
)

// Following a service's log is a POST the server allows only an admin of
// the instance.
const units = computed(() => Object.keys(inst.value?.services ?? {}))

const ago = (t) =>
  t ? `${Math.round((Date.now() - new Date(t).getTime()) / 60000)} min ago` : 'never'
const stateColor = (s) =>
  s === 'up' || s === 'active' || s === 'unknown'
    ? 'success'
    : s === 'down' || s === 'failed'
      ? 'error'
      : 'neutral'
</script>

<template>
  <div class="space-y-4">
    <div class="flex justify-end">
      <AutoRefreshButton :auto="auto" :loading="loading" />
    </div>
    <UAlert
      v-if="deploy.error"
      color="error"
      variant="subtle"
      icon="i-lucide-unplug"
      title="Cannot reach the firewall agent"
      :description="deploy.error"
      :actions="[{ label: 'Settings', to: '/settings' }]"
    />
    <UAlert
      v-if="deploy.missingNics.length"
      color="warning"
      variant="subtle"
      icon="i-lucide-cable"
      title="Interfaces not found on the firewall"
      :actions="[{ label: 'Interfaces', to: '/interfaces' }]"
    >
      <template #description>
        <ul class="mt-1 space-y-0.5">
          <li v-for="n in deploy.missingNics" :key="n.instance + '/' + n.name">
            <span class="font-mono">{{ n.name }}</span> · instance {{ n.instance }}
          </li>
        </ul>
        <div class="mt-1 text-xs">
          Deploying a configuration with a physical interface the firewall does not have fails.
        </div>
      </template>
    </UAlert>
    <UAlert
      v-if="missing.length"
      :color="missingNeeded ? 'error' : 'warning'"
      variant="subtle"
      icon="i-lucide-package-x"
      :title="
        missingNeeded
          ? 'Programs the configuration needs are not installed on the firewall'
          : 'Some programs are not installed on the firewall'
      "
    >
      <template #description>
        <ul class="mt-1 space-y-0.5">
          <li v-for="p in missing" :key="p.name">
            <span class="font-mono">{{ p.name }}</span> · {{ p.purpose
            }}<span v-if="p.needed" class="font-semibold"> · in use</span>
          </li>
        </ul>
        <div class="mt-1 text-xs">Deploying a configuration that uses them fails.</div>
      </template>
    </UAlert>
    <template v-if="inst">
      <div class="card overflow-x-auto">
        <div class="mb-2 font-semibold">Interfaces · {{ inst.name }}</div>
        <div class="mb-2">
          <SearchInput v-model="ifaceSearch" />
        </div>
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-default text-left text-xs text-muted">
              <th class="py-1 pr-4 font-medium">Name</th>
              <th class="pr-4 font-medium">Description</th>
              <th class="pr-4 font-medium">State</th>
              <th class="pr-4 font-medium">Bandwidth, 5 min</th>
              <th class="pr-4 text-right font-medium">Received</th>
              <th class="text-right font-medium">Sent</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="i in shownIfaces"
              :key="i.name"
              class="border-b border-default last:border-0"
            >
              <td class="py-1 pr-4 font-mono">{{ ifaceText(i.name) }}</td>
              <td class="pr-4">{{ ifaceDesc.get(i.name) }}</td>
              <td class="pr-4">
                <UBadge :color="stateColor(i.state)" variant="subtle" :label="i.state" />
              </td>
              <td class="py-1 pr-4">
                <RateSparkline :samples="deploy.rates[`${inst.name}/${i.name}`]" />
              </td>
              <td class="pr-4 text-right whitespace-nowrap">{{ bytes(i.rx_bytes) }}</td>
              <td class="text-right whitespace-nowrap">{{ bytes(i.tx_bytes) }}</td>
            </tr>
            <tr v-if="!shownIfaces.length">
              <td colspan="6" class="py-2 text-muted">No interface matches.</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="grid gap-4 xl:grid-cols-2">
        <div class="card">
          <div class="mb-2 flex items-center gap-2">
            <span class="font-semibold">Services</span>
            <UButton
              v-if="auth.canEdit && units.length"
              icon="i-lucide-external-link"
              size="sm"
              variant="outline"
              label="Show logs"
              title="The services' logs in a window of their own, while you use the rest of the GUI"
              @click="openServiceLogWindow(instances.currentId)"
            />
          </div>
          <div v-if="!units.length" class="text-sm text-muted">
            No DNS or DHCP server in this virtual firewall.
          </div>
          <div
            v-for="(state, unit) in inst.services"
            :key="unit"
            class="flex items-center justify-between py-1 text-sm"
          >
            <span class="font-mono">{{ unit }}</span>
            <UBadge :color="stateColor(state)" variant="subtle" :label="state" />
          </div>
        </div>
        <div v-if="peers.length" class="card">
          <div class="mb-2 font-semibold">WireGuard peers</div>
          <div
            v-for="p in peers"
            :key="p.public_key"
            class="flex flex-wrap items-center justify-between gap-2 py-1 text-sm"
          >
            <span class="font-mono text-xs">{{ p.iface }} · {{ p.allowed_ips.join(', ') }}</span>
            <span class="text-xs text-muted"
              >{{ ago(p.latest_handshake) }} · ↓ {{ bytes(p.rx_bytes) }} ↑
              {{ bytes(p.tx_bytes) }}</span
            >
          </div>
        </div>
      </div>
    </template>
    <div v-else-if="st && !deploy.error" class="card text-sm text-muted">
      This virtual firewall is not on the firewall yet. Configure it and
      <RouterLink class="text-primary" to="/deploy">deploy</RouterLink>.
    </div>
  </div>
</template>
