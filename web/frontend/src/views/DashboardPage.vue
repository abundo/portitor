<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, onUnmounted } from 'vue'
import { useDeployStore } from '@/stores/deploy'
import { useInstanceStore } from '@/stores/instances'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { bytes } from '@/utils/bytes'
import { datetime } from '@/utils/time'

const deploy = useDeployStore()
const instances = useInstanceStore()
const { ifaceRefItems } = useInstanceRefs()
onMounted(() => deploy.watch())
onUnmounted(() => deploy.unwatch())

// Descriptions of the instance's interfaces and link ends, by name.
const ifaceDesc = computed(
  () => new Map(ifaceRefItems.value.map((it) => [it.value, it.description])),
)

const st = computed(() => deploy.status)
const inst = computed(() => st.value?.instances?.find((i) => i.name === instances.current?.name))
const wan = computed(() =>
  (st.value?.dhcp_client_leases ?? []).filter((l) => l.instance === instances.current?.name),
)
const ifaces = computed(() =>
  [...(inst.value?.interfaces ?? [])].sort((a, b) =>
    a.name.localeCompare(b.name, undefined, { numeric: true }),
  ),
)
const missing = computed(() => (st.value?.programs ?? []).filter((p) => !p.path))
const missingNeeded = computed(() => missing.value.some((p) => p.needed))
const peers = computed(() =>
  (inst.value?.wireguard ?? []).flatMap((w) => w.peers.map((p) => ({ ...p, iface: w.interface }))),
)

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
    <div v-if="st" class="grid gap-4 md:grid-cols-3">
      <div class="card">
        <div class="text-sm text-muted">Firewall</div>
        <div class="text-xl font-semibold">{{ st.hostname }}</div>
        <div class="text-xs text-muted">
          agent {{ st.version }}<span v-if="st.dry_run"> · dry-run</span>
        </div>
      </div>
      <div class="card">
        <div class="text-sm text-muted">Running configuration</div>
        <div class="text-xl font-semibold">generation {{ st.generation }}</div>
        <div class="text-xs text-muted">
          {{ st.last_apply ? datetime(st.last_apply) : 'never applied' }}
        </div>
      </div>
      <div class="card">
        <div class="text-sm text-muted">Last result</div>
        <div v-if="st.last_error" class="text-sm text-error">{{ st.last_error }}</div>
        <div v-else class="flex items-center gap-2 text-xl font-semibold text-success">
          <UIcon name="i-lucide-circle-check" /> OK
        </div>
      </div>
    </div>

    <div v-if="wan.length" class="card overflow-x-auto">
      <div class="mb-2 font-semibold">Internet (DHCP)</div>
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-default text-left text-xs text-muted">
            <th class="py-1.5 pr-4 font-medium">Interface</th>
            <th class="pr-4 font-medium">Description</th>
            <th class="pr-4 font-medium">Status</th>
            <th class="pr-4 font-medium">Address</th>
            <th class="pr-4 font-medium">Default route</th>
            <th class="font-medium">DNS</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="l in wan"
            :key="l.interface"
            class="border-b border-default align-top last:border-0"
          >
            <td class="py-1.5 pr-4 font-mono">{{ l.interface }}</td>
            <td class="py-1.5 pr-4">{{ ifaceDesc.get(l.interface) }}</td>
            <td class="py-1.5 pr-4">
              <UBadge
                :color="l.state === 'bound' ? 'success' : 'warning'"
                variant="subtle"
                :label="l.state"
              />
              <div v-if="l.last_error" class="mt-0.5 text-xs text-error">{{ l.last_error }}</div>
            </td>
            <td class="py-1.5 pr-4 font-mono text-xs">{{ l.address }}</td>
            <td class="py-1.5 pr-4 font-mono text-xs">{{ l.router }}</td>
            <td class="py-1.5 font-mono text-xs">
              <div v-for="d in l.dns ?? []" :key="d">{{ d }}</div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <template v-if="inst">
      <div class="card overflow-x-auto">
        <div class="mb-2 font-semibold">Interfaces · {{ inst.name }}</div>
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-default text-left text-xs text-muted">
              <th class="py-1.5 pr-4 font-medium">Name</th>
              <th class="pr-4 font-medium">Description</th>
              <th class="pr-4 font-medium">State</th>
              <th class="pr-4 font-medium">MAC</th>
              <th class="pr-4 font-medium">Addresses</th>
              <th class="pr-4 text-right font-medium">Received</th>
              <th class="text-right font-medium">Sent</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="i in ifaces" :key="i.name" class="border-b border-default last:border-0">
              <td class="py-1.5 pr-4 font-mono">{{ i.name }}</td>
              <td class="pr-4">{{ ifaceDesc.get(i.name) }}</td>
              <td class="pr-4">
                <UBadge :color="stateColor(i.state)" variant="subtle" :label="i.state" />
              </td>
              <td class="pr-4 font-mono text-xs">{{ i.mac }}</td>
              <td class="pr-4 font-mono text-xs">{{ i.addresses.join(', ') }}</td>
              <td class="pr-4 text-right whitespace-nowrap">{{ bytes(i.rx_bytes) }}</td>
              <td class="text-right whitespace-nowrap">{{ bytes(i.tx_bytes) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="grid gap-4 xl:grid-cols-2">
        <div class="card">
          <div class="mb-2 font-semibold">Services</div>
          <div v-if="!Object.keys(inst.services).length" class="text-sm text-muted">
            No DNS or DHCP server in this instance.
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
      This instance is not on the firewall yet. Configure it and
      <RouterLink class="text-primary" to="/deploy">deploy</RouterLink>.
    </div>
  </div>
</template>
