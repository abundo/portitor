<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import { useStatusRefresh } from '@/composables/useAutoRefresh'
import FirewallEvents from '@/components/FirewallEvents.vue'
import RateSparkline from '@/components/RateSparkline.vue'
import SearchInput from '@/components/SearchInput.vue'
import TrafficGraph from '@/components/TrafficGraph.vue'
import { api } from '@/api'
import { useAuthStore } from '@/stores/auth'
import { useDeployStore } from '@/stores/deploy'
import { useInstanceStore } from '@/stores/instances'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { openServiceLogWindow } from '@/composables/useServiceLogWindow'
import { bytes } from '@/utils/bytes'
import { ago } from '@/utils/time'
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

// The firewall the selected virtual firewall is on. Its host's memory, disks
// and CPU are a global reader's only (the server leaves them out otherwise).
const firewallId = computed(() => instances.current?.firewall_id ?? null)
const fw = computed(() => {
  const list = st.value?.firewalls ?? []
  return list.find((f) => f.id === firewallId.value) ?? list[0] ?? null
})
const host = computed(() => fw.value?.host ?? null)
const cpuSamples = computed(() => (fw.value ? (deploy.cpu[fw.value.id] ?? []) : []))
const cpuNow = computed(() => cpuSamples.value.at(-1)?.usage ?? null)
const memUsed = computed(() => (host.value ? host.value.mem_total - host.value.mem_available : 0))

// The operating system, its updates and the Portitor releases (from the
// last check for updates), for System information and Announcements. Asking
// runs an apt simulation on the firewall, so it is asked now and then, not
// at every refresh.
const SYSTEM_MS = 5 * 60 * 1000
const sys = ref(null)
const sysError = ref('')
const web = ref(null)
let sysTimer = null
async function loadSystem() {
  clearTimeout(sysTimer)
  if (!auth.readsAll) return
  try {
    sys.value = await api.system(firewallId.value)
    sysError.value = ''
  } catch (err) {
    sysError.value = err.response?.data?.error ?? err.message
  }
  sysTimer = setTimeout(loadSystem, SYSTEM_MS)
}
onMounted(async () => {
  loadSystem()
  try {
    web.value = await api.version()
  } catch {
    // The card shows the agent's version alone.
  }
})
onUnmounted(() => clearTimeout(sysTimer))
watch(firewallId, () => {
  sys.value = null
  loadSystem()
})

const releases = computed(() => sys.value?.releases?.releases ?? [])
const newer = computed(() => releases.value.filter((r) => r.newer && r.installable))
const security = computed(() => (sys.value?.packages ?? []).filter((p) => p.security).length)
const lastCheck = computed(() => sys.value?.jobs?.find((j) => j.name === 'check')?.finished)
const announcements = computed(() => releases.value.slice(0, 3))

// Traffic graph: one interface's rates, the first one up by default.
const graphIface = ref(null)
const graphItems = computed(() =>
  ifaces.value.map((i) => ({ label: ifaceText(i.name), value: i.name })),
)
watch(
  ifaces,
  (list) => {
    if (!list.some((i) => i.name === graphIface.value))
      graphIface.value = (list.find((i) => i.state === 'up') ?? list[0])?.name ?? null
  },
  { immediate: true },
)
const graphSamples = computed(() =>
  inst.value && graphIface.value
    ? (deploy.rates[`${inst.value.name}/${graphIface.value}`] ?? [])
    : [],
)

// Following a service's log is a POST the server allows only an admin of
// the instance.
const units = computed(() => Object.keys(inst.value?.services ?? {}))

// A WireGuard peer is connected while its last handshake is recent: WireGuard
// does one at least every 2 minutes on a session that carries traffic.
const ACTIVE_S = 180
const peers = computed(() =>
  (inst.value?.wireguard ?? [])
    .flatMap((w) => w.peers.map((p) => ({ ...p, iface: w.interface })))
    .map((p) => ({
      ...p,
      active:
        !!p.latest_handshake &&
        Date.now() - new Date(p.latest_handshake).getTime() < ACTIVE_S * 1000,
    }))
    .sort((a, b) => b.active - a.active),
)
const activePeers = computed(() => peers.value.filter((p) => p.active).length)

const stateColor = (s) =>
  s === 'up' || s === 'active' || s === 'unknown'
    ? 'success'
    : s === 'down' || s === 'failed'
      ? 'error'
      : 'neutral'
const count = (n) => (n ?? 0).toLocaleString()
const pct = (f) => `${Math.round(f * 100)} %`
const usageColor = (f) => (f >= 0.9 ? 'error' : f >= 0.75 ? 'warning' : 'primary')
function duration(s) {
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  return d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : `${m} min`
}

// The CPU sparkline: use over the store's 5 minutes, 0..100 %.
const CPU_W = 160
const CPU_H = 32
const CPU_WINDOW = 5 * 60 * 1000
const cpuPath = computed(() => {
  const s = cpuSamples.value
  const end = s.at(-1)?.t ?? 0
  return s
    .map((p, n) => {
      const x = CPU_W - ((end - p.t) / CPU_WINDOW) * CPU_W
      const y = CPU_H - 1 - p.usage * (CPU_H - 2)
      return `${n ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(' ')
})
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

    <div v-if="auth.readsAll || host" class="grid gap-4 md:grid-cols-2 2xl:grid-cols-4">
      <div v-if="auth.readsAll" class="card text-sm">
        <div class="mb-2 flex items-center gap-2">
          <span class="font-semibold">System information</span>
          <UButton class="ms-auto" size="sm" variant="outline" label="Updates" to="/updates" />
        </div>
        <dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5">
          <dt class="text-muted">Host name</dt>
          <dd class="font-mono">{{ fw?.hostname || sys?.hostname }}</dd>
          <dt class="text-muted">Portitor</dt>
          <dd>
            <span class="font-mono">{{ fw?.version }}</span>
            <span v-if="web && web.version !== fw?.version" class="text-muted">
              · web <span class="font-mono">{{ web.version }}</span></span
            >
            <div v-if="fw?.version_mismatch" class="text-xs text-warning">
              {{ fw.version_mismatch }}
            </div>
          </dd>
          <template v-if="sys">
            <dt class="text-muted">OS</dt>
            <dd>{{ sys.os }}</dd>
            <dt class="text-muted">Kernel</dt>
            <dd class="font-mono">{{ sys.kernel }}</dd>
          </template>
          <template v-if="host">
            <dt class="text-muted">Uptime</dt>
            <dd>{{ duration(host.uptime) }}</dd>
          </template>
          <template v-if="sys">
            <dt class="text-muted">Updates</dt>
            <dd class="flex flex-wrap gap-1">
              <UBadge
                v-if="newer.length"
                color="info"
                variant="subtle"
                :label="`Portitor ${newer[0].tag}`"
              />
              <UBadge
                v-if="sys.packages.length"
                :color="security ? 'warning' : 'neutral'"
                variant="subtle"
                :label="`${sys.packages.length} packages${security ? `, ${security} security` : ''}`"
              />
              <UBadge
                v-if="sys.reboot_required"
                color="warning"
                variant="subtle"
                label="reboot required"
              />
              <span
                v-if="!newer.length && !sys.packages.length && !sys.reboot_required"
                class="text-muted"
                >none</span
              >
            </dd>
            <dt class="text-muted">Last check</dt>
            <dd>{{ lastCheck ? ago(lastCheck) : 'not since the agent started' }}</dd>
          </template>
        </dl>
        <div v-if="sysError" class="mt-1 text-xs text-error">{{ sysError }}</div>
      </div>

      <template v-if="host">
        <div class="card text-sm">
          <div class="mb-2 font-semibold">CPU</div>
          <div class="flex items-center gap-3">
            <span class="text-2xl font-semibold">{{ cpuNow == null ? '…' : pct(cpuNow) }}</span>
            <svg :width="CPU_W" :height="CPU_H" class="shrink-0">
              <line
                :x1="0"
                :x2="CPU_W"
                :y1="CPU_H - 0.5"
                :y2="CPU_H - 0.5"
                class="stroke-(--ui-border)"
              />
              <path
                v-if="cpuSamples.length > 1"
                :d="cpuPath"
                fill="none"
                stroke-width="2"
                class="stroke-(--ui-primary)"
              />
            </svg>
          </div>
          <div class="mt-2 text-xs text-muted">
            {{ host.cpus }} CPUs · load {{ host.load.map((l) => l.toFixed(2)).join(' ') }}
          </div>
        </div>

        <div class="card text-sm">
          <div class="mb-2 font-semibold">Memory</div>
          <div class="mb-1 flex justify-between">
            <span>{{ bytes(memUsed) }} of {{ bytes(host.mem_total) }}</span>
            <span class="text-muted">{{ pct(memUsed / host.mem_total) }}</span>
          </div>
          <UProgress
            :model-value="(memUsed / host.mem_total) * 100"
            :color="usageColor(memUsed / host.mem_total)"
            size="sm"
          />
          <div v-if="host.swap_total" class="mt-2 text-xs text-muted">
            Swap {{ bytes(host.swap_total - host.swap_free) }} of {{ bytes(host.swap_total) }}
          </div>
        </div>

        <div class="card text-sm">
          <div class="mb-2 font-semibold">Disk</div>
          <div v-if="!host.disks.length" class="text-muted">No disk found.</div>
          <div v-for="d in host.disks" :key="d.mount" class="mb-2 last:mb-0">
            <div class="mb-1 flex justify-between gap-2">
              <span class="truncate font-mono" :title="d.mount">{{ d.mount }}</span>
              <span class="whitespace-nowrap text-muted"
                >{{ bytes(d.used) }} of {{ bytes(d.used + d.free) }}</span
              >
            </div>
            <UProgress
              :model-value="(d.used / (d.used + d.free)) * 100"
              :color="usageColor(d.used / (d.used + d.free))"
              size="sm"
            />
          </div>
        </div>
      </template>
    </div>

    <template v-if="inst">
      <div class="card">
        <div class="mb-2 flex flex-wrap items-center gap-2">
          <span class="font-semibold">Traffic graph</span>
          <USelect
            v-if="graphItems.length"
            v-model="graphIface"
            :items="graphItems"
            size="sm"
            class="w-56"
          />
        </div>
        <TrafficGraph :samples="graphSamples" />
      </div>

      <div class="card overflow-x-auto">
        <div class="mb-2 font-semibold">Interface statistics · {{ inst.name }}</div>
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
              <th class="pr-4 text-right font-medium">Packets in</th>
              <th class="pr-4 text-right font-medium">Packets out</th>
              <th class="pr-4 text-right font-medium">Bytes in</th>
              <th class="pr-4 text-right font-medium">Bytes out</th>
              <th class="pr-4 text-right font-medium" title="Received / sent">Errors</th>
              <th class="text-right font-medium" title="Received / sent">Drops</th>
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
              <td class="pr-4 text-right whitespace-nowrap">{{ count(i.rx_packets) }}</td>
              <td class="pr-4 text-right whitespace-nowrap">{{ count(i.tx_packets) }}</td>
              <td class="pr-4 text-right whitespace-nowrap">{{ bytes(i.rx_bytes) }}</td>
              <td class="pr-4 text-right whitespace-nowrap">{{ bytes(i.tx_bytes) }}</td>
              <td
                class="pr-4 text-right whitespace-nowrap"
                :class="{ 'text-error': i.rx_errors || i.tx_errors }"
              >
                {{ count(i.rx_errors) }} / {{ count(i.tx_errors) }}
              </td>
              <td
                class="text-right whitespace-nowrap"
                :class="{ 'text-warning': i.rx_dropped || i.tx_dropped }"
              >
                {{ count(i.rx_dropped) }} / {{ count(i.tx_dropped) }}
              </td>
            </tr>
            <tr v-if="!shownIfaces.length">
              <td colspan="10" class="py-2 text-muted">No interface matches.</td>
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
            No services run in this virtual firewall.
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

        <div class="card">
          <div class="mb-2 flex items-center gap-2">
            <span class="font-semibold">VPN</span>
            <span v-if="peers.length" class="text-xs text-muted"
              >{{ activePeers }} of {{ peers.length }} WireGuard peers connected</span
            >
            <UButton
              class="ms-auto"
              size="sm"
              variant="outline"
              label="WireGuard"
              to="/wireguard"
            />
          </div>
          <div v-if="!peers.length" class="text-sm text-muted">
            No WireGuard peers in this virtual firewall.
          </div>
          <div
            v-for="p in peers"
            :key="p.iface + p.public_key"
            class="flex flex-wrap items-center justify-between gap-2 py-1 text-sm"
          >
            <span class="flex items-center gap-2">
              <UBadge
                :color="p.active ? 'success' : 'neutral'"
                variant="subtle"
                :label="p.active ? 'connected' : 'idle'"
              />
              <span class="font-mono text-xs">{{ p.iface }} · {{ p.allowed_ips.join(', ') }}</span>
            </span>
            <span class="text-xs text-muted"
              ><span v-if="p.endpoint" class="font-mono">{{ p.endpoint }} · </span
              >{{ ago(p.latest_handshake) }} · ↓ {{ bytes(p.rx_bytes) }} ↑
              {{ bytes(p.tx_bytes) }}</span
            >
          </div>
        </div>
      </div>

      <div class="grid gap-4 xl:grid-cols-3">
        <FirewallEvents
          class="xl:col-span-2"
          :instance="inst.name"
          :firewall-id="firewallId"
          :iface-text="ifaceText"
        />
        <div v-if="auth.readsAll" class="card text-sm">
          <div class="mb-2 font-semibold">Announcements</div>
          <div v-if="!sys?.releases" class="text-muted">
            Check for updates on the
            <RouterLink class="text-primary" to="/updates">Updates</RouterLink> page to see the
            project's latest releases.
          </div>
          <div v-else-if="!announcements.length" class="text-muted">No releases yet.</div>
          <div
            v-for="r in announcements"
            :key="r.tag"
            class="mb-3 border-b border-default pb-2 last:mb-0 last:border-0 last:pb-0"
          >
            <div class="mb-1 flex flex-wrap items-center gap-2">
              <span class="font-mono font-semibold">{{ r.tag }}</span>
              <span class="text-xs text-muted">{{ r.date }}</span>
              <UBadge v-if="r.newer" color="info" variant="subtle" size="sm" label="new" />
              <UBadge v-if="r.broken" color="error" variant="subtle" size="sm" label="broken" />
            </div>
            <p class="line-clamp-4 whitespace-pre-line text-muted">
              {{ r.notes.replace(/\s*BROKEN:.*$/, '') }}
            </p>
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
