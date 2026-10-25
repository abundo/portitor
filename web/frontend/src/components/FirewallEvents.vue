<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import SearchInput from '@/components/SearchInput.vue'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { clock } from '@/utils/time'
import { useSearch, valuesText } from '@/utils/search'

// The packets the instance's rulesets logged since the card was shown (the
// agent's ring buffer before that is skipped): a snapshot of what the
// firewall sees now, with the most common actions, sources, destination
// ports and rules.
const props = defineProps({
  instance: { type: String, required: true },
  firewallId: { type: Number, default: null },
  ifaceText: { type: Function, default: (n) => n },
})

const MAX = 1000
const POLL_MS = 2000
const SHOWN = 100

const events = ref([])
const error = ref('')
const since = ref(new Date())
let after = null // null until the first answer gives the cursor
let timer = null
let gen = 0

async function poll() {
  const g = gen
  try {
    const res = await api.agentPacketLog(after ?? 0, props.firewallId)
    if (g !== gen) return
    const entries = res.entries ?? []
    if (after !== null) {
      events.value.push(...entries.filter((p) => p.instance === props.instance))
      if (events.value.length > MAX) events.value.splice(0, events.value.length - MAX)
    }
    after = entries.length ? entries.at(-1).id : (after ?? 0)
    error.value = ''
  } catch (err) {
    if (g !== gen) return
    error.value = errMsg(err)
  }
  timer = setTimeout(poll, POLL_MS)
}

function restart() {
  clearTimeout(timer)
  gen++
  after = null
  events.value = []
  since.value = new Date()
  poll()
}

onMounted(restart)
onUnmounted(() => {
  clearTimeout(timer)
  gen++
})
watch(() => [props.instance, props.firewallId], restart)

// The most common values of key, with their counts.
function top(key, n = 5) {
  const counts = new Map()
  for (const p of events.value) {
    const k = key(p)
    if (k) counts.set(k, (counts.get(k) ?? 0) + 1)
  }
  return [...counts].sort((a, b) => b[1] - a[1]).slice(0, n)
}

function ruleLabel(p) {
  if (p.rule) return `rule ${p.rule}`
  return p.builtin === 'auto' ? `auto: ${p.service}` : p.builtin
}
function dstPort(p) {
  if (!p.dst_port) return p.protocol
  return `${p.protocol}/${p.dst_service || p.dst_port}`
}

const actions = computed(() => top((p) => p.action, 10))
const summaries = computed(() => [
  { title: 'Sources', rows: top((p) => p.src) },
  { title: 'Destinations', rows: top((p) => p.dst) },
  { title: 'Services', rows: top(dstPort) },
  { title: 'Rules', rows: top(ruleLabel) },
])

const newest = computed(() => events.value.slice(-SHOWN).reverse())
const { search, filtered } = useSearch(newest, (p) =>
  valuesText(
    p.action,
    p.in_interface && props.ifaceText(p.in_interface),
    p.out_interface && props.ifaceText(p.out_interface),
    p.protocol,
    p.src,
    p.src_port,
    p.dst,
    p.dst_port,
    p.dst_service,
    ruleLabel(p),
  ),
)

const actionColor = { accept: 'success', drop: 'error', reject: 'warning' }
const actionClass = { accept: 'text-success', drop: 'text-error', reject: 'text-warning' }
</script>

<template>
  <div class="card">
    <div class="mb-2 flex flex-wrap items-center gap-2">
      <span class="font-semibold">Firewall</span>
      <span class="text-xs text-muted">logged since {{ clock(since) }} · {{ events.length }}</span>
      <UBadge
        v-for="[a, n] in actions"
        :key="a"
        :color="actionColor[a] ?? 'neutral'"
        variant="subtle"
        :label="`${a} ${n}`"
      />
      <UButton
        class="ms-auto"
        icon="i-lucide-rotate-ccw"
        size="sm"
        variant="outline"
        label="Start over"
        @click="restart"
      />
    </div>
    <div v-if="error" class="text-sm text-error">{{ error }}</div>
    <div v-else-if="!events.length" class="text-sm text-muted">
      Nothing logged since the dashboard opened. Only rules with Log ticked on the Rules page log
      packets.
    </div>
    <template v-else>
      <div class="mb-3 grid gap-3 text-xs sm:grid-cols-2 2xl:grid-cols-4">
        <div v-for="s in summaries" :key="s.title">
          <div class="mb-1 font-medium text-muted">{{ s.title }}</div>
          <div v-for="[k, n] in s.rows" :key="k" class="flex justify-between gap-2">
            <span class="truncate font-mono" :title="k">{{ k }}</span>
            <span class="text-muted">{{ n }}</span>
          </div>
        </div>
      </div>
      <div class="mb-2">
        <SearchInput v-model="search" />
      </div>
      <div class="max-h-80 overflow-auto">
        <table class="w-full text-xs">
          <thead class="sticky top-0 bg-default">
            <tr class="border-b border-default text-left text-muted">
              <th class="py-1 pr-3 font-medium">Time</th>
              <th class="pr-3 font-medium">Action</th>
              <th class="pr-3 font-medium">Interfaces</th>
              <th class="pr-3 font-medium">Source</th>
              <th class="pr-3 font-medium">Destination</th>
              <th class="pr-3 font-medium">Service</th>
              <th class="font-medium">Rule</th>
            </tr>
          </thead>
          <tbody class="font-mono">
            <tr v-for="p in filtered" :key="p.id" class="border-b border-default last:border-0">
              <td class="py-1 pr-3 whitespace-nowrap">{{ clock(p.time) }}</td>
              <td class="pr-3" :class="actionClass[p.action] ?? 'text-muted'">
                {{ p.action }}
              </td>
              <td class="pr-3 whitespace-nowrap">
                {{ p.in_interface ? ifaceText(p.in_interface) : '' }}
                <template v-if="p.out_interface"> → {{ ifaceText(p.out_interface) }}</template>
              </td>
              <td class="pr-3">
                {{ p.src }}<span v-if="p.src_port">:{{ p.src_port }}</span>
              </td>
              <td class="pr-3">
                {{ p.dst }}<span v-if="p.dst_port">:{{ p.dst_port }}</span>
              </td>
              <td class="pr-3">{{ dstPort(p) }}</td>
              <td class="whitespace-nowrap">{{ ruleLabel(p) }}</td>
            </tr>
            <tr v-if="!filtered.length">
              <td colspan="7" class="py-2 text-muted">No packet matches.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>
