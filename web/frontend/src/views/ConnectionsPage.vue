<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- Connections: the virtual firewall's connection tracking table, streamed
     from the agent (POST /api/agent/connections) as one snapshot per
     interval, the largest connections first. -->
<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { rules } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useSearch, valuesText } from '@/utils/search'
import { bytes } from '@/utils/bytes'

const { store } = useInstanceRefs()
const form = reactive({ interval: 2000, max: 1000 })
const intervalItems = [1000, 2000, 5000, 10000].map((ms) => ({
  label: `${ms / 1000} s`,
  value: ms,
}))
const maxItems = [100, 500, 1000, 5000].map((n) => ({ label: String(n), value: n }))

const snapshot = ref(null)
const error = ref('')
const running = ref(false)
const paused = ref(false)
let controller = null

// The rules' descriptions, for the rule (ct mark) that accepted a connection.
const ruleText = ref({})
async function loadRules() {
  if (!store.currentId) return
  try {
    const list = await rules.list({ instance_id: store.currentId })
    ruleText.value = Object.fromEntries(list.map((r) => [r.id, r.description || `#${r.id}`]))
  } catch {
    ruleText.value = {}
  }
}

async function start() {
  stop()
  if (!store.current) return
  error.value = ''
  running.value = true
  const ctl = (controller = new AbortController())
  try {
    const res = await fetch('/api/agent/connections', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        instance: store.current.name,
        interval_ms: form.interval,
        max: form.max,
      }),
      signal: ctl.signal,
    })
    if (!res.ok) {
      let msg = res.statusText
      try {
        msg = (await res.json()).error ?? msg
      } catch {
        /* not JSON */
      }
      throw new Error(msg)
    }
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader()
    let rest = ''
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      rest += value
      const lines = rest.split('\n')
      rest = lines.pop()
      // Only the newest complete snapshot matters.
      const last = lines.filter((l) => l.trim()).pop()
      if (!last) continue
      const snap = JSON.parse(last)
      if (snap.error) error.value = snap.error
      else if (!paused.value) {
        error.value = ''
        snapshot.value = snap
      }
    }
  } catch (err) {
    if (err.name !== 'AbortError') error.value = err.message
  } finally {
    if (controller === ctl) {
      running.value = false
      controller = null
    }
  }
}
function stop() {
  controller?.abort()
  controller = null
  running.value = false
}

onMounted(() => {
  loadRules()
  start()
})
onBeforeUnmount(stop)
watch(
  () => store.currentId,
  () => {
    snapshot.value = null
    loadRules()
    start()
  },
)
watch(
  () => [form.interval, form.max],
  () => running.value && start(),
)

const hostPort = (a, p) => (p ? (a.includes(':') ? `[${a}]:${p}` : `${a}:${p}`) : a)
const rows = computed(() =>
  (snapshot.value?.entries ?? []).map((c, i) => {
    // NAT: the reply's source is not the original destination (DNAT), or its
    // destination not the original source (SNAT).
    const dnat = c.reply_src !== c.dst || (c.reply_sport || 0) !== (c.dport || 0)
    const snat = c.reply_dst !== c.src || (c.reply_dport || 0) !== (c.sport || 0)
    return {
      key: i,
      protocol: c.protocol + (c.family === 'ipv6' ? '6' : ''),
      source: hostPort(c.src, c.sport),
      destination: hostPort(c.dst, c.dport),
      nat: [
        snat && `SNAT ${hostPort(c.reply_dst, c.reply_dport)}`,
        dnat && `DNAT ${hostPort(c.reply_src, c.reply_sport)}`,
      ]
        .filter(Boolean)
        .join(', '),
      state: c.state ?? '',
      packets: c.packets + c.reply_packets,
      bytes: c.bytes + c.reply_bytes,
      rule: c.mark ? (ruleText.value[c.mark] ?? `#${c.mark}`) : '',
      timeout: c.timeout,
    }
  }),
)
const { search, filtered } = useSearch(rows, (r) =>
  valuesText(r.protocol, r.source, r.destination, r.nat, r.state, r.rule),
)

const columns = [
  { accessorKey: 'protocol', header: 'Protocol' },
  { accessorKey: 'source', header: 'Source' },
  { accessorKey: 'destination', header: 'Destination' },
  { accessorKey: 'nat', header: 'NAT' },
  { accessorKey: 'state', header: 'State' },
  { id: 'packets', header: 'Packets' },
  { id: 'bytes', header: 'Bytes' },
  { accessorKey: 'rule', header: 'Rule' },
  { id: 'timeout', header: 'Expires in' },
]
const updated = computed(() =>
  snapshot.value ? new Date(snapshot.value.time).toLocaleTimeString() : '',
)
</script>

<template>
  <NeedInstance>
    <div class="card">
      <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div class="text-lg font-semibold">Connections</div>
          <p class="max-w-3xl text-sm text-muted">
            The connection tracking table of this virtual firewall, updated live, the largest
            connections first. Rule is the rule that accepted the connection.
          </p>
        </div>
        <div class="flex flex-wrap items-end gap-3">
          <UFormField label="Update every">
            <USelect v-model="form.interval" :items="intervalItems" class="w-24" />
          </UFormField>
          <UFormField label="Show at most">
            <USelect v-model="form.max" :items="maxItems" class="w-24" />
          </UFormField>
          <UButton
            v-if="running"
            :icon="paused ? 'i-lucide-play' : 'i-lucide-pause'"
            color="neutral"
            variant="outline"
            :label="paused ? 'Resume' : 'Pause'"
            @click="paused = !paused"
          />
          <UButton
            v-else
            icon="i-lucide-play"
            color="neutral"
            variant="outline"
            label="Start"
            @click="start"
          />
        </div>
      </div>

      <UAlert v-if="error" class="mb-2" color="error" variant="subtle" :title="error" />
      <div class="mb-2 flex flex-wrap items-center gap-3">
        <SearchInput v-model="search" />
        <span v-if="snapshot" class="text-sm text-muted">
          {{ snapshot.total }} connections<template v-if="snapshot.total > rows.length">
            ({{ rows.length }} largest shown)</template
          >, at {{ updated }}<template v-if="paused">, paused</template>
        </span>
      </div>
      <UTable
        :data="filtered"
        :columns="columns"
        :loading="running && !snapshot"
        :get-row-id="(r) => String(r.key)"
      >
        <template #source-cell="{ row }">
          <span class="font-mono text-xs">{{ row.original.source }}</span>
        </template>
        <template #destination-cell="{ row }">
          <span class="font-mono text-xs">{{ row.original.destination }}</span>
        </template>
        <template #nat-cell="{ row }">
          <span class="font-mono text-xs">{{ row.original.nat }}</span>
        </template>
        <template #packets-cell="{ row }">{{ row.original.packets.toLocaleString() }}</template>
        <template #bytes-cell="{ row }">{{ bytes(row.original.bytes) }}</template>
        <template #timeout-cell="{ row }">{{ row.original.timeout }} s</template>
      </UTable>
    </div>
  </NeedInstance>
</template>
