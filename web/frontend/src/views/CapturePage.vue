<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useCaptureWorker } from '@/composables/useCaptureWorker'
import { useUnsaved } from '@/composables/useFormGuard'
import { bytes } from '@/utils/bytes'
import PacketList from '@/components/capture/PacketList.vue'
import PacketTree from '@/components/capture/PacketTree.vue'
import HexDump from '@/components/capture/HexDump.vue'
import { openCaptureWindow } from '@/composables/useCaptureWindow'
import { useAuthStore } from '@/stores/auth'

// Packet capture: tcpdump on the firewall, streamed live through
// portitor-web (at the rate in Settings) into Wiregasm, Wireshark in
// WebAssembly, which runs in a worker (workers/capture.worker.js).
// CaptureWindowPage shows it alone in a popup window (inWindow), so a
// capture keeps running while the main window moves on.
const props = defineProps({ inWindow: Boolean })
const toast = useToast()
// Capturing takes an admin of the instance.
const auth = useAuthStore()
const { store, ifaceNames, ifaceText } = useInstanceRefs()
const cap = useCaptureWorker()
const { ready, fatal, columns, running, packets, generation } = cap
const received = cap.bytes

const form = reactive({
  interface: 'any',
  filter: '',
  max_packets: 100000,
  max_seconds: 600,
  snaplen: 0,
})
const ifaceItems = computed(() => [
  { label: 'any (all interfaces)', value: 'any' },
  ...ifaceNames.value.map((n) => ({ label: ifaceText(n), value: n })),
])

const started = ref(null)
const captured = ref({ instance: '', interface: '' })
const saved = ref(true) // the capture has been downloaded (or there is none)
let fileName = ''
// A capture that is not downloaded counts as unsaved: leaving the page asks.
useUnsaved(() => !saved.value && received.value > 24)

function start() {
  const inst = store.current?.name
  started.value = new Date()
  captured.value = { instance: inst, interface: form.interface }
  fileName = `${inst}-${form.interface}-${started.value.toISOString().replace(/[:.]/g, '-')}.pcap`
  selected.value = null
  frame.value = null
  node.value = null
  follow.value = true
  saved.value = false
  cap.start({
    instance: inst,
    interface: form.interface,
    filter: form.filter.trim(),
    max_packets: Number(form.max_packets) || 0,
    max_seconds: Number(form.max_seconds) || 0,
    snaplen: Number(form.snaplen) || 0,
  })
}
cap.onEnded((error) => {
  if (error) toast.add({ title: error, color: 'error' })
})

async function download() {
  const url = URL.createObjectURL(await cap.pcap())
  const a = document.createElement('a')
  a.href = url
  a.download = fileName
  a.click()
  URL.revokeObjectURL(url)
  saved.value = true
}

// The display filter (Wireshark syntax) is checked as you type and
// applied once it is valid.
const display = ref('')
const applied = ref('')
const filterError = ref('')
let checkTimer = null
watch(display, (f) => {
  clearTimeout(checkTimer)
  checkTimer = setTimeout(async () => {
    const t = f.trim()
    const r = t ? await cap.checkFilter(t) : { ok: true }
    filterError.value = r.ok ? '' : r.error || 'invalid filter'
    if (r.ok) applied.value = t
  }, 300)
})

const follow = ref(true)
const listVersion = computed(() => `${generation.value}/${applied.value}`)
const loadRows = (skip, limit) => cap.frames(applied.value, skip, limit)

const selected = ref(null)
const frame = ref(null)
const node = ref(null)
async function select(n) {
  selected.value = n
  follow.value = false
  try {
    frame.value = await cap.frame(n)
    node.value = null
  } catch (err) {
    toast.add({ title: err.message, color: 'error' })
  }
}
const hexSource = computed(() => frame.value?.sources[node.value?.source ?? 0])

// The panes are resized by dragging the bars between them (a double click
// resets); the sizes, in percent, are remembered in this browser.
const SPLIT_KEY = 'capture-split'
const split = reactive({ top: 50, left: 50 })
try {
  Object.assign(split, JSON.parse(localStorage.getItem(SPLIT_KEY)) ?? {})
} catch {
  // defaults
}
watch(split, () => {
  try {
    localStorage.setItem(SPLIT_KEY, JSON.stringify(split))
  } catch {
    // not remembered
  }
})
const panes = ref(null)
const bottom = ref(null)
function drag(key, event) {
  const el = key === 'top' ? panes.value : bottom.value
  const bar = event.currentTarget
  bar.setPointerCapture(event.pointerId)
  const move = (e) => {
    const r = el.getBoundingClientRect()
    const pct =
      key === 'top'
        ? ((e.clientY - r.top) / r.height) * 100
        : ((e.clientX - r.left) / r.width) * 100
    split[key] = Math.min(90, Math.max(10, pct))
  }
  const up = () => {
    bar.removeEventListener('pointermove', move)
    bar.removeEventListener('pointerup', up)
  }
  bar.addEventListener('pointermove', move)
  bar.addEventListener('pointerup', up)
}
</script>

<template>
  <div
    class="flex min-h-[36rem] flex-col gap-3"
    :class="props.inWindow ? 'h-full' : 'h-[calc(100vh-7rem)]'"
  >
    <form class="card flex flex-wrap items-end gap-3" @submit.prevent="start">
      <UFormField label="Interface">
        <USelect v-model="form.interface" :items="ifaceItems" class="w-56" :disabled="running" />
      </UFormField>
      <UFormField label="Capture filter" class="min-w-64 flex-1">
        <UInput
          v-model="form.filter"
          class="w-full font-mono"
          placeholder="host 192.0.2.1 and port 53"
          :disabled="running"
        />
      </UFormField>
      <UFormField label="Packets">
        <UInput v-model="form.max_packets" type="number" min="1" class="w-28" :disabled="running" />
      </UFormField>
      <UFormField label="Seconds">
        <UInput
          v-model="form.max_seconds"
          type="number"
          min="1"
          max="3600"
          class="w-24"
          :disabled="running"
        />
      </UFormField>
      <UFormField label="Bytes/packet" title="0 captures whole packets">
        <UInput
          v-model="form.snaplen"
          type="number"
          min="0"
          max="65535"
          class="w-24"
          :disabled="running"
        />
      </UFormField>
      <div class="flex items-center gap-2">
        <UButton
          v-if="!running"
          type="submit"
          icon="i-lucide-play"
          :disabled="!store.current || !ready || !auth.canEdit"
          >Start</UButton
        >
        <UButton v-else color="error" icon="i-lucide-square" @click="cap.stop()">Stop</UButton>
        <UButton
          v-if="!running && received > 24"
          variant="outline"
          icon="i-lucide-download"
          @click="download"
          >pcap</UButton
        >
        <UButton
          v-if="!props.inWindow"
          icon="i-lucide-external-link"
          color="neutral"
          variant="ghost"
          title="Capture in a window of its own, while you use the rest of the GUI"
          :disabled="!store.currentId"
          @click="openCaptureWindow(store.currentId)"
          >Open in window</UButton
        >
      </div>
    </form>

    <UAlert v-if="fatal" color="error" variant="subtle" :title="fatal" />
    <div v-else-if="!ready" class="text-sm text-muted">
      <UIcon name="i-lucide-loader-circle" class="animate-spin align-middle" /> Loading Wireshark
      (about 20 MB)…
    </div>

    <div class="flex flex-wrap items-center gap-3">
      <UInput
        v-model="display"
        icon="i-lucide-filter"
        placeholder="Display filter, e.g. dns || tcp.port == 443"
        aria-label="Display filter"
        size="sm"
        class="w-96 max-w-full font-mono"
        :color="filterError ? 'error' : undefined"
        :highlight="!!filterError"
        :ui="{ trailing: 'pe-1' }"
        @keydown.enter.prevent
        @keydown.esc="display = ''"
      >
        <template v-if="display" #trailing>
          <UButton
            color="neutral"
            variant="link"
            size="sm"
            icon="i-lucide-x"
            aria-label="Clear filter"
            title="Clear filter"
            @click="display = ''"
          />
        </template>
      </UInput>
      <USwitch v-model="follow" label="Follow" size="sm" />
      <span v-if="started" class="text-sm text-muted">
        <span v-if="running" class="me-1 inline-block size-2 animate-pulse rounded-full bg-error" />
        {{ packets }} packets, {{ bytes(received) }} · {{ captured.instance }} ·
        {{ captured.interface }}
      </span>
      <span v-if="filterError" class="text-sm text-error">{{ filterError }}</span>
    </div>

    <div ref="panes" class="flex min-h-0 flex-1 flex-col">
      <div class="flex min-h-0 flex-col" :style="{ height: `${split.top}%` }">
        <PacketList
          v-if="ready"
          v-model:follow="follow"
          :columns="columns"
          :load="loadRows"
          :version="listVersion"
          :selected="selected"
          @select="select"
        />
        <div v-else class="flex-1 rounded border border-default" />
      </div>
      <div
        class="splitter h-3 cursor-row-resize"
        title="Drag to resize, double-click to reset"
        @pointerdown.prevent="drag('top', $event)"
        @dblclick="split.top = 50"
      />
      <div ref="bottom" class="flex min-h-0 flex-1 flex-col gap-3 lg:flex-row lg:gap-0">
        <div
          class="min-h-0 flex-1 overflow-auto rounded border border-default p-2 lg:w-(--left) lg:flex-none"
          :style="{ '--left': `${split.left}%` }"
        >
          <PacketTree
            v-if="frame"
            :key="frame.number"
            :nodes="frame.tree"
            :selected="node"
            @select="node = $event"
          />
          <div v-else class="p-2 text-sm text-muted">Select a packet.</div>
        </div>
        <div
          class="splitter hidden w-3 cursor-col-resize lg:block"
          title="Drag to resize, double-click to reset"
          @pointerdown.prevent="drag('left', $event)"
          @dblclick="split.left = 50"
        />
        <div class="min-h-0 min-w-0 flex-1 overflow-auto rounded border border-default p-2">
          <HexDump
            v-if="hexSource"
            :data="hexSource.data"
            :start="node?.start ?? 0"
            :length="node?.length ?? 0"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.splitter {
  position: relative;
  touch-action: none;
}
.splitter::after {
  content: '';
  position: absolute;
  inset: 0;
  margin: auto;
  border-radius: 9999px;
  background: var(--ui-border-accented);
}
.splitter.cursor-row-resize::after {
  width: 3rem;
  height: 3px;
}
.splitter.cursor-col-resize::after {
  width: 3px;
  height: 3rem;
}
.splitter:hover::after {
  background: var(--ui-primary);
}
</style>
