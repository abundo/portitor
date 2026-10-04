<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// ServiceLogDialog: a service's journal (journalctl --follow on the
// agent) as it comes, with a filter over the lines. Closing the dialog
// stops it.
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import SearchInput from '@/components/SearchInput.vue'

const props = defineProps({
  instance: { type: String, default: '' },
  unit: { type: String, default: '' },
})
const open = defineModel('open', { type: Boolean, default: false })

// maxLines is how many lines the dialog keeps.
const maxLines = 5000

const lines = ref([])
const error = ref('')
const running = ref(false)
const filter = ref('')
const follow = ref(true)
const wrap = ref(false)
const box = ref(null)
let controller = null

const shown = computed(() => {
  const words = filter.value.toLowerCase().split(/\s+/).filter(Boolean)
  if (!words.length) return lines.value
  return lines.value.filter((l) => {
    const t = l.toLowerCase()
    return words.every((w) => t.includes(w))
  })
})

async function start() {
  stop()
  lines.value = []
  error.value = ''
  running.value = true
  const ctl = new AbortController()
  controller = ctl
  try {
    const res = await fetch('/api/agent/servicelog', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ instance: props.instance, unit: props.unit }),
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
      const parts = rest.split('\n')
      rest = parts.pop()
      if (!parts.length) continue
      const all = lines.value.concat(parts)
      lines.value = all.length > maxLines ? all.slice(all.length - maxLines) : all
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

watch(
  open,
  (o) => {
    if (o) {
      filter.value = ''
      follow.value = true
      start()
    } else stop()
  },
  { immediate: true },
)

// Keep the newest line in view unless the user scrolled up.
watch(shown, async () => {
  if (!follow.value) return
  await nextTick()
  if (box.value) box.value.scrollTop = box.value.scrollHeight
})
onBeforeUnmount(stop)

// lineStyle indents a wrapped line's continuation to start after the
// host name (short-iso: "<time> <host> <unit>[pid]: <message>").
function lineStyle(l) {
  if (!wrap.value) return null
  const n = l.match(/^\S+ \S+ /)?.[0].length ?? 0
  return { paddingLeft: `${n}ch`, textIndent: `-${n}ch` }
}

function onScroll() {
  const el = box.value
  follow.value = el.scrollHeight - el.scrollTop - el.clientHeight < 20
}
</script>

<template>
  <UModal
    v-model:open="open"
    :title="`Log · ${unit}`"
    :dismissible="false"
    :ui="{ content: 'max-w-[90vw] w-[90vw] h-[85vh]', body: 'flex flex-col min-h-0 flex-1' }"
  >
    <template #body>
      <div class="mb-2 flex flex-wrap items-center gap-2">
        <SearchInput v-model="filter" placeholder="Filter" />
        <span class="text-xs text-muted">
          {{ shown.length }} of {{ lines.length }} lines
          <template v-if="running"> · following</template>
        </span>
        <UCheckbox v-model="wrap" label="Wrap long lines" />
        <UButton
          v-if="!running"
          icon="i-lucide-refresh-cw"
          size="sm"
          variant="outline"
          label="Restart"
          class="ml-auto"
          @click="start"
        />
      </div>
      <UAlert v-if="error" color="error" variant="subtle" :description="error" class="mb-2" />
      <div
        ref="box"
        class="min-h-0 flex-1 overflow-auto rounded border border-default bg-elevated p-2 font-mono text-xs"
        :class="wrap ? 'break-all whitespace-pre-wrap' : 'whitespace-pre'"
        @scroll="onScroll"
      >
        <div v-for="(l, i) in shown" :key="i" :style="lineStyle(l)">{{ l }}</div>
        <div v-if="!shown.length" class="text-muted">
          {{ lines.length ? 'No line matches.' : running ? 'Waiting for the log…' : 'No lines.' }}
        </div>
      </div>
    </template>
  </UModal>
</template>
