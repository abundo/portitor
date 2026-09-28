<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { onMounted, onUnmounted, ref, watch } from 'vue'
import { useLogPanel } from '@/composables/useLogPanel'

// The agent's log at the bottom of the layout. It takes its height out of
// the page (a flex item, not an overlay), so nothing ends up behind it.
const { state, close, clear, togglePause, setHeight, start, stop } = useLogPanel()

const body = ref(null)

// Follow the tail unless paused. Watching the newest id (not the length)
// keeps following once the buffer is full.
watch(
  () => state.lines.at(-1)?.id,
  () => {
    if (!state.paused && body.value) body.value.scrollTop = body.value.scrollHeight
  },
  { flush: 'post' },
)

function startResize(event) {
  event.preventDefault()
  const startY = event.clientY
  const startHeight = state.height
  const onMove = (e) => setHeight(startHeight + (startY - e.clientY))
  const onUp = () => {
    window.removeEventListener('mousemove', onMove)
    window.removeEventListener('mouseup', onUp)
    setHeight(state.height, true)
  }
  window.addEventListener('mousemove', onMove)
  window.addEventListener('mouseup', onUp)
}

function formatTime(iso) {
  const d = new Date(iso)
  const p = (n, w = 2) => String(n).padStart(w, '0')
  return (
    `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
    `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`
  )
}

function levelClass(level) {
  if (level === 'ERROR') return 'text-error'
  if (level === 'WARN') return 'text-warning'
  if (level === 'DEBUG') return 'text-muted'
  return ''
}

function attrs(line) {
  return Object.entries(line.attrs ?? {}).filter(([, v]) => v !== '')
}

onMounted(() => {
  setHeight(state.height)
  start()
})
onUnmounted(stop)
</script>

<template>
  <section
    class="flex w-full shrink-0 flex-col overflow-hidden border-t border-default bg-default"
    :style="{ height: state.height + 'px' }"
  >
    <div class="h-1 shrink-0 cursor-row-resize hover:bg-primary/30" @mousedown="startResize"></div>
    <div class="flex shrink-0 items-center gap-2 border-b border-default px-3 py-1.5">
      <UIcon name="i-lucide-terminal" class="size-4" />
      <span class="text-sm font-medium">Agent log</span>
      <UTooltip v-if="state.error" :text="state.error">
        <UBadge color="error" variant="subtle" size="sm" label="agent unreachable" />
      </UTooltip>
      <UBadge v-if="state.paused" color="neutral" variant="subtle" size="sm" label="paused" />
      <div class="ml-auto flex items-center gap-1">
        <UButton
          :icon="state.paused ? 'i-lucide-play' : 'i-lucide-pause'"
          variant="ghost"
          color="neutral"
          size="xs"
          :title="state.paused ? 'Follow new lines' : 'Stop following new lines'"
          @click="togglePause"
        />
        <UButton
          icon="i-lucide-trash-2"
          variant="ghost"
          color="neutral"
          size="xs"
          title="Clear"
          @click="clear"
        />
        <UButton
          icon="i-lucide-x"
          variant="ghost"
          color="neutral"
          size="xs"
          title="Close"
          @click="close"
        />
      </div>
    </div>
    <div
      ref="body"
      class="min-h-0 flex-1 overflow-auto px-3 py-2 font-mono text-xs [overflow-anchor:none]"
    >
      <div v-if="!state.lines.length" class="text-muted">No log lines yet</div>
      <div
        v-for="line in state.lines"
        :key="line.id"
        class="flex flex-wrap gap-x-2"
        :class="levelClass(line.level)"
      >
        <span class="text-muted">{{ formatTime(line.time) }}</span>
        <span class="w-11 shrink-0 font-semibold">{{ line.level }}</span>
        <span class="break-all">{{ line.message }}</span>
        <span v-for="[k, v] in attrs(line)" :key="k" class="break-all text-muted"
          >{{ k }}={{ v }}</span
        >
      </div>
    </div>
  </section>
</template>
