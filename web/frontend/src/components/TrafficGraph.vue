<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { bitRate } from '@/utils/bytes'
import { clock } from '@/utils/time'

// A receive/send rate graph over a fixed time window (the newest sample at
// the right edge), as wide as its container, with a crosshair and the rates
// at the sample under the pointer.
const props = defineProps({
  samples: { type: Array, default: () => [] }, // { t, rx, tx } in bytes/s
  window: { type: Number, default: 5 * 60 * 1000 },
  height: { type: Number, default: 180 },
})

const PAD = { left: 72, right: 8, top: 8, bottom: 20 }
const box = ref(null)
const width = ref(600)
let observer = null
onMounted(() => {
  observer = new ResizeObserver(([e]) => (width.value = Math.max(200, e.contentRect.width)))
  observer.observe(box.value)
})
onUnmounted(() => observer?.disconnect())

const plotW = computed(() => width.value - PAD.left - PAD.right)
const plotH = computed(() => props.height - PAD.top - PAD.bottom)
const end = computed(() => props.samples.at(-1)?.t ?? Date.now())

// A round top of the scale in bits/s (1, 2 or 5 times a power of ten), so
// the grid lines read as whole numbers.
const top = computed(() => {
  const peak = Math.max(1, ...props.samples.flatMap((s) => [s.rx, s.tx])) * 8
  const p = 10 ** Math.floor(Math.log10(peak))
  return ([1, 2, 5, 10].find((m) => m * p >= peak) * p) / 8
})
const grid = computed(() => [0, 0.25, 0.5, 0.75, 1].map((f) => f * top.value))

const x = (t) => PAD.left + plotW.value - ((end.value - t) / props.window) * plotW.value
const y = (v) => PAD.top + plotH.value - (v / top.value) * plotH.value
const path = (key) =>
  props.samples
    .map((s, n) => `${n ? 'L' : 'M'}${x(s.t).toFixed(1)},${y(s[key]).toFixed(1)}`)
    .join(' ')
const area = (key) =>
  props.samples.length > 1
    ? `${path(key)} L${x(end.value).toFixed(1)},${y(0)} L${x(props.samples[0].t).toFixed(1)},${y(0)} Z`
    : ''

const hover = ref(null)
function onMove(e) {
  if (props.samples.length < 2) return
  const rect = e.currentTarget.getBoundingClientRect()
  const px = e.clientX - rect.left
  let best = null
  for (const s of props.samples) {
    if (!best || Math.abs(x(s.t) - px) < Math.abs(x(best.t) - px)) best = s
  }
  hover.value = best
}
const tipLeft = computed(() => {
  if (!hover.value) return 0
  const px = x(hover.value.t)
  return px > width.value - 170 ? px - 170 : px + 10
})
</script>

<template>
  <div ref="box" class="relative w-full">
    <div class="mb-1 flex gap-4 text-xs text-muted">
      <span class="flex items-center gap-1"
        ><span class="inline-block h-0.5 w-4 bg-(--ui-primary)"></span>Received</span
      >
      <span class="flex items-center gap-1"
        ><span class="inline-block h-0.5 w-4 bg-(--ui-warning)"></span>Sent</span
      >
    </div>
    <svg
      :width="width"
      :height="height"
      class="block"
      @mousemove="onMove"
      @mouseleave="hover = null"
    >
      <g v-for="g in grid" :key="g">
        <line
          :x1="PAD.left"
          :x2="width - PAD.right"
          :y1="y(g)"
          :y2="y(g)"
          class="stroke-(--ui-border)"
          :stroke-dasharray="g ? '2 3' : ''"
        />
        <text
          :x="PAD.left - 6"
          :y="y(g) + 3"
          text-anchor="end"
          class="fill-(--ui-text-muted) text-[10px]"
        >
          {{ bitRate(g) }}
        </text>
      </g>
      <text :x="PAD.left" :y="height - 4" class="fill-(--ui-text-muted) text-[10px]">
        −{{ Math.round(window / 60000) }} min
      </text>
      <text
        :x="width - PAD.right"
        :y="height - 4"
        text-anchor="end"
        class="fill-(--ui-text-muted) text-[10px]"
      >
        now
      </text>
      <template v-if="samples.length > 1">
        <path :d="area('rx')" class="fill-(--ui-primary)" fill-opacity="0.08" />
        <path :d="path('rx')" fill="none" stroke-width="2" class="stroke-(--ui-primary)" />
        <path :d="path('tx')" fill="none" stroke-width="2" class="stroke-(--ui-warning)" />
      </template>
      <text
        v-else
        :x="PAD.left + plotW / 2"
        :y="PAD.top + plotH / 2"
        text-anchor="middle"
        class="fill-(--ui-text-muted) text-xs"
      >
        Collecting…
      </text>
      <g v-if="hover">
        <line
          :x1="x(hover.t)"
          :x2="x(hover.t)"
          :y1="PAD.top"
          :y2="PAD.top + plotH"
          class="stroke-(--ui-text-muted)"
        />
        <circle
          :cx="x(hover.t)"
          :cy="y(hover.rx)"
          r="4"
          class="fill-(--ui-primary) stroke-(--ui-bg)"
          stroke-width="2"
        />
        <circle
          :cx="x(hover.t)"
          :cy="y(hover.tx)"
          r="4"
          class="fill-(--ui-warning) stroke-(--ui-bg)"
          stroke-width="2"
        />
      </g>
    </svg>
    <div
      v-if="hover"
      class="pointer-events-none absolute top-6 w-40 rounded border border-default bg-default px-2 py-1 text-xs shadow"
      :style="{ left: `${tipLeft}px` }"
    >
      <div class="text-muted">{{ clock(new Date(hover.t)) }}</div>
      <div>↓ {{ bitRate(hover.rx) }}</div>
      <div>↑ {{ bitRate(hover.tx) }}</div>
    </div>
  </div>
</template>
