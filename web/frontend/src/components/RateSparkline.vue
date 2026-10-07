<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed } from 'vue'
import { bitRate } from '@/utils/bytes'

// A receive/send rate sparkline over a fixed time window (the newest sample at
// the right edge), with the current rates beside it.
const props = defineProps({
  samples: { type: Array, default: () => [] }, // { t, rx, tx } in bytes/s
  window: { type: Number, default: 5 * 60 * 1000 },
})

const W = 120
const H = 28

const max = computed(() => Math.max(1, ...props.samples.flatMap((s) => [s.rx, s.tx])))
const path = (key) => {
  const end = props.samples.at(-1)?.t ?? 0
  return props.samples
    .map((s, n) => {
      const x = W - ((end - s.t) / props.window) * W
      const y = H - 1 - (s[key] / max.value) * (H - 2)
      return `${n ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`
    })
    .join(' ')
}
const last = computed(() => props.samples.at(-1))
const rate = bitRate
const title = computed(() =>
  last.value
    ? `Last 5 minutes, peak ${rate(max.value)}\n↓ ${rate(last.value.rx)}  ↑ ${rate(last.value.tx)}`
    : 'Collecting…',
)
</script>

<template>
  <div class="flex items-center gap-2" :title="title">
    <svg :width="W" :height="H" :viewBox="`0 0 ${W} ${H}`" class="shrink-0">
      <line :x1="0" :x2="W" :y1="H - 0.5" :y2="H - 0.5" class="stroke-(--ui-border)" />
      <path
        v-if="samples.length > 1"
        :d="path('rx')"
        fill="none"
        stroke-width="1.5"
        class="stroke-(--ui-primary)"
      />
      <path
        v-if="samples.length > 1"
        :d="path('tx')"
        fill="none"
        stroke-width="1.5"
        class="stroke-(--ui-warning)"
      />
    </svg>
    <div v-if="last" class="text-xs leading-tight whitespace-nowrap">
      <div class="text-primary">↓ {{ rate(last.rx) }}</div>
      <div class="text-warning">↑ {{ rate(last.tx) }}</div>
    </div>
  </div>
</template>
