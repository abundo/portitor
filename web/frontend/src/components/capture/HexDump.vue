<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed } from 'vue'

// HexDump: a packet's bytes, 16 per line with offset and ASCII; the bytes
// of the selected tree line are highlighted.
const props = defineProps({
  data: { type: String, default: '' }, // base64
  start: { type: Number, default: 0 },
  length: { type: Number, default: 0 },
})

const bytes = computed(() => {
  try {
    return Uint8Array.from(atob(props.data), (c) => c.charCodeAt(0))
  } catch {
    return new Uint8Array()
  }
})
const lines = computed(() => {
  const out = []
  for (let off = 0; off < bytes.value.length; off += 16) {
    out.push({ off, bytes: [...bytes.value.subarray(off, off + 16)] })
  }
  return out
})
const hi = (i) => props.length > 0 && i >= props.start && i < props.start + props.length
// pad fills a short last line so its ASCII lines up.
const pad = (n) => '   '.repeat(16 - n) + (n <= 7 ? ' ' : '')
const hex = (b) => b.toString(16).padStart(2, '0')
const ascii = (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')
</script>

<template>
  <div class="font-mono text-xs leading-5 whitespace-pre">
    <div v-for="l in lines" :key="l.off" class="flex gap-3">
      <span class="text-muted">{{ l.off.toString(16).padStart(4, '0') }}</span>
      <span
        ><span v-for="(b, j) in l.bytes" :key="j" :class="hi(l.off + j) ? 'bg-primary/30' : ''"
          >{{ hex(b) }}{{ j === 7 ? '  ' : ' ' }}</span
        >{{ pad(l.bytes.length) }}</span
      >
      <span
        ><span v-for="(b, j) in l.bytes" :key="j" :class="hi(l.off + j) ? 'bg-primary/30' : ''">{{
          ascii(b)
        }}</span></span
      >
    </div>
  </div>
</template>
