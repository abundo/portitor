<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, nextTick, onMounted, ref, watch } from 'vue'

// PacketList: the capture's packet list, like Wireshark's. It shows only the
// rows in view and asks for them (load(skip, limit)) as it scrolls or as
// the capture grows. With follow on, it stays at the newest packet.
const props = defineProps({
  columns: { type: Array, required: true },
  // load(skip, limit) resolves to { matched, frames: [{ number, bg, fg, columns }] }.
  load: { type: Function, required: true },
  // Changes whenever the rows may have changed (new data, new filter).
  version: { type: [Number, String], required: true },
  follow: { type: Boolean, default: false },
  selected: { type: Number, default: null },
})
const emit = defineEmits(['select', 'update:follow'])

const rowH = 22
const box = ref(null)
const matched = ref(0)
const rows = ref([])
const first = ref(0)
let height = 400
let seq = 0

const widths = computed(() =>
  props.columns.map((c) => {
    switch (c) {
      case 'No.':
        return '4.5rem'
      case 'Time':
        return '6.5rem'
      case 'Source':
      case 'Destination':
        return 'minmax(8rem, 14rem)'
      case 'Protocol':
        return '5.5rem'
      case 'Length':
        return '4rem'
      default:
        return 'minmax(12rem, 1fr)'
    }
  }),
)
const grid = computed(() => ({ gridTemplateColumns: widths.value.join(' ') }))

async function refresh() {
  const el = box.value
  if (!el) return
  height = el.clientHeight
  const count = Math.ceil(height / rowH) + 20
  const start = Math.max(0, Math.floor(el.scrollTop / rowH) - 10)
  const my = ++seq
  const res = await props.load(start, count)
  if (my !== seq) return
  matched.value = res.matched
  rows.value = res.frames
  first.value = start
  if (props.follow) {
    await nextTick()
    const bottom = res.matched * rowH - height
    if (bottom > 0 && Math.abs(el.scrollTop - bottom) > 1) {
      el.scrollTop = bottom
      refresh()
    }
  }
}

let lastTop = 0
function onScroll() {
  const el = box.value
  // Scrolling up leaves follow mode; scrolling to the end enters it.
  if (el.scrollTop < lastTop - 2 && props.follow) emit('update:follow', false)
  else if (
    el.scrollTop + el.clientHeight >= el.scrollHeight - rowH &&
    !props.follow &&
    matched.value
  )
    emit('update:follow', true)
  lastTop = el.scrollTop
  refresh()
}

watch(
  () => props.version,
  () => refresh(),
)
watch(
  () => props.follow,
  (f) => f && refresh(),
)
onMounted(refresh)

const color = (n) => '#' + (n >>> 0).toString(16).padStart(6, '0').slice(-6)
const rowStyle = (f) =>
  f.bg || f.fg ? { backgroundColor: color(f.bg), color: color(f.fg) } : undefined

// Arrow keys move the selection.
function onKey(e) {
  if (!rows.value.length) return
  const i = rows.value.findIndex((f) => f.number === props.selected)
  const next = e.key === 'ArrowDown' ? i + 1 : e.key === 'ArrowUp' ? i - 1 : null
  if (next === null) return
  e.preventDefault()
  const f = rows.value[Math.max(0, Math.min(rows.value.length - 1, next))]
  if (f) emit('select', f.number)
}
</script>

<template>
  <div
    ref="box"
    class="relative h-full overflow-auto rounded border border-default font-mono text-xs"
    tabindex="0"
    @scroll="onScroll"
    @keydown="onKey"
  >
    <div class="sticky top-0 z-10 grid bg-elevated font-semibold" :style="grid">
      <div v-for="c in columns" :key="c" class="truncate border-b border-default px-2 py-1">
        {{ c }}
      </div>
    </div>
    <div :style="{ height: `${matched * rowH}px` }" class="relative">
      <div
        v-for="(f, i) in rows"
        :key="f.number"
        class="absolute inset-x-0 grid cursor-default"
        :class="f.number === selected ? 'outline-2 -outline-offset-2 outline-primary' : ''"
        :style="{ ...grid, top: `${(first + i) * rowH}px`, height: `${rowH}px`, ...rowStyle(f) }"
        @click="emit('select', f.number)"
      >
        <div v-for="(v, j) in f.columns" :key="j" class="truncate px-2 leading-[22px]" :title="v">
          {{ v }}
        </div>
      </div>
    </div>
    <div v-if="!matched" class="p-4 text-center text-muted">No packets</div>
  </div>
</template>
