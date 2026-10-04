<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// EntriesEditor: a list of entries edited in place inside a form (a prefix
// list's entries, BGP networks), one row per entry. Like TagsInput it is a
// field's value, not a page table: each row has a remove button, and with
// `ordered` up/down buttons and a grip to drag a row by, since the order of
// the entries is what decides (AS path and community lists). With `seqKey`
// (prefix lists) a move renumbers the entries with the sequence numbers they
// had, so the order stays the one shown; all 0 (auto) stay 0.
import { ref } from 'vue'

//
// Column: { key, label, type: text|number|select|switch, items (array or
// row => array; a select's '' value shows as "—"), placeholder, class }
const model = defineModel({ type: Array, default: () => [] })
const props = defineProps({
  columns: { type: Array, required: true },
  // newEntry() is the row Add appends.
  newEntry: { type: Function, required: true },
  ordered: { type: Boolean, default: false },
  seqKey: { type: String, default: '' },
  disabled: { type: Boolean, default: false },
  addLabel: { type: String, default: 'Add entry' },
  empty: { type: String, default: 'No entries.' },
})

// Reka's select can't hold '', so the empty choice is NONE in the select.
const NONE = '\u0000'

function itemsOf(col, row) {
  const list = typeof col.items === 'function' ? col.items(row) : (col.items ?? [])
  return list.map((it) =>
    typeof it === 'object' ? { ...it, value: it.value === '' ? NONE : it.value } : it,
  )
}

function getSelect(row, key) {
  return row[key] === '' || row[key] == null ? NONE : row[key]
}

function setSelect(row, key, v) {
  row[key] = v === NONE ? '' : v
}

function setNumber(row, key, v) {
  row[key] = v === '' || v == null ? 0 : Number(v)
}

function add() {
  model.value = [...model.value, props.newEntry(model.value)]
}

function remove(i) {
  model.value = model.value.filter((_, j) => j !== i)
}

function move(i, d) {
  moveTo(i, i + d)
}

// moveTo moves row from to position to (in the list without it).
function moveTo(from, to) {
  const list = [...model.value]
  const [row] = list.splice(from, 1)
  list.splice(to, 0, row)
  const k = props.seqKey
  if (k && list.some((r) => r[k])) {
    let seqs = list.map((r) => r[k] || 0).sort((a, b) => a - b)
    if (new Set(seqs).size !== seqs.length || seqs.includes(0))
      seqs = seqs.map((_, j) => (j + 1) * 10)
    model.value = list.map((r, j) => ({ ...r, [k]: seqs[j] }))
  } else model.value = list
}

// Drag and drop: dropAt is the gap before that row (model.length after the
// last).
const rowEls = ref([])
const dragFrom = ref(null)
const dropAt = ref(null)

function onPointerDown(i, ev) {
  if (ev.button !== 0) return
  ev.preventDefault()
  ev.currentTarget.setPointerCapture(ev.pointerId)
  dragFrom.value = i
  dropAt.value = null
}

function onPointerMove(ev) {
  if (dragFrom.value == null) return
  dropAt.value = rowEls.value.filter((el) => {
    const r = el.getBoundingClientRect()
    return r.top + r.height / 2 < ev.clientY
  }).length
}

function onPointerUp() {
  const from = dragFrom.value
  const to = dropAt.value
  dragFrom.value = dropAt.value = null
  if (from == null || to == null || to === from || to === from + 1) return
  moveTo(from, to > from ? to - 1 : to)
}
</script>

<template>
  <div class="w-full">
    <div v-if="model.length" class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr class="text-left text-xs text-muted">
            <th v-if="ordered && !disabled" class="w-px" />
            <th v-for="col in columns" :key="col.key" class="px-1 py-1 font-medium">
              {{ col.label }}
            </th>
            <th class="w-px" />
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="(row, i) in model"
            :key="i"
            ref="rowEls"
            :class="{
              'opacity-50': dragFrom === i,
              'border-t-2 border-t-primary': dropAt === i,
              'border-b-2 border-b-primary': dropAt === model.length && i === model.length - 1,
            }"
          >
            <td v-if="ordered && !disabled" class="w-px py-1 pe-1">
              <span
                class="inline-flex cursor-grab touch-none items-center text-muted select-none active:cursor-grabbing"
                title="Drag to reorder"
                @pointerdown="onPointerDown(i, $event)"
                @pointermove="onPointerMove"
                @pointerup="onPointerUp"
                @pointercancel="dragFrom = dropAt = null"
              >
                <UIcon name="i-lucide-grip-vertical" class="pointer-events-none size-3.5" />
              </span>
            </td>
            <td v-for="col in columns" :key="col.key" class="px-1 py-1" :class="col.class">
              <USwitch
                v-if="col.type === 'switch'"
                v-model="row[col.key]"
                size="sm"
                :disabled="disabled"
              />
              <USelect
                v-else-if="col.type === 'select'"
                :model-value="getSelect(row, col.key)"
                :items="itemsOf(col, row)"
                size="sm"
                class="w-full min-w-20"
                :disabled="disabled"
                @update:model-value="(v) => setSelect(row, col.key, v)"
              />
              <UInput
                v-else-if="col.type === 'number'"
                :model-value="row[col.key] || ''"
                type="number"
                size="sm"
                class="w-full min-w-12"
                :placeholder="col.placeholder"
                :disabled="disabled"
                @update:model-value="(v) => setNumber(row, col.key, v)"
              />
              <UInput
                v-else
                v-model="row[col.key]"
                size="sm"
                class="w-full min-w-28"
                :ui="{ base: 'font-mono' }"
                :placeholder="col.placeholder"
                :disabled="disabled"
              />
            </td>
            <td class="py-1 whitespace-nowrap">
              <template v-if="ordered">
                <UButton
                  size="xs"
                  color="neutral"
                  variant="ghost"
                  icon="i-lucide-arrow-up"
                  aria-label="Move up"
                  :disabled="disabled || i === 0"
                  @click="move(i, -1)"
                />
                <UButton
                  size="xs"
                  color="neutral"
                  variant="ghost"
                  icon="i-lucide-arrow-down"
                  aria-label="Move down"
                  :disabled="disabled || i === model.length - 1"
                  @click="move(i, 1)"
                />
              </template>
              <UButton
                size="xs"
                color="neutral"
                variant="ghost"
                icon="i-lucide-x"
                aria-label="Remove entry"
                title="Remove entry"
                :disabled="disabled"
                @click="remove(i)"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p v-else class="py-1 text-sm text-muted">{{ empty }}</p>
    <UButton
      v-if="!disabled"
      class="mt-1"
      size="xs"
      color="neutral"
      variant="outline"
      icon="i-lucide-plus"
      :label="addLabel"
      @click="add"
    />
  </div>
</template>
