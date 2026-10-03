<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// EntriesEditor: a list of entries edited in place inside a form (a prefix
// list's entries, BGP networks), one row per entry. Like TagsInput it is a
// field's value, not a page table: each row has a remove button, and with
// `ordered` up/down buttons, since the order of the entries is what
// decides (AS path and community lists).
//
// Column: { key, label, type: text|number|select|switch, items (array or
// row => array; a select's '' value shows as "—"), placeholder, class }
const model = defineModel({ type: Array, default: () => [] })
const props = defineProps({
  columns: { type: Array, required: true },
  // newEntry() is the row Add appends.
  newEntry: { type: Function, required: true },
  ordered: { type: Boolean, default: false },
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
  const list = [...model.value]
  const [row] = list.splice(i, 1)
  list.splice(i + d, 0, row)
  model.value = list
}
</script>

<template>
  <div class="w-full">
    <div v-if="model.length" class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr class="text-left text-xs text-muted">
            <th v-for="col in columns" :key="col.key" class="px-1 py-1 font-medium">
              {{ col.label }}
            </th>
            <th class="w-px" />
          </tr>
        </thead>
        <tbody>
          <tr v-for="(row, i) in model" :key="i">
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
