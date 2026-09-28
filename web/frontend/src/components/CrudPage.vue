<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// CrudPage: a table of one REST resource with a create/edit modal, driven
// by column and field schemas.
//
// Field: { key, label, type: text|number|password|switch|select|multiselect|tags|addrs|addr|textarea,
//          items (array or form => array), nullable, placeholder, hint,
//          required, show: form => bool, disabled: form => bool }
// multiselect: an array of strings picked from items (strings, or
// { label, value, description } to show a description under each name).
// addrs/addr: address list / single address; names of hosts/prefixes are
// suggested and accepted, and with `lists: true` IP lists ("@name").
// Column: { key, label, format: (row, rows) => string, class }
// Cells can be overridden with a `cell-<key>` slot, or the whole table with
// the `table` slot ({ rows, openCreate, openEdit, remove, moveTo, saveRow,
// createAt }).
import { computed, nextTick, onMounted, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import AddrInput from '@/components/AddrInput.vue'
import { useRowDrag } from '@/composables/useRowDrag'
import { api as rootApi } from '@/api'
import { errMsg } from '@/api/http'

const props = defineProps({
  title: { type: String, required: true },
  description: { type: String, default: '' },
  // Longer help shown in a popover behind an info icon next to the title.
  info: { type: String, default: '' },
  api: { type: Object, required: true },
  params: { type: Object, default: () => ({}) },
  columns: { type: Array, required: true },
  fields: { type: Array, required: true },
  defaults: { type: [Object, Function], default: () => ({}) },
  newLabel: { type: String, default: 'Add' },
  // Resource name for POST /api/<reorder>/reorder; enables drag-and-drop.
  reorder: { type: String, default: '' },
  blockedReason: { type: String, default: '' },
  // itemName(row, rows) names a row in prompts.
  itemName: { type: Function, default: (row) => row.name ?? `#${row.id}` },
})
const emit = defineEmits(['changed'])

const toast = useToast()
const rows = ref([])
const loading = ref(true)
const open = ref(false)
const saving = ref(false)
const editing = ref(null)
const form = reactive({})
// Index in rows where the row being created goes (with `reorder`); null
// appends it.
const insertAt = ref(null)
const NONE = 0
// The info popover opens on hover, and on a click for touch screens.
const infoOpen = ref(false)

const tableColumns = computed(() => [
  ...(props.reorder ? [{ id: 'drag', header: '', meta: { class: { td: 'w-7 px-1' } } }] : []),
  ...props.columns.map((c) => ({ accessorKey: c.key, header: c.label })),
  { id: 'actions', header: '' },
])

function display(col, row) {
  if (col.format) return col.format(row, rows.value)
  const v = row[col.key]
  if (Array.isArray(v)) return v.join(', ')
  if (typeof v === 'boolean') return v ? 'yes' : ''
  return v ?? ''
}

function itemsOf(f) {
  const list = typeof f.items === 'function' ? f.items(form) : (f.items ?? [])
  return f.nullable ? [{ label: '—', value: NONE }, ...list] : list
}

// selectedItem returns the select item the form holds, to show its
// description next to the chosen name.
function selectedItem(f) {
  return itemsOf(f).find((it) => typeof it === 'object' && it.value === form[f.key])
}

// multiItems returns a multiselect's items as objects, plus values the form
// holds but items lack, so they stay visible.
function multiItems(f) {
  const list = itemsOf(f).map((it) => (typeof it === 'object' ? it : { label: it, value: it }))
  const known = new Set(list.map((it) => it.value))
  return [...list, ...form[f.key].filter((v) => !known.has(v)).map((v) => ({ label: v, value: v }))]
}

function visible(f) {
  return f.show ? f.show(form) : true
}

async function load() {
  loading.value = true
  try {
    rows.value = await props.api.list(props.params)
  } catch (err) {
    toast.add({ title: errMsg(err, `Failed to load ${props.title}`), color: 'error' })
  } finally {
    loading.value = false
  }
}

function fill(src) {
  for (const k of Object.keys(form)) delete form[k]
  Object.assign(form, JSON.parse(JSON.stringify(src)))
  for (const f of props.fields) {
    if (f.nullable && form[f.key] == null) form[f.key] = NONE
    if (['tags', 'addrs', 'multiselect'].includes(f.type) && !Array.isArray(form[f.key]))
      form[f.key] = []
    if (f.type === 'addr' && form[f.key] == null) form[f.key] = ''
  }
}

// openCreate opens the form for a new row; `extra` overrides the defaults
// and `at` is the index in rows to insert it at.
function openCreate(extra = {}, at = null) {
  editing.value = null
  insertAt.value = at
  const d = typeof props.defaults === 'function' ? props.defaults() : props.defaults
  fill({ ...d, ...extra, ...props.params })
  open.value = true
}

function openEdit(row) {
  editing.value = row
  fill(row)
  open.value = true
}

async function save() {
  saving.value = true
  const body = { ...form }
  for (const f of props.fields) {
    if (f.nullable && body[f.key] === NONE) body[f.key] = null
    if (f.type === 'number' && body[f.key] !== null && body[f.key] !== '')
      body[f.key] = Number(body[f.key] ?? 0)
  }
  try {
    if (editing.value) await props.api.update(editing.value.id, body)
    else {
      const created = await props.api.create(body)
      if (insertAt.value != null) await placeAt(created, insertAt.value)
    }
    open.value = false
    await load()
    emit('changed')
  } catch (err) {
    toast.add({ title: errMsg(err, 'Save failed'), color: 'error' })
  } finally {
    saving.value = false
  }
}

async function remove(row) {
  if (!window.confirm(`Delete ${props.itemName(row, rows.value)}?`)) return
  try {
    await props.api.remove(row.id)
    await load()
    emit('changed')
  } catch (err) {
    toast.add({ title: errMsg(err, 'Delete failed'), color: 'error' })
  }
}

// Saves one row edited in place (a custom table); reloads on failure.
async function saveRow(row) {
  const body = { ...row }
  for (const f of props.fields) if (f.nullable && body[f.key] === NONE) body[f.key] = null
  try {
    const saved = await props.api.update(row.id, body)
    const cur = rows.value.find((r) => r.id === row.id)
    if (cur && saved) Object.assign(cur, saved)
    emit('changed')
    return true
  } catch (err) {
    toast.add({ title: errMsg(err, 'Save failed'), color: 'error' })
    await load()
    return false
  }
}

async function moveTo(from, to) {
  const list = [...rows.value]
  const [item] = list.splice(from, 1)
  list.splice(to, 0, item)
  // The server numbers positions like this; keep rows in step so a later
  // PUT of a row doesn't send back a stale position.
  list.forEach((r, i) => (r.position = (i + 1) * 10))
  rows.value = list
  try {
    await rootApi.reorder(
      props.reorder,
      list.map((r) => r.id),
    )
    emit('changed')
  } catch (err) {
    toast.add({ title: errMsg(err, 'Reorder failed'), color: 'error' })
    await load()
  }
}

// placeAt moves a just created row to index `at` of rows.
async function placeAt(created, at) {
  const ids = rows.value.map((r) => r.id)
  ids.splice(at, 0, created.id)
  await rootApi.reorder(props.reorder, ids)
}

// createAt creates a row without the form and inserts it at index `at` of
// rows; it resolves to the created row (null on failure) once the table
// shows it.
async function createAt(body, at) {
  try {
    const created = await props.api.create({ ...body, ...props.params })
    await placeAt(created, at)
    rows.value = await props.api.list(props.params)
    emit('changed')
    await nextTick()
    return created
  } catch (err) {
    toast.add({ title: errMsg(err, 'Save failed'), color: 'error' })
    await load()
    return null
  }
}

const tableWrap = ref(null)
const { onPointerDown } = useRowDrag({
  wrap: tableWrap,
  label: (i) => props.itemName(rows.value[i], rows.value),
  onMove: moveTo,
})

watch(() => JSON.stringify(props.params), load)
onMounted(load)
defineExpose({ reload: load, openEdit, openCreate })
</script>

<template>
  <div class="card">
    <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <div class="flex items-center gap-1.5">
          <div class="text-lg font-semibold">{{ title }}</div>
          <UPopover
            v-if="info"
            v-model:open="infoOpen"
            mode="hover"
            :open-delay="100"
            :content="{ side: 'bottom', align: 'start' }"
          >
            <UButton
              size="xs"
              color="neutral"
              variant="ghost"
              icon="i-lucide-info"
              aria-label="About this page"
              @click="infoOpen = true"
            />
            <template #content>
              <p class="max-w-md p-3 text-sm text-muted">{{ info }}</p>
            </template>
          </UPopover>
        </div>
        <p v-if="description" class="max-w-3xl text-sm text-muted">{{ description }}</p>
      </div>
      <div class="flex items-center gap-2">
        <slot name="toolbar" />
        <UButton
          icon="i-lucide-plus"
          :label="newLabel"
          :disabled="!!blockedReason"
          :title="blockedReason || undefined"
          @click="openCreate()"
        />
      </div>
    </div>
    <UAlert
      v-if="blockedReason"
      color="neutral"
      variant="subtle"
      :title="blockedReason"
      class="mb-3"
    />

    <div v-if="loading" class="flex justify-center p-6">
      <UIcon name="i-lucide-loader-2" class="size-7 animate-spin" />
    </div>
    <slot
      v-else-if="$slots.table"
      name="table"
      :rows="rows"
      :open-create="openCreate"
      :open-edit="openEdit"
      :remove="remove"
      :move-to="moveTo"
      :save-row="saveRow"
      :create-at="createAt"
    />
    <div v-else ref="tableWrap">
      <UTable :data="rows" :columns="tableColumns" class="text-sm">
        <template #drag-cell="{ row }">
          <span
            class="inline-flex cursor-grab touch-none items-center text-muted select-none active:cursor-grabbing"
            title="Drag to reorder"
            @pointerdown="onPointerDown(row.index, $event)"
          >
            <UIcon name="i-lucide-grip-vertical" class="pointer-events-none size-3.5" />
          </span>
        </template>
        <template v-for="col in columns" :key="col.key" #[`${col.key}-cell`]="{ row }">
          <slot :name="`cell-${col.key}`" :row="row.original">
            <span :class="col.class">{{ display(col, row.original) }}</span>
          </slot>
        </template>
        <template #actions-cell="{ row }">
          <div class="flex justify-end gap-1">
            <slot name="row-actions" :row="row.original" />
            <UButton
              size="xs"
              color="neutral"
              variant="ghost"
              icon="i-lucide-pencil"
              @click="openEdit(row.original)"
            />
            <UButton
              size="xs"
              color="error"
              variant="ghost"
              icon="i-lucide-trash"
              @click="remove(row.original)"
            />
          </div>
        </template>
        <template #empty>
          <div class="py-6 text-center text-muted">Nothing here yet.</div>
        </template>
      </UTable>
    </div>
  </div>

  <UModal
    v-model:open="open"
    :title="(editing ? 'Edit ' : 'New ') + title.replace(/s$/, '').toLowerCase()"
  >
    <template #body>
      <form id="crud-form" class="space-y-3" @submit.prevent="save">
        <template v-for="f in fields" :key="f.key">
          <UFormField
            v-if="visible(f)"
            :label="f.label"
            :hint="f.hintRight"
            :help="f.hint"
            :required="f.required"
          >
            <USwitch
              v-if="f.type === 'switch'"
              v-model="form[f.key]"
              :disabled="f.disabled?.(form)"
            />
            <USelect
              v-else-if="f.type === 'select'"
              v-model="form[f.key]"
              :items="itemsOf(f)"
              class="w-full"
              :disabled="f.disabled?.(form)"
            >
              <template v-if="selectedItem(f)" #default>
                <span class="truncate">
                  {{ selectedItem(f).label }}
                  <span v-if="selectedItem(f).description" class="text-muted">
                    — {{ selectedItem(f).description }}
                  </span>
                </span>
              </template>
            </USelect>
            <USelectMenu
              v-else-if="f.type === 'multiselect'"
              v-model="form[f.key]"
              multiple
              :items="multiItems(f)"
              value-key="value"
              :filter-fields="['label', 'description']"
              class="w-full"
              :placeholder="f.placeholder"
              :disabled="f.disabled?.(form)"
            />
            <UInputTags
              v-else-if="f.type === 'tags'"
              v-model="form[f.key]"
              class="w-full"
              :placeholder="f.placeholder"
              add-on-blur
              add-on-paste
            />
            <AddrInput
              v-else-if="f.type === 'addrs' || f.type === 'addr'"
              v-model="form[f.key]"
              :multiple="f.type === 'addrs'"
              :lists="!!f.lists"
              :placeholder="f.placeholder"
              :disabled="f.disabled?.(form)"
            />
            <UTextarea
              v-else-if="f.type === 'textarea'"
              v-model="form[f.key]"
              class="w-full"
              :rows="3"
            />
            <UInput
              v-else
              v-model="form[f.key]"
              :type="['number', 'password'].includes(f.type) ? f.type : 'text'"
              :autocomplete="f.type === 'password' ? 'new-password' : undefined"
              class="w-full"
              :placeholder="f.placeholder"
              :required="f.required"
              :disabled="f.disabled?.(form)"
            />
          </UFormField>
        </template>
        <slot name="form-extra" :form="form" :editing="editing" />
      </form>
    </template>
    <template #footer>
      <div class="flex w-full justify-end gap-2">
        <UButton color="neutral" variant="ghost" @click="open = false">Cancel</UButton>
        <UButton type="submit" form="crud-form" :loading="saving">Save</UButton>
      </div>
    </template>
  </UModal>
</template>
