<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// CrudPage: a table of one REST resource with a create/edit modal, driven
// by column and field schemas.
//
// Field: { key, label, type: text|number|password|switch|select|multiselect|tags|addrs|addr|ports|textarea|custom,
//          items (array or form => array), nullable, placeholder, hint,
//          required, show: form => bool, disabled: form => bool }
// multiselect: an array of strings picked from items (strings, or
// { label, value, description } to show a description under each name).
// addrs/addr: address list / single address; names of hosts/prefixes are
// suggested and accepted, and with `lists: true` IP lists ("@name").
// ports: a port list, with port names and their ports suggested.
// custom: the page's `field-<key>` slot ({ form }) edits the value.
// Column: { key, label, format: (row, rows) => string, class }
// Cells can be overridden with a `cell-<key>` slot, or the whole table with
// the `table` slot ({ rows, openCreate, openEdit, openView, remove, moveTo,
// saveRow, createAt }). openView shows a row read-only, for rows that can't
// be changed (the rules page's auto rules).
// Layout (AGENTS.md, GUI design rules): the row actions are the first
// column, a search field above the table filters its rows (by the columns'
// text, plus searchText(row)), Delete is in the form and asks Yes/No, and
// the form's labels sit beside their fields on a wide screen. The `table`
// slot brings its own search.
import { computed, nextTick, onMounted, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import AddrInput from '@/components/AddrInput.vue'
import PortMenu from '@/components/PortMenu.vue'
import SearchInput from '@/components/SearchInput.vue'
import TagsInput from '@/components/TagsInput.vue'
import { usePortMenu } from '@/composables/usePortMenu'
import { useRowDrag } from '@/composables/useRowDrag'
import { api as rootApi } from '@/api'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { useObjectStore } from '@/stores/objects'
import { useConfirm } from '@/composables/useConfirm'
import { useFormGuard } from '@/composables/useFormGuard'
import { inlineField, wideModal } from '@/utils/form'
import { useSearch, valuesText } from '@/utils/search'

const props = defineProps({
  title: { type: String, required: true },
  description: { type: String, default: '' },
  // Longer help shown in a popover behind an info icon next to the title.
  info: { type: String, default: '' },
  api: { type: Object, required: true },
  // shared: the rows belong to no instance; only a global admin changes them.
  shared: { type: Boolean, default: false },
  params: { type: Object, default: () => ({}) },
  columns: { type: Array, required: true },
  fields: { type: Array, required: true },
  defaults: { type: [Object, Function], default: () => ({}) },
  // The header's create button; '' leaves it out (the page adds its own).
  newLabel: { type: String, default: 'Add' },
  // Resource name for POST /api/<reorder>/reorder; enables drag-and-drop.
  reorder: { type: String, default: '' },
  blockedReason: { type: String, default: '' },
  // One row in words ("interface", "DNS zone"), for the form's title and
  // the delete prompt; default: the title without its plural s.
  noun: { type: String, default: '' },
  // itemName(row, rows) names a row in the delete prompt, with what it is
  // ("NAT rule 3"); default: the noun and the row's name.
  itemName: { type: Function, default: null },
  // editTo(row) is a route: Edit opens that page instead of the form (the
  // page then holds the row's Delete).
  editTo: { type: Function, default: null },
  // searchText(row) is more text the search finds a row by, for a column
  // whose cell slot shows what display() does not.
  searchText: { type: Function, default: null },
  // rowFilter(row) leaves out the rows the page doesn't show.
  rowFilter: { type: Function, default: null },
})
const emit = defineEmits(['changed'])

const toast = useToast()
const { confirmDelete } = useConfirm()
const noun = computed(() => props.noun || props.title.replace(/s$/, '').toLowerCase())
const describe = (row) =>
  props.itemName ? props.itemName(row, rows.value) : `${noun.value} ${row.name ?? `#${row.id}`}`
const formTitle = computed(() => {
  const t = (readOnly.value ? '' : editing.value ? 'Edit ' : 'New ') + noun.value
  return t.charAt(0).toUpperCase() + t.slice(1)
})
// A viewer sees the table and the form, read-only.
const auth = useAuthStore()
// Rows of an instance take its admin; shared ones (templates, services,
// tasks, links, instances) a global admin.
const viewing = ref(false)
const readOnly = computed(() => viewing.value || (props.shared ? !auth.isAdmin : !auth.canEdit))
const rows = ref([])
const shown = (list) => (props.rowFilter ? list.filter(props.rowFilter) : list)
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
const guard = useFormGuard(form, open)

// While searching, rows can't be dragged: the table's indices are then not
// those of rows.
const { search, filtered: shownRows } = useSearch(rows, (row) =>
  valuesText(
    props.columns.map((c) => display(c, row)),
    props.searchText?.(row),
  ),
)

const tableColumns = computed(() => [
  ...(props.reorder && !readOnly.value && !search.value.trim()
    ? [{ id: 'drag', header: '', meta: { class: { td: 'w-7 px-1' } } }]
    : []),
  { id: 'actions', header: '' },
  ...props.columns.map((c) => ({ accessorKey: c.key, header: c.label })),
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
    rows.value = shown(await props.api.list(props.params))
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
  viewing.value = false
  editing.value = null
  insertAt.value = at
  const d = typeof props.defaults === 'function' ? props.defaults() : props.defaults
  fill({ ...d, ...extra, ...props.params })
  open.value = true
}

function openEdit(row) {
  viewing.value = false
  editing.value = row
  fill(row)
  open.value = true
}

function openView(row) {
  openEdit(row)
  viewing.value = true
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

// remove deletes a row after asking; it resolves to true if it did.
async function remove(row) {
  if (!(await confirmDelete(describe(row)))) return false
  try {
    await props.api.remove(row.id)
    await load()
    emit('changed')
    return true
  } catch (err) {
    toast.add({ title: errMsg(err, 'Delete failed'), color: 'error' })
    return false
  }
}

async function removeEditing() {
  if (await remove(editing.value)) open.value = false
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
    rows.value = shown(await props.api.list(props.params))
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
const ports = usePortMenu()
const portMenu = ports.menu
const objects = useObjectStore()

onMounted(() => {
  load()
  if (props.fields.some((f) => f.type === 'ports')) objects.load().catch(() => {})
})
defineExpose({ reload: load, openEdit, openView, openCreate })
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
          v-if="newLabel && !readOnly"
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
      :open-view="openView"
      :remove="remove"
      :move-to="moveTo"
      :save-row="saveRow"
      :create-at="createAt"
    />
    <div v-else ref="tableWrap">
      <div class="mb-2">
        <SearchInput v-model="search" />
      </div>
      <UTable :data="shownRows" :columns="tableColumns" class="text-sm">
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
          <div class="flex gap-1">
            <UButton
              size="xs"
              color="neutral"
              variant="ghost"
              :icon="readOnly ? 'i-lucide-eye' : 'i-lucide-pencil'"
              :aria-label="readOnly ? 'View' : 'Edit'"
              :title="readOnly ? 'View' : 'Edit'"
              :to="editTo?.(row.original)"
              @click="editTo || openEdit(row.original)"
            />
            <slot name="row-actions" :row="row.original" />
          </div>
        </template>
        <template #empty>
          <div class="py-6 text-center text-muted">
            {{ rows.length ? 'Nothing matches the search.' : 'Nothing here yet.' }}
          </div>
        </template>
      </UTable>
    </div>
  </div>

  <UModal
    :open="open"
    :title="formTitle"
    :ui="wideModal"
    :dismissible="false"
    @update:open="guard.onUpdateOpen"
  >
    <template #body>
      <form id="crud-form" class="space-y-3" @submit.prevent="save">
        <fieldset :disabled="readOnly" class="space-y-3">
          <template v-for="f in fields" :key="f.key">
            <UFormField
              v-if="visible(f)"
              :label="f.label"
              :hint="f.hintRight"
              :help="f.hint"
              :required="f.required"
              :ui="inlineField"
            >
              <slot v-if="f.type === 'custom'" :name="`field-${f.key}`" :form="form" />
              <USwitch
                v-else-if="f.type === 'switch'"
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
              <TagsInput
                v-else-if="f.type === 'tags'"
                v-model="form[f.key]"
                :placeholder="f.placeholder"
                :disabled="!!f.disabled?.(form)"
              />
              <AddrInput
                v-else-if="f.type === 'addrs' || f.type === 'addr'"
                v-model="form[f.key]"
                :multiple="f.type === 'addrs'"
                :lists="!!f.lists"
                :placeholder="f.placeholder"
                :disabled="f.disabled?.(form)"
              />
              <div v-else-if="f.type === 'ports'" class="relative">
                <UInput
                  v-model="form[f.key]"
                  class="w-full"
                  :ui="{ base: 'font-mono' }"
                  autocomplete="off"
                  :placeholder="f.placeholder"
                  :disabled="f.disabled?.(form)"
                  @click="ports.open"
                  @input="ports.open"
                  @blur="ports.close"
                  @keydown="ports.onKeydown"
                />
                <PortMenu :menu="portMenu" @pick="ports.pick" />
              </div>
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
        </fieldset>
      </form>
    </template>
    <template #footer>
      <div class="flex w-full gap-2">
        <UButton
          v-if="editing && !readOnly"
          color="error"
          variant="ghost"
          icon="i-lucide-trash"
          label="Delete"
          @click="removeEditing"
        />
        <UButton class="ms-auto" color="neutral" variant="ghost" @click="guard.close">{{
          readOnly ? 'Close' : 'Cancel'
        }}</UButton>
        <UButton v-if="!readOnly" type="submit" form="crud-form" :loading="saving">Save</UButton>
      </div>
    </template>
  </UModal>
</template>
