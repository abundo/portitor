<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// DataGrid: the data grid (AG Grid Community, MIT) for every table: columns
// resized and moved by dragging, sorted by a click on the header (shift-click
// adds a column to the sort), filtered per column in the row under the
// header, cells edited in place, rows and columns virtualized. A SearchInput
// above it filters by every column (AGENTS.md, GUI design rules).
//
// columns are AG Grid column definitions (field, headerName, valueFormatter,
// editable, cellEditor, ...). With `edit`, an Edit button (an eye with
// `viewOnly(row)`) is the first column, pinned, and emits edit(row). An edit
// in place emits cell-edit({ row, field, value, oldValue, revert }); revert()
// puts the old value back when the save fails.
//
// The `row-actions` slot ({ row }) adds buttons after Edit (actionsWidth
// px wide in all). With `reorder`, rows are dragged by a grip in the first
// column (not while sorted or filtered) and reorder(rows) gives the new order.
//
// stateKey keeps each viewer's column widths, order, sort and filters in
// localStorage (a convenience: the grid works without it).
import { computed, defineComponent, h, ref, shallowRef, useSlots } from 'vue'
import { AgGridVue } from 'ag-grid-vue3'
import {
  CellStyleModule,
  CheckboxEditorModule,
  ClientSideRowModelModule,
  ColumnApiModule,
  DateFilterModule,
  LargeTextEditorModule,
  ModuleRegistry,
  NumberEditorModule,
  NumberFilterModule,
  QuickFilterModule,
  RowDragModule,
  SelectEditorModule,
  TextEditorModule,
  TextFilterModule,
  themeQuartz,
} from 'ag-grid-community'
import UButton from '@nuxt/ui/components/Button.vue'
import SearchInput from '@/components/SearchInput.vue'

// Only the modules the grid uses, to keep the bundle small.
ModuleRegistry.registerModules([
  ClientSideRowModelModule,
  CellStyleModule,
  ColumnApiModule,
  QuickFilterModule,
  RowDragModule,
  TextFilterModule,
  NumberFilterModule,
  DateFilterModule,
  TextEditorModule,
  LargeTextEditorModule,
  NumberEditorModule,
  SelectEditorModule,
  CheckboxEditorModule,
])

const props = defineProps({
  rows: { type: Array, required: true },
  columns: { type: Array, required: true },
  edit: { type: Boolean, default: false },
  viewOnly: { type: Function, default: () => false },
  stateKey: { type: String, default: '' },
  rowId: { type: Function, default: (row) => String(row.id ?? row.name) },
  // Height of the grid; 'auto' grows with its rows (no inner scrolling,
  // fine up to a few hundred rows).
  height: { type: String, default: 'auto' },
  emptyText: { type: String, default: 'Nothing here yet.' },
  reorder: { type: Boolean, default: false },
  actionsWidth: { type: Number, default: 0 },
})
const emit = defineEmits(['edit', 'cell-edit', 'reorder'])
const slots = useSlots()

const search = ref('')
const api = shallowRef(null)

// The theme follows Nuxt UI's tokens, so light and dark mode come with it.
const theme = themeQuartz.withParams({
  fontFamily: 'inherit',
  fontSize: 13,
  spacing: 4,
  rowHeight: 30,
  headerHeight: 32,
  wrapperBorderRadius: 'var(--ui-radius)',
  borderRadius: 'var(--ui-radius)',
  backgroundColor: 'var(--ui-bg)',
  foregroundColor: 'var(--ui-text)',
  headerBackgroundColor: 'var(--ui-bg-elevated)',
  headerTextColor: 'var(--ui-text-highlighted)',
  borderColor: 'var(--ui-border)',
  rowHoverColor: 'var(--ui-bg-elevated)',
  oddRowBackgroundColor: 'var(--ui-bg)',
  accentColor: 'var(--ui-primary)',
  inputBackgroundColor: 'var(--ui-bg)',
  inputBorder: { color: 'var(--ui-border-accented)' },
  chromeBackgroundColor: 'var(--ui-bg-elevated)',
  menuBackgroundColor: 'var(--ui-bg-elevated)',
  columnBorder: { color: 'var(--ui-border)' },
  cellHorizontalPadding: 8,
})

const EditCell = defineComponent({
  props: { params: Object },
  setup(p) {
    return () => {
      const ro = props.viewOnly(p.params.data)
      const btn = h(UButton, {
        size: 'xs',
        variant: 'outline',
        icon: ro ? 'i-lucide-eye' : 'i-lucide-pencil',
        title: ro ? 'View' : 'Edit',
        'aria-label': ro ? 'View' : 'Edit',
        onClick: () => emit('edit', p.params.data),
      })
      if (!slots['row-actions']) return btn
      return h('div', { class: 'flex items-center gap-1' }, [
        btn,
        slots['row-actions']({ row: p.params.data }),
      ])
    }
  },
})

const columnDefs = computed(() => [
  ...(props.edit || props.reorder
    ? [
        {
          colId: '_edit',
          headerName: '',
          width: (props.actionsWidth || (props.edit ? 44 : 0)) + (props.reorder ? 24 : 0),
          minWidth: 0,
          flex: 0,
          rowDrag: props.reorder,
          pinned: 'left',
          lockPosition: 'left',
          sortable: false,
          filter: false,
          resizable: false,
          suppressMovable: true,
          editable: false,
          suppressHeaderMenuButton: true,
          cellRenderer: props.edit ? EditCell : undefined,
          cellClass: 'dg-edit-cell',
        },
      ]
    : []),
  ...props.columns,
])

const defaultColDef = {
  sortable: true,
  resizable: true,
  filter: true,
  floatingFilter: true,
  suppressHeaderMenuButton: true,
  minWidth: 70,
  flex: 1,
}

function saveState() {
  if (!props.stateKey || !api.value) return
  try {
    localStorage.setItem(
      `portitor-grid:${props.stateKey}`,
      JSON.stringify({
        columns: api.value.getColumnState(),
        filter: api.value.getFilterModel(),
      }),
    )
  } catch {
    // no storage: the layout isn't kept
  }
}

function onGridReady(e) {
  api.value = e.api
  if (!props.stateKey) return
  try {
    const s = JSON.parse(localStorage.getItem(`portitor-grid:${props.stateKey}`) ?? 'null')
    if (s?.columns) e.api.applyColumnState({ state: s.columns, applyOrder: true })
    if (s?.filter) e.api.setFilterModel(s.filter)
  } catch {
    // a broken or missing layout: the default
  }
}

function onCellValueChanged(e) {
  if (e.oldValue === e.newValue) return
  emit('cell-edit', {
    row: e.data,
    field: e.colDef.field,
    value: e.newValue,
    oldValue: e.oldValue,
    revert: () => e.node.setDataValue(e.colDef.field, e.oldValue),
  })
}

function onRowDragEnd() {
  const order = []
  api.value.forEachNode((n) => order.push(n.data))
  emit('reorder', order)
}

function resetLayout() {
  try {
    localStorage.removeItem(`portitor-grid:${props.stateKey}`)
  } catch {
    // nothing kept
  }
  api.value?.resetColumnState()
  api.value?.setFilterModel(null)
}

defineExpose({ api, resetLayout })
</script>

<template>
  <div>
    <div class="mb-2 flex items-center gap-2">
      <SearchInput v-model="search" />
      <UButton
        v-if="stateKey"
        size="sm"
        color="neutral"
        variant="ghost"
        icon="i-lucide-rotate-ccw"
        title="Reset the columns' widths, order, sort and filters"
        aria-label="Reset layout"
        @click="resetLayout"
      />
    </div>
    <AgGridVue
      :class="{ 'dg-rows': rows.length }"
      :theme="theme"
      :row-data="rows"
      :column-defs="columnDefs"
      :default-col-def="defaultColDef"
      :get-row-id="(p) => rowId(p.data)"
      :quick-filter-text="search"
      :dom-layout="height === 'auto' ? 'autoHeight' : 'normal'"
      :style="height === 'auto' ? undefined : { height }"
      :single-click-edit="false"
      :stop-editing-when-cells-lose-focus="true"
      :enable-cell-text-selection="true"
      :ensure-dom-order="true"
      :overlay-no-rows-template="`<span class='dg-empty'>${emptyText}</span>`"
      :animate-rows="false"
      :row-drag-managed="reorder"
      :include-hidden-columns-in-quick-filter="true"
      @grid-ready="onGridReady"
      @row-drag-end="onRowDragEnd"
      @cell-value-changed="onCellValueChanged"
      @column-resized="(e) => e.finished && saveState()"
      @column-moved="(e) => e.finished && saveState()"
      @sort-changed="saveState"
      @filter-changed="saveState"
    />
  </div>
</template>

<style>
/* One line per row: a cell's text that doesn't fit ends in an ellipsis. */
.ag-root-wrapper .ag-cell:not(.ag-cell-inline-editing) {
  display: flex;
  align-items: center;
  overflow: hidden;
}
.ag-root-wrapper .ag-cell .ag-cell-wrapper,
.ag-root-wrapper .ag-cell .ag-cell-value {
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
}
.dg-clip {
  display: block;
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.dg-clip > * {
  white-space: nowrap;
}
.dg-edit-cell {
  display: flex;
  align-items: center;
  padding-inline: 6px !important;
}
/* Auto height keeps room for the no-rows message; not needed with rows. */
.dg-rows .ag-layout-auto-height .ag-center-cols-viewport,
.dg-rows .ag-layout-auto-height .ag-center-cols-container {
  min-height: 0 !important;
}
.dg-empty {
  color: var(--ui-text-muted);
}
</style>
