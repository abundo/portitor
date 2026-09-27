<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<template>
  <div class="space-y-2">
    <div
      v-if="!disabled || $slots.actions || $slots['leading-actions']"
      class="flex flex-wrap gap-2"
    >
      <slot name="leading-actions" />
      <UButton
        v-if="!disabled"
        type="button"
        color="neutral"
        variant="outline"
        icon="i-lucide-plus"
        @click="addRow"
      >
        {{ t('zoneRecords.add') }}
      </UButton>
      <UButton
        v-if="!disabled"
        type="button"
        color="neutral"
        variant="outline"
        icon="i-lucide-plus"
        @click="addComment"
      >
        {{ t('zoneRecords.addComment') }}
      </UButton>
      <UButton
        v-if="!disabled"
        type="button"
        color="neutral"
        variant="outline"
        icon="i-lucide-folder-plus"
        @click="addDomain"
      >
        {{ t('zoneRecords.addDomain') }}
      </UButton>
      <slot name="actions" />
    </div>
    <UContextMenu :items="contextItems" :disabled="disabled">
      <div
        ref="tableWrap"
        class="zone-records-table w-full rounded-md ring ring-default overflow-auto max-h-[calc(100dvh-16rem)]"
        :data-changed-count="changedKeys.size"
        @contextmenu.capture="captureMenuRow"
      >
        <UTable
          sticky="header"
          :data="records"
          :columns="columns"
          :get-row-id="getRowId"
          :ui="tableUi"
          :meta="tableMeta"
          :empty="t('zoneRecords.empty')"
          :watch-options="{ deep: false }"
        >
          <template #drag-cell="{ row }">
            <span
              v-if="isDraftRow(row.index)"
              class="inline-flex items-center justify-center size-8 text-muted"
              :title="t('zoneRecords.add')"
              :aria-label="t('zoneRecords.add')"
            >
              <UIcon name="i-lucide-plus" class="size-3.5" />
            </span>
            <span
              v-else-if="isDomainRecord(row.original)"
              class="inline-flex items-center justify-center size-8 text-muted"
              :title="t('zoneRecords.domain')"
              :aria-label="t('zoneRecords.domain')"
            >
              <UIcon name="i-lucide-folder" class="size-3.5" />
            </span>
            <span
              v-else
              class="inline-flex items-center justify-center size-8 text-muted cursor-grab active:cursor-grabbing select-none touch-none"
              :title="t('zoneRecords.drag')"
              :aria-label="t('zoneRecords.drag')"
              :class="disabled && 'pointer-events-none'"
              @pointerdown="onPointerDown(row.index, $event)"
            >
              <UIcon name="i-lucide-grip-vertical" class="size-3.5 pointer-events-none" />
            </span>
          </template>
          <template v-for="col in resizeHeaderCols" :key="col.key" #[`${col.key}-header`]>
            <div class="zone-col-head">
              <span class="truncate">{{ col.label }}</span>
              <button
                type="button"
                class="zone-col-resizer"
                tabindex="-1"
                :aria-label="t('zoneRecords.resizeColumn')"
                :title="t('zoneRecords.resizeColumn')"
                @pointerdown="startResize(col.key, $event)"
              />
            </div>
          </template>
          <template #name-cell="{ row }">
            <div
              v-if="isDomainRecord(row.original)"
              data-record-col="name"
              class="w-full flex items-center min-w-0"
              @keydown="onCellKeydown($event, row, 'name')"
            >
              <span
                class="font-mono ps-2 pe-2 shrink-0 select-none font-semibold text-highlighted"
                aria-hidden="true"
              >
                $DOMAIN
              </span>
              <UTooltip v-bind="cellTooltipProps(row.original.name, row.original, 'name')">
                <div
                  class="w-full min-w-0"
                  @pointerenter="onFieldEnter($event, row.original, 'name', row.original.name)"
                  @pointerleave="onFieldLeave(row.original, 'name')"
                >
                  <UInput
                    v-model="row.original.name"
                    class="w-full font-mono"
                    variant="none"
                    color="neutral"
                    size="xs"
                    :ui="cellFieldUi"
                    :placeholder="t('zoneRecords.domainPlaceholder')"
                    autocomplete="off"
                    :disabled="disabled"
                    @update:model-value="syncRowChanged(row.original)"
                  />
                </div>
              </UTooltip>
            </div>
            <div
              v-else-if="isCommentRecord(row.original)"
              data-record-col="value"
              class="w-full flex items-center min-w-0"
              @keydown="onCellKeydown($event, row, 'value')"
            >
              <span
                class="text-muted font-mono ps-2 shrink-0 select-none"
                aria-hidden="true"
                :title="t('zoneRecords.comment')"
              >
                ;
              </span>
              <UTooltip v-bind="cellTooltipProps(row.original.value, row.original, 'value')">
                <div
                  class="w-full min-w-0"
                  @pointerenter="onFieldEnter($event, row.original, 'value', row.original.value)"
                  @pointerleave="onFieldLeave(row.original, 'value')"
                >
                  <UInput
                    v-model="row.original.value"
                    class="w-full font-mono"
                    variant="none"
                    color="neutral"
                    size="xs"
                    :ui="cellFieldUi"
                    :aria-label="t('zoneRecords.comment')"
                    :title="tooltipText(row.original.value) ? undefined : t('zoneRecords.comment')"
                    autocomplete="off"
                    :disabled="disabled"
                    @update:model-value="syncRowChanged(row.original)"
                  />
                </div>
              </UTooltip>
            </div>
            <div v-else data-record-col="name" class="w-full" @keydown="onNameKeydown($event, row)">
              <UTooltip v-bind="cellTooltipProps(row.original.name, row.original, 'name')">
                <div
                  class="w-full min-w-0"
                  @pointerenter="onFieldEnter($event, row.original, 'name', row.original.name)"
                  @pointerleave="onFieldLeave(row.original, 'name')"
                >
                  <UInput
                    v-model="row.original.name"
                    class="w-full font-mono"
                    variant="none"
                    color="neutral"
                    size="xs"
                    :ui="cellFieldUi"
                    placeholder="@"
                    autocomplete="off"
                    :disabled="disabled"
                    @update:model-value="syncRowChanged(row.original)"
                  />
                </div>
              </UTooltip>
            </div>
          </template>
          <template #ttl-cell="{ row }">
            <div data-record-col="ttl" class="w-full" @keydown="onCellKeydown($event, row, 'ttl')">
              <UInput
                :model-value="row.original.ttl ?? ''"
                type="number"
                min="1"
                class="w-full"
                variant="none"
                color="neutral"
                size="xs"
                :ui="cellFieldUi"
                autocomplete="off"
                :disabled="disabled"
                @update:model-value="
                  (v) => {
                    row.original.ttl = v === '' || v == null ? null : Number(v)
                    syncRowChanged(row.original)
                  }
                "
              />
            </div>
          </template>
          <template #type-cell="{ row }">
            <div class="w-full" @keydown="onTypeKeydown($event, row)">
              <USelect
                :model-value="row.original.type"
                :items="typeItems"
                class="w-full"
                variant="none"
                color="neutral"
                size="xs"
                :ui="cellSelectUi"
                :aria-label="t('zoneRecords.type')"
                :disabled="disabled || isSpanningRecord(row.original)"
                @update:model-value="(v) => setRowType(row, v)"
              />
            </div>
          </template>
          <template #value-cell="{ row }">
            <UTooltip v-bind="cellTooltipProps(row.original.value, row.original, 'value')">
              <div
                data-record-col="value"
                class="zone-rdata-fields w-full min-w-0"
                @keydown="onCellKeydown($event, row, 'value')"
                @pointerenter="onFieldEnter($event, row.original, 'value', row.original.value)"
                @pointerleave="onFieldLeave(row.original, 'value')"
              >
                <div
                  v-for="(field, i) in valueFieldSpecs(row.original.type)"
                  :key="`${row.original.type}-${i}`"
                  :class="field.wrapClass"
                >
                  <UInput
                    :model-value="rdataField(row.original, i)"
                    :type="field.inputType"
                    class="w-full font-mono"
                    variant="none"
                    color="neutral"
                    size="xs"
                    :ui="field.inputType === 'number' ? cellNumUi : cellFieldUi"
                    :placeholder="field.placeholder"
                    :aria-label="field.aria"
                    autocomplete="off"
                    :disabled="disabled"
                    v-bind="numberAttrs(field)"
                    @update:model-value="(v) => setRdataField(row.original, i, v)"
                  />
                </div>
              </div>
            </UTooltip>
          </template>
          <template #mac-cell="{ row }">
            <div
              data-record-col="mac"
              class="w-full flex items-center min-w-0"
              @keydown="onCellKeydown($event, row, 'mac')"
            >
              <UTooltip v-bind="cellTooltipProps(row.original.mac, row.original, 'mac')">
                <div
                  class="w-full min-w-0"
                  @pointerenter="onFieldEnter($event, row.original, 'mac', row.original.mac)"
                  @pointerleave="onFieldLeave(row.original, 'mac')"
                >
                  <UInput
                    v-model="row.original.mac"
                    class="w-full font-mono"
                    variant="none"
                    color="neutral"
                    size="xs"
                    :ui="cellFieldUi"
                    placeholder="aa:bb:cc:dd:ee:ff"
                    autocomplete="off"
                    :disabled="disabled || !isAddressRecord(row.original)"
                    @update:model-value="syncRowChanged(row.original)"
                  />
                </div>
              </UTooltip>
              <UButton
                v-if="!disabled && isAddressRecord(row.original)"
                type="button"
                size="xs"
                color="neutral"
                variant="ghost"
                icon="i-lucide-list"
                class="shrink-0"
                :aria-label="t('zoneRecords.pickMac')"
                :title="t('zoneRecords.pickMac')"
                @click.stop="openLeasePicker(row.original)"
              />
            </div>
          </template>
          <template #description-cell="{ row }">
            <div
              data-record-col="description"
              class="w-full"
              @keydown="onCellKeydown($event, row, 'description')"
            >
              <UTooltip
                v-bind="cellTooltipProps(row.original.description, row.original, 'description')"
              >
                <div
                  class="w-full min-w-0"
                  @pointerenter="
                    onFieldEnter($event, row.original, 'description', row.original.description)
                  "
                  @pointerleave="onFieldLeave(row.original, 'description')"
                >
                  <UInput
                    v-model="row.original.description"
                    class="w-full"
                    variant="none"
                    color="neutral"
                    size="xs"
                    :ui="cellFieldUi"
                    autocomplete="off"
                    :disabled="disabled"
                    @update:model-value="syncRowChanged(row.original)"
                  />
                </div>
              </UTooltip>
            </div>
          </template>
          <template #actions-header>
            <div v-if="!disabled" class="flex items-center justify-center">
              <UButton
                type="button"
                size="xs"
                color="neutral"
                variant="ghost"
                icon="i-lucide-plus"
                :aria-label="t('zoneRecords.add')"
                :title="t('zoneRecords.add')"
                @click="addRow"
              />
            </div>
          </template>
          <template #actions-cell="{ row }">
            <div class="flex items-center justify-center h-8">
              <UButton
                v-if="!disabled && !isDraftRow(row.index)"
                type="button"
                size="xs"
                color="error"
                variant="ghost"
                icon="i-lucide-trash"
                :aria-label="t('zoneRecords.remove')"
                @click="removeAt(row.index)"
              />
            </div>
          </template>
        </UTable>
      </div>
    </UContextMenu>
    <DhcpLeasePicker
      v-model:open="leasePickerOpen"
      :instance="instance"
      :ip="leasePickerRow?.value"
      @select="applyLeaseMac"
    />
  </div>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, reactive, ref, shallowRef, watch } from 'vue'
import DhcpLeasePicker from '@/components/DhcpLeasePicker.vue'
import {
  COMMENT_TYPE,
  emptyCommentRecord,
  emptyDomainRecord,
  emptyZoneRecord,
  isCommentRecord,
  isDomainRecord,
  isRecordChanged,
  isSpanningRecord,
  joinRdataFields,
  splitRdataFields,
  subzoneRecordRange,
  ZONE_RECORD_TYPES,
} from '@/utils/zoneRecords'

const STRINGS = {
  'common.name': 'Name',
  'zones.ttl': 'TTL',
  'zoneRecords.empty': 'No records. Add a record.',
  'zoneRecords.drag': 'Drag to reorder',
  'zoneRecords.type': 'Type',
  'zoneRecords.value': 'Value',
  'zoneRecords.description': 'Description',
  'zoneRecords.mac': 'MAC',
  'zoneRecords.pickMac': 'Pick MAC from DHCP leases',
  'zoneRecords.remove': 'Remove record',
  'zoneRecords.add': 'Add record',
  'zoneRecords.addComment': 'Add comment',
  'zoneRecords.addDomain': 'Add $DOMAIN',
  'zoneRecords.insertAbove': 'Insert row above',
  'zoneRecords.insertBelow': 'Insert row below',
  'zoneRecords.insertCommentAbove': 'Insert comment above',
  'zoneRecords.insertCommentBelow': 'Insert comment below',
  'zoneRecords.insertDomainAbove': 'Insert $DOMAIN above',
  'zoneRecords.insertDomainBelow': 'Insert $DOMAIN below',
  'zoneRecords.resizeColumn': 'Drag to resize column',
  'zoneRecords.comment': 'Comment',
  'zoneRecords.domain': '$DOMAIN',
  'zoneRecords.domainPlaceholder': 'subdomain',
  'zoneRecords.mxPriority': 'Priority',
  'zoneRecords.mxHost': 'Mail server',
  'zoneRecords.srvPriority': 'Priority',
  'zoneRecords.srvWeight': 'Weight',
  'zoneRecords.srvPort': 'Port',
  'zoneRecords.srvTarget': 'Target',
  'zoneRecords.tlsaUsage': 'Usage',
  'zoneRecords.tlsaSelector': 'Selector',
  'zoneRecords.tlsaMatching': 'Matching type',
  'zoneRecords.tlsaData': 'Certificate data',
}

function t(key, params = {}) {
  let s = STRINGS[key] ?? key
  for (const [k, v] of Object.entries(params)) {
    s = s.replaceAll(`{${k}}`, String(v))
  }
  return s
}

const records = defineModel({ type: Array, default: () => [] })
const props = defineProps({
  disabled: { type: Boolean, default: false },
  // The MAC column (DHCP reservations) is shown when the instance runs DHCP.
  showMac: { type: Boolean, default: false },
  // Instance whose Kea leases the MAC picker lists.
  instance: { type: String, default: '' },
})
const dhcpEnabled = computed(() => props.showMac)

const tableWrap = ref(null)

const DRAG_CLASS = 'zone-record-dragging'
const DRAG_THRESHOLD_PX = 4
const AUTO_SCROLL_EDGE_PX = 96
const AUTO_SCROLL_MAX_PX = 32
const GHOST_CLASS =
  'zone-record-ghost fixed z-50 pointer-events-none flex items-center gap-2 rounded-md border border-primary/50 bg-elevated px-3 py-1.5 text-sm shadow-lg max-w-lg'

let dragFrom = null
let dragMoved = false
let dragStartY = 0
let dragClientX = 0
let dragClientY = 0
let autoScrollRaf = 0
let lastRowRevealAt = 0
let ghostEl = null
let lineEl = null

const COMMENT_COLSPAN = computed(() => (dhcpEnabled.value ? 6 : 5))
const COL_MIN = { name: 72, ttl: 48, type: 72, value: 96, mac: 96, description: 96 }
const colWidths = reactive({
  name: 144,
  ttl: 64,
  type: 96,
  value: 200,
  mac: 196,
  description: 200,
})

const typeItems = ZONE_RECORD_TYPES.map((type) => ({
  label: type,
  value: type,
}))

const resizeHeaderCols = computed(() => {
  const cols = [
    { key: 'name', label: t('common.name') },
    { key: 'ttl', label: t('zones.ttl') },
    { key: 'type', label: t('zoneRecords.type') },
    { key: 'value', label: t('zoneRecords.value') },
  ]
  if (dhcpEnabled.value) cols.push({ key: 'mac', label: t('zoneRecords.mac') })
  cols.push({ key: 'description', label: t('zoneRecords.description') })
  return cols
})

let menuRowIndex = -1

const contextItems = computed(() => [
  [
    {
      label: t('zoneRecords.insertAbove'),
      icon: 'i-lucide-arrow-up-to-line',
      onSelect: () => insertRowAt(menuRowIndex),
    },
    {
      label: t('zoneRecords.insertBelow'),
      icon: 'i-lucide-arrow-down-to-line',
      onSelect: () => insertRowAt(menuRowIndex + 1),
    },
  ],
  [
    {
      label: t('zoneRecords.insertCommentAbove'),
      icon: 'i-lucide-message-square',
      onSelect: () => insertCommentAt(menuRowIndex),
    },
    {
      label: t('zoneRecords.insertCommentBelow'),
      icon: 'i-lucide-message-square',
      onSelect: () => insertCommentAt(menuRowIndex + 1),
    },
  ],
  [
    {
      label: t('zoneRecords.insertDomainAbove'),
      icon: 'i-lucide-folder-plus',
      onSelect: () => insertDomainAt(menuRowIndex),
    },
    {
      label: t('zoneRecords.insertDomainBelow'),
      icon: 'i-lucide-folder-plus',
      onSelect: () => insertDomainAt(menuRowIndex + 1),
    },
  ],
])

const cellFieldUi = {
  root: 'w-full',
  base: 'rounded-none h-8 px-2',
}
const cellNumUi = {
  root: 'w-full',
  base: 'rounded-none h-8 px-1.5 text-center tabular-nums',
}
const cellSelectUi = {
  base: 'rounded-none h-8 w-full px-2',
  trailing: 'pe-1',
  trailingIcon: 'size-3.5 text-dimmed',
}
const tableUi = {
  root: 'w-full overflow-visible',
  base: 'table-fixed w-full min-w-full',
  thead: 'sticky top-0 z-10 bg-elevated',
  tbody: 'divide-y-0',
  separator: 'hidden',
  th: 'px-2 py-1.5 text-xs font-medium bg-elevated',
  td: 'p-0 min-w-0',
}
const changedKeys = shallowRef(new Set())

const tableMeta = {
  class: {
    tr: (row) => {
      const classes = []
      if (isCommentRecord(row.original)) classes.push('zone-record-comment')
      if (isDomainRecord(row.original)) classes.push('zone-record-domain')
      if (changedKeys.value.has(row.original._key)) {
        classes.push('zone-record-changed')
      }
      return classes.join(' ')
    },
  },
}

const cellTooltipContent = {
  side: 'top',
  align: 'start',
  collisionPadding: 12,
}
const cellTooltipUi = {
  content:
    'h-auto w-max max-w-[90vw] items-start px-3 py-2 rounded-md ring-2 ring-accented shadow-lg bg-default',
  text: 'font-mono text-xs break-all whitespace-pre-wrap overflow-visible',
}
const overflowTip = ref('')
const OVERFLOW_TIP_DELAY_MS = 300
let overflowTipTimer

const measureCanvas = typeof document !== 'undefined' ? document.createElement('canvas') : null

function tooltipText(value) {
  const s = value == null ? '' : String(value)
  return s.trim() ? s : ''
}

function tipId(row, col) {
  return `${row._key}:${col}`
}

function measureTextWidth(text, style) {
  const ctx = measureCanvas?.getContext('2d')
  if (!ctx) return 0
  ctx.font = style.font
  return ctx.measureText(text).width
}

function isInputOverflowing(el) {
  if (!el) return false
  if (el.scrollWidth > el.clientWidth + 1) return true
  if (!(el instanceof HTMLInputElement) && el.tagName !== 'TEXTAREA') {
    return false
  }
  const value = el.value ?? ''
  if (!value) return false
  const style = getComputedStyle(el)
  const available =
    el.clientWidth -
    parseFloat(style.paddingLeft) -
    parseFloat(style.paddingRight) -
    parseFloat(style.borderLeftWidth) -
    parseFloat(style.borderRightWidth)
  if (available <= 0) return false
  return measureTextWidth(value, style) > available + 1
}

function fieldOverflows(root) {
  if (!root) return false
  const fields = root.querySelectorAll('input, textarea')
  if (!fields.length) return isInputOverflowing(root)
  return [...fields].some(isInputOverflowing)
}

function onFieldEnter(event, row, col, value) {
  clearTimeout(overflowTipTimer)
  const id = tipId(row, col)
  const root = event.currentTarget
  overflowTipTimer = setTimeout(() => {
    const text = tooltipText(value)
    overflowTip.value = text && fieldOverflows(root) ? id : ''
  }, OVERFLOW_TIP_DELAY_MS)
}

function onFieldLeave(row, col) {
  clearTimeout(overflowTipTimer)
  if (overflowTip.value === tipId(row, col)) overflowTip.value = ''
}

function cellTooltipProps(value, row, col) {
  const id = tipId(row, col)
  const text = tooltipText(value)
  const active = Boolean(text) && overflowTip.value === id
  return {
    text,
    delayDuration: 0,
    disableClosingTrigger: true,
    disableHoverableContent: true,
    arrow: true,
    content: cellTooltipContent,
    ui: cellTooltipUi,
    class: 'w-full min-w-0',
    disabled: !active,
    open: active,
    'onUpdate:open': (next) => {
      if (!next && overflowTip.value === id) overflowTip.value = ''
    },
  }
}

function rebuildChangedKeys() {
  const next = new Set()
  const list = records.value
  for (let i = 0; i < list.length; i++) {
    if (isDraftRow(i)) continue
    if (isRecordChanged(list[i])) next.add(list[i]._key)
  }
  changedKeys.value = next
}

function syncRowChanged(row) {
  if (!row?._key) return
  const index = records.value.findIndex((r) => r._key === row._key)
  const dirty = index >= 0 && !isDraftRow(index) && isRecordChanged(row)
  if (changedKeys.value.has(row._key) === dirty) return
  const next = new Set(changedKeys.value)
  if (dirty) next.add(row._key)
  else next.delete(row._key)
  changedKeys.value = next
}

let typeQuery = ''
let typeQueryTimer

function matchRecordType(query, current) {
  const q = query.toUpperCase()
  const isRepeated = q.length > 1 && [...q].every((c) => c === q[0])
  const needle = isRepeated ? q[0] : q
  if (needle.length === 1) {
    const start = ZONE_RECORD_TYPES.indexOf(current)
    const ordered =
      start < 0
        ? ZONE_RECORD_TYPES
        : [...ZONE_RECORD_TYPES.slice(start + 1), ...ZONE_RECORD_TYPES.slice(0, start + 1)]
    return ordered.find((t) => t.startsWith(needle)) || null
  }
  return ZONE_RECORD_TYPES.find((t) => t.startsWith(needle)) || null
}

function spanningSkipClass(cell) {
  return isSpanningRecord(cell.row.original) ? 'hidden' : undefined
}

function colWidthStyle(key) {
  return { width: `${colWidths[key]}px`, minWidth: `${colWidths[key]}px` }
}

function colFlexStyle(key) {
  return { minWidth: `${colWidths[key]}px` }
}

function isAddressRecord(row) {
  const type = (row?.type || '').toUpperCase()
  return type === 'A' || type === 'AAAA'
}

const leasePickerOpen = ref(false)
const leasePickerRow = ref(null)

function openLeasePicker(row) {
  if (props.disabled || !isAddressRecord(row)) return
  leasePickerRow.value = row
  leasePickerOpen.value = true
}

function applyLeaseMac(lease) {
  const row = leasePickerRow.value
  leasePickerRow.value = null
  if (!row || !lease?.mac) return
  row.mac = lease.mac
  syncRowChanged(row)
}

function setRowType(row, type) {
  const prev = row.original.type
  row.original.type = type
  if (type === COMMENT_TYPE && prev !== COMMENT_TYPE) {
    row.original.name = ';'
    row.original.ttl = null
    row.original.description = ''
    row.original.mac = ''
    focusCell(row.index, 'value')
  } else if (type !== COMMENT_TYPE && prev === COMMENT_TYPE) {
    if (row.original.name === ';') row.original.name = ''
  }
  if (!isAddressRecord(row.original)) {
    row.original.mac = ''
  }
  syncRowChanged(row.original)
}

function onTypeKeydown(event, row) {
  if (event.ctrlKey || event.altKey || event.metaKey) return
  if (event.key === ';') {
    typeQuery = ''
    setRowType(row, COMMENT_TYPE)
    event.preventDefault()
    return
  }
  if (
    event.key === 'Tab' ||
    event.key === 'Escape' ||
    event.key === 'Enter' ||
    event.key === ' ' ||
    event.key === 'ArrowDown' ||
    event.key === 'ArrowUp'
  ) {
    typeQuery = ''
    return
  }
  if (event.key.length !== 1 || !/^[a-z]$/i.test(event.key)) return

  typeQuery += event.key
  clearTimeout(typeQueryTimer)
  typeQueryTimer = setTimeout(() => {
    typeQuery = ''
  }, 1000)

  const match = matchRecordType(typeQuery, row.original.type)
  if (match) {
    setRowType(row, match)
    event.preventDefault()
  }
}

const columns = computed(() => [
  {
    id: 'drag',
    header: '',
    enableSorting: false,
    meta: { class: { th: 'w-7', td: 'w-7 text-center' } },
  },
  {
    accessorKey: 'name',
    header: t('common.name'),
    enableSorting: false,
    meta: {
      class: {
        td: (cell) =>
          isSpanningRecord(cell.row.original) ? 'zone-record-comment-cell' : undefined,
      },
      style: {
        th: () => colWidthStyle('name'),
        td: (cell) => (isSpanningRecord(cell.row.original) ? undefined : colWidthStyle('name')),
      },
      colspan: {
        td: (cell) => (isSpanningRecord(cell.row.original) ? COMMENT_COLSPAN.value : undefined),
      },
    },
  },
  {
    accessorKey: 'ttl',
    header: t('zones.ttl'),
    enableSorting: false,
    meta: {
      class: { td: spanningSkipClass },
      style: { th: () => colWidthStyle('ttl'), td: () => colWidthStyle('ttl') },
    },
  },
  {
    accessorKey: 'type',
    header: t('zoneRecords.type'),
    enableSorting: false,
    meta: {
      class: { td: spanningSkipClass },
      style: {
        th: () => colWidthStyle('type'),
        td: () => colWidthStyle('type'),
      },
    },
  },
  {
    accessorKey: 'value',
    header: t('zoneRecords.value'),
    enableSorting: false,
    meta: {
      class: { td: spanningSkipClass },
      style: { th: () => colFlexStyle('value'), td: () => colFlexStyle('value') },
    },
  },
  ...(dhcpEnabled.value
    ? [
        {
          accessorKey: 'mac',
          header: t('zoneRecords.mac'),
          enableSorting: false,
          meta: {
            class: { td: spanningSkipClass },
            style: {
              th: () => colWidthStyle('mac'),
              td: () => colWidthStyle('mac'),
            },
          },
        },
      ]
    : []),
  {
    accessorKey: 'description',
    header: t('zoneRecords.description'),
    enableSorting: false,
    meta: {
      class: { td: spanningSkipClass },
      style: {
        th: () => colWidthStyle('description'),
        td: () => colWidthStyle('description'),
      },
    },
  },
  {
    id: 'actions',
    header: '',
    enableSorting: false,
    meta: { class: { th: 'w-8', td: 'w-8' } },
  },
])

function getRowId(row) {
  return row._key
}

function valuePlaceholder(type) {
  switch (type) {
    case 'A':
      return '192.0.2.1'
    case 'AAAA':
      return '2001:db8::1'
    case 'CNAME':
      return 'target.example.com.'
    case 'MX':
      return '10 mail.example.com.'
    case 'NS':
      return 'ns1.example.com.'
    case 'PTR':
      return 'host.example.com.'
    case 'SRV':
      return '0 5 5060 sip.example.com.'
    case 'TLSA':
      return '3 1 1 abcdef…'
    case 'TXT':
      return 'v=spf1 -all'
    default:
      return ''
  }
}

const valueFieldSpecsByType = computed(() => {
  const text = (placeholder, aria, wrapClass = 'min-w-0 flex-1') => ({
    inputType: 'text',
    placeholder,
    aria,
    wrapClass,
  })
  const int = (placeholder, aria, wrapClass, max = 65535) => ({
    inputType: 'number',
    min: 0,
    max,
    placeholder,
    aria,
    wrapClass,
  })
  return {
    MX: [
      int('10', t('zoneRecords.mxPriority'), 'w-14 shrink-0'),
      text('mail.example.com.', t('zoneRecords.mxHost')),
    ],
    SRV: [
      int('0', t('zoneRecords.srvPriority'), 'w-12 shrink-0'),
      int('5', t('zoneRecords.srvWeight'), 'w-12 shrink-0'),
      int('5060', t('zoneRecords.srvPort'), 'w-14 shrink-0'),
      text('sip.example.com.', t('zoneRecords.srvTarget')),
    ],
    TLSA: [
      int('3', t('zoneRecords.tlsaUsage'), 'w-12 shrink-0', 3),
      int('1', t('zoneRecords.tlsaSelector'), 'w-12 shrink-0', 1),
      int('1', t('zoneRecords.tlsaMatching'), 'w-12 shrink-0', 2),
      text('abcdef…', t('zoneRecords.tlsaData')),
    ],
  }
})

function valueFieldSpecs(type) {
  return (
    valueFieldSpecsByType.value[type] || [
      {
        inputType: 'text',
        placeholder: valuePlaceholder(type),
        aria: t('zoneRecords.value'),
        wrapClass: 'min-w-0 flex-1',
      },
    ]
  )
}

function numberAttrs(field) {
  if (field.inputType !== 'number') return {}
  return { min: field.min, max: field.max, step: 1 }
}

function rdataField(row, index) {
  return splitRdataFields(row.type, row.value)[index] ?? ''
}

function setRdataField(row, index, raw) {
  const fields = splitRdataFields(row.type, row.value)
  fields[index] = raw === '' || raw == null ? '' : String(raw)
  row.value = joinRdataFields(fields)
  syncRowChanged(row)
}

function isBlankRecord(row) {
  if (isSpanningRecord(row)) return false
  return (
    !(row?.name || '').trim() && !(row?.value || '').trim() && (row?.ttl == null || row?.ttl === '')
  )
}

function isDraftRow(index) {
  const list = records.value
  if (index < 0 || index !== list.length - 1) return false
  const row = list[index]
  return Boolean(row) && !isSpanningRecord(row) && isBlankRecord(row)
}

function appendDraftRow() {
  if (props.disabled) return
  records.value = [...records.value, emptyZoneRecord()]
}

function focusCell(rowIndex, col) {
  nextTick(() => {
    const tr = tableRows()[rowIndex]
    if (!tr) return
    const root = tr.querySelector(`[data-record-col="${col}"]`)
    const el = root?.querySelector('input, textarea') || root?.querySelector('button')
    el?.focus()
    tr.scrollIntoView({ block: 'nearest' })
  })
}

function addRow() {
  if (props.disabled) return
  const list = records.value
  const lastIndex = list.length - 1
  if (lastIndex >= 0 && isDraftRow(lastIndex)) {
    focusCell(lastIndex, 'name')
    return
  }
  appendDraftRow()
  focusCell(records.value.length - 1, 'name')
}

function insertRowAt(index) {
  if (props.disabled || index == null || index < 0) return
  const list = [...records.value]
  const last = list.length - 1
  if (last >= 0 && isDraftRow(last) && index > last) {
    focusCell(last, 'name')
    return
  }
  const i = Math.min(index, list.length)
  list.splice(i, 0, emptyZoneRecord())
  records.value = list
  focusCell(i, 'name')
}

function insertCommentAt(index) {
  if (props.disabled || index == null || index < 0) return
  const list = [...records.value]
  const last = list.length - 1
  let i = Math.min(index, list.length)
  if (last >= 0 && isDraftRow(last) && i > last) i = last
  list.splice(i, 0, emptyCommentRecord())
  records.value = list
  focusCell(i, 'value')
}

function addComment() {
  if (props.disabled) return
  const list = records.value
  const lastIndex = list.length - 1
  insertCommentAt(lastIndex >= 0 && isDraftRow(lastIndex) ? lastIndex : list.length)
}

function insertDomainAt(index) {
  if (props.disabled || index == null || index < 0) return
  const list = [...records.value]
  const last = list.length - 1
  let i = Math.min(index, list.length)
  if (last >= 0 && isDraftRow(last) && i > last) i = last
  list.splice(i, 0, emptyDomainRecord())
  records.value = list
  focusCell(i, 'name')
}

function addDomain() {
  if (props.disabled) return
  const list = records.value
  const lastIndex = list.length - 1
  insertDomainAt(lastIndex >= 0 && isDraftRow(lastIndex) ? lastIndex : list.length)
}

function onNameKeydown(event, row) {
  if (
    event.key === ';' &&
    !event.ctrlKey &&
    !event.altKey &&
    !event.metaKey &&
    !(row.original.name || '').trim()
  ) {
    event.preventDefault()
    setRowType(row, COMMENT_TYPE)
    return
  }
  onCellKeydown(event, row, 'name')
}

function captureMenuRow(event) {
  const tbody = event.target.closest("[data-slot='tbody']") || event.target.closest('tbody')
  const tr = event.target.closest("[data-slot='tr']") || event.target.closest('tr')
  if (!tbody || !tr) {
    menuRowIndex = -1
    return
  }
  menuRowIndex = tableRows().indexOf(tr)
}

function onCellKeydown(event, row, col) {
  if (event.key !== 'Enter' || event.isComposing) return
  event.preventDefault()
  const next = row.index + 1
  if (next >= records.value.length) {
    if (isBlankRecord(row.original)) return
    appendDraftRow()
  }
  focusCell(next, col === 'description' ? 'name' : col)
}

function removeAt(index) {
  records.value = records.value.filter((_, i) => i !== index)
}

watch(
  () => {
    const list = records.value
    if (!list.length) return 'missing'
    const last = list[list.length - 1]
    if (isSpanningRecord(last)) return 'comment-tail'
    return isBlankRecord(last) ? 'blank' : 'filled'
  },
  (state) => {
    if (state !== 'blank') appendDraftRow()
  },
  { immediate: true },
)

watch(records, rebuildChangedKeys, { immediate: true })

function tableRows() {
  const wrap = wrapEl()
  if (!wrap) return []
  const tbody = wrap.querySelector("[data-slot='tbody']") || wrap.querySelector('tbody')
  if (!tbody) return []
  return [...tbody.querySelectorAll("[data-slot='tr']")]
}

function gapFromY(clientY) {
  const rows = tableRows()
  if (!rows.length) return -1
  for (let i = 0; i < rows.length; i++) {
    const { top, bottom } = rows[i].getBoundingClientRect()
    if (clientY < (top + bottom) / 2) return i
  }
  return rows.length
}

function insertIndex(from, gap) {
  if (from == null || gap < 0) return from
  return gap > from ? gap - 1 : gap
}

function clampGapToSubzone(from, gap) {
  if (from == null || gap < 0) return gap
  const { lo, hi } = subzoneRecordRange(records.value, from)
  let maxGap = hi
  const last = records.value.length - 1
  if (last >= lo && last < hi && isDraftRow(last)) maxGap = last
  if (gap < lo) return lo
  if (gap > maxGap) return maxGap
  return gap
}

function tableBox() {
  const wrap = tableWrap.value
  const table = wrap?.querySelector("[data-slot='base']") || wrap?.querySelector('table') || wrap
  return table?.getBoundingClientRect() ?? null
}

function ensureDragUi() {
  if (!ghostEl) {
    ghostEl = document.createElement('div')
    ghostEl.className = GHOST_CLASS
    ghostEl.setAttribute('aria-hidden', 'true')
    document.body.appendChild(ghostEl)
  }
  if (!lineEl) {
    lineEl = document.createElement('div')
    lineEl.className = 'zone-record-drop-line'
    lineEl.setAttribute('aria-hidden', 'true')
    document.body.appendChild(lineEl)
  }
}

function fillGhost(record) {
  if (!ghostEl) return
  ghostEl.replaceChildren()
  if (isCommentRecord(record)) {
    const comment = document.createElement('span')
    comment.className = 'font-mono text-muted truncate'
    comment.textContent = `; ${record?.value || ''}`
    ghostEl.append(comment)
    return
  }
  const name = document.createElement('span')
  name.className = 'font-mono font-medium shrink-0'
  name.textContent = record?.name || '@'
  const type = document.createElement('span')
  type.className = 'rounded px-1.5 py-0.5 text-xs font-semibold bg-primary/15 text-primary shrink-0'
  type.textContent = record?.type || ''
  const value = document.createElement('span')
  value.className = 'font-mono text-muted truncate'
  value.textContent = record?.value || ''
  ghostEl.append(name, type, value)
}

function placeGhost(clientX, clientY) {
  if (!ghostEl) return
  const pad = 8
  const offset = 16
  const w = ghostEl.offsetWidth
  const h = ghostEl.offsetHeight
  const x = Math.min(Math.max(pad, clientX + offset), window.innerWidth - w - pad)
  const y = Math.min(Math.max(pad, clientY + offset), window.innerHeight - h - pad)
  ghostEl.style.transform = `translate(${x}px, ${y}px)`
  ghostEl.style.opacity = '1'
}

function placeLine(gap) {
  if (!lineEl) return
  const rows = tableRows()
  const box = tableBox()
  if (!rows.length || !box || gap < 0) {
    lineEl.style.opacity = '0'
    return
  }
  const y =
    gap >= rows.length
      ? rows[rows.length - 1].getBoundingClientRect().bottom
      : rows[gap].getBoundingClientRect().top
  lineEl.style.opacity = '1'
  lineEl.style.width = `${box.width}px`
  lineEl.style.transform = `translate(${box.left}px, ${y - 1.5}px)`
}

function paintSource(from) {
  tableRows().forEach((tr, i) => {
    tr.classList.toggle(DRAG_CLASS, from != null && i === from)
  })
}

function paintDragAt(clientX, clientY) {
  placeGhost(clientX, clientY)
  placeLine(clampGapToSubzone(dragFrom, gapFromY(clientY)))
}

function wrapEl() {
  const el = tableWrap.value
  if (!el) return null
  if (el instanceof HTMLElement) return el
  return el.$el instanceof HTMLElement ? el.$el : null
}

function autoScrollDelta(clientY, top, bottom) {
  const edge = AUTO_SCROLL_EDGE_PX
  const max = AUTO_SCROLL_MAX_PX
  if (bottom - top < 8) return 0
  if (clientY < top + edge) {
    const t = Math.min(1, (top + edge - clientY) / edge)
    return -Math.max(1, Math.round(t * max))
  }
  if (clientY > bottom - edge) {
    const t = Math.min(1, (clientY - (bottom - edge)) / edge)
    return Math.max(1, Math.round(t * max))
  }
  return 0
}

function tryScrollEl(el, dy) {
  if (!el || !dy) return false
  const max = el.scrollHeight - el.clientHeight
  if (!(max > 0)) return false
  const prev = el.scrollTop
  const next = Math.max(0, Math.min(max, prev + dy))
  if (next === prev) return false
  el.scrollTop = next
  return el.scrollTop !== prev
}

function scrollByDy(start, dy) {
  for (let el = start; el; el = el.parentElement) {
    if (tryScrollEl(el, dy)) return true
  }
  if (tryScrollEl(document.scrollingElement, dy)) return true
  if (tryScrollEl(document.documentElement, dy)) return true
  if (tryScrollEl(document.body, dy)) return true
  const y0 = window.scrollY
  window.scrollBy(0, dy)
  return window.scrollY !== y0
}

function edgeDelta(wrap, clientY) {
  const r = wrap.getBoundingClientRect()
  const fromWrap = autoScrollDelta(
    clientY,
    Math.max(0, r.top),
    Math.min(window.innerHeight, r.bottom),
  )
  if (fromWrap) return fromWrap
  return autoScrollDelta(clientY, 0, window.innerHeight)
}

function revealOffscreenRow(wrap, dy) {
  const rows = tableRows()
  if (!rows.length || !dy) return false
  const r = wrap.getBoundingClientRect()
  const top = Math.max(0, r.top)
  const bottom = Math.min(window.innerHeight, r.bottom)
  if (dy < 0) {
    for (let i = 0; i < rows.length; i++) {
      if (rows[i].getBoundingClientRect().bottom > top + 1) {
        if (i === 0) return false
        ;(rows[i - 1].querySelector('td') || rows[i - 1]).scrollIntoView({
          block: 'nearest',
          inline: 'nearest',
        })
        return true
      }
    }
  } else {
    for (let i = rows.length - 1; i >= 0; i--) {
      if (rows[i].getBoundingClientRect().top < bottom - 1) {
        if (i >= rows.length - 1) return false
        ;(rows[i + 1].querySelector('td') || rows[i + 1]).scrollIntoView({
          block: 'nearest',
          inline: 'nearest',
        })
        return true
      }
    }
  }
  return false
}

function stopAutoScroll() {
  if (!autoScrollRaf) return
  cancelAnimationFrame(autoScrollRaf)
  autoScrollRaf = 0
}

function tickAutoScroll(now) {
  autoScrollRaf = 0
  if (dragFrom == null || !dragMoved) return
  const wrap = wrapEl()
  if (wrap) {
    const dy = edgeDelta(wrap, dragClientY)
    if (dy) {
      let moved = scrollByDy(wrap, dy)
      if (!moved && now - lastRowRevealAt > 40) {
        lastRowRevealAt = now
        moved = revealOffscreenRow(wrap, dy)
      }
      if (moved) paintDragAt(dragClientX, dragClientY)
    }
  }
  autoScrollRaf = requestAnimationFrame(tickAutoScroll)
}

function onDragWheel(event) {
  if (dragFrom == null || !dragMoved) return
  const wrap = wrapEl()
  if (!wrap || !event.deltaY) return
  event.preventDefault()
  scrollByDy(wrap, event.deltaY)
  paintDragAt(dragClientX, dragClientY)
}

function teardownDragUi() {
  ghostEl?.remove()
  lineEl?.remove()
  ghostEl = null
  lineEl = null
  tableRows().forEach((tr) => tr.classList.remove(DRAG_CLASS))
}

function stopListening() {
  window.removeEventListener('pointermove', onPointerMove, true)
  window.removeEventListener('pointerup', onPointerUp, true)
  window.removeEventListener('pointercancel', onPointerUp, true)
  window.removeEventListener('wheel', onDragWheel, { capture: true })
  stopAutoScroll()
}

function endDrag() {
  stopListening()
  document.body.style.cursor = ''
  document.body.style.userSelect = ''
  teardownDragUi()
  dragFrom = null
  dragMoved = false
  dragStartY = 0
  dragClientX = 0
  dragClientY = 0
}

let resizeKey = null
let resizeStartX = 0
let resizeStartW = 0
let resizeStartDescW = 0

function startResize(key, event) {
  if (event.button !== 0) return
  event.preventDefault()
  event.stopPropagation()
  resizeKey = key
  resizeStartX = event.clientX
  if (key === 'value') {
    const th = event.currentTarget.closest('[data-slot="th"]')
    resizeStartW = th?.getBoundingClientRect().width ?? colWidths.value
    colWidths.value = resizeStartW
    resizeStartDescW = colWidths.description
  } else {
    resizeStartW = colWidths[key]
  }
  document.body.style.cursor = 'col-resize'
  document.body.style.userSelect = 'none'
  window.addEventListener('pointermove', onResizeMove)
  window.addEventListener('pointerup', onResizeUp)
  window.addEventListener('pointercancel', onResizeUp)
}

function onResizeMove(event) {
  if (!resizeKey) return
  const delta = event.clientX - resizeStartX
  const min = COL_MIN[resizeKey] ?? 48
  if (resizeKey !== 'value') {
    colWidths[resizeKey] = Math.max(min, resizeStartW + delta)
    return
  }
  const descMin = COL_MIN.description ?? 48
  const valueW = Math.max(min, resizeStartW + delta)
  let descW = Math.max(descMin, resizeStartDescW - delta)
  if (delta < 0 && resizeStartW + delta <= min) {
    descW = Math.max(descMin, resizeStartDescW + resizeStartW - min)
  }
  colWidths.value = valueW
  colWidths.description = descW
}

function onResizeUp() {
  window.removeEventListener('pointermove', onResizeMove)
  window.removeEventListener('pointerup', onResizeUp)
  window.removeEventListener('pointercancel', onResizeUp)
  document.body.style.cursor = ''
  document.body.style.userSelect = ''
  resizeKey = null
}

function onPointerDown(index, event) {
  if (props.disabled || event.button !== 0) return
  if (isDraftRow(index) || isDomainRecord(records.value[index])) return
  event.preventDefault()
  event.currentTarget.setPointerCapture?.(event.pointerId)
  dragFrom = index
  dragMoved = false
  dragStartY = event.clientY
  window.addEventListener('pointermove', onPointerMove, { passive: false, capture: true })
  window.addEventListener('pointerup', onPointerUp, true)
  window.addEventListener('pointercancel', onPointerUp, true)
}

function onPointerMove(event) {
  if (dragFrom == null) return
  if (!dragMoved && Math.abs(event.clientY - dragStartY) < DRAG_THRESHOLD_PX) {
    return
  }
  if (!dragMoved) {
    dragMoved = true
    document.body.style.cursor = 'grabbing'
    document.body.style.userSelect = 'none'
    ensureDragUi()
    fillGhost(records.value[dragFrom])
    lastRowRevealAt = 0
    window.addEventListener('wheel', onDragWheel, { passive: false, capture: true })
  }
  event.preventDefault()
  dragClientX = event.clientX
  dragClientY = event.clientY
  paintSource(dragFrom)
  paintDragAt(dragClientX, dragClientY)
  if (!autoScrollRaf) autoScrollRaf = requestAnimationFrame(tickAutoScroll)
}

function onPointerUp(event) {
  const from = dragFrom
  const gap = dragMoved ? clampGapToSubzone(from, gapFromY(event.clientY)) : -1
  const to = insertIndex(from, gap)
  endDrag()
  if (from == null || gap < 0 || from === to) return
  const next = [...records.value]
  const [item] = next.splice(from, 1)
  next.splice(to, 0, item)
  records.value = next
}

onBeforeUnmount(() => {
  clearTimeout(overflowTipTimer)
  endDrag()
  onResizeUp()
})
</script>

<style>
.zone-record-ghost {
  top: 0;
  left: 0;
  opacity: 0;
  will-change: transform;
}
.zone-record-drop-line {
  position: fixed;
  top: 0;
  left: 0;
  z-index: 50;
  height: 3px;
  pointer-events: none;
  border-radius: 9999px;
  background: var(--ui-primary);
  box-shadow: 0 0 0 1px var(--ui-bg);
  opacity: 0;
  will-change: transform, width;
}
.zone-record-drop-line::before {
  content: '';
  position: absolute;
  left: -5px;
  top: 50%;
  width: 11px;
  height: 11px;
  border-radius: 9999px;
  background: var(--ui-primary);
  box-shadow: 0 0 0 1px var(--ui-bg);
  transform: translateY(-50%);
}
.zone-record-dragging > td {
  opacity: 0.4;
  background: color-mix(in oklab, var(--ui-primary) 8%, transparent) !important;
}
.zone-record-dragging > td:first-child {
  box-shadow: inset 2px 0 0 var(--ui-primary);
}
.zone-records-table {
  max-height: min(48rem, calc(100dvh - var(--ui-header-height, 4rem) - 8rem));
  overscroll-behavior: contain;
}
.zone-records-table [data-slot='th'],
.zone-records-table [data-slot='td'] {
  border-inline-end: 1px solid var(--ui-border-accented);
}
.zone-records-table [data-slot='th']:last-child,
.zone-records-table [data-slot='td']:last-child {
  border-inline-end: 0;
}
.zone-records-table [data-slot='tbody'] [data-slot='tr']:not(:last-child) [data-slot='td'] {
  border-block-end: 1px solid var(--ui-border-accented);
}
.zone-records-table [data-slot='thead'] [data-slot='th'] {
  position: sticky;
  top: 0;
  z-index: 10;
  background-color: var(--ui-bg-elevated);
  border-block-end: 1px solid var(--ui-border-accented);
}
.zone-records-table [data-slot='td']:hover {
  background: color-mix(in oklab, var(--ui-bg-elevated) 70%, transparent);
}
.zone-records-table [data-slot='td']:focus-within {
  position: relative;
  z-index: 1;
  background: var(--ui-bg);
  box-shadow: inset 0 0 0 2px var(--ui-primary);
}
.zone-records-table input[type='number'] {
  appearance: textfield;
}
.zone-records-table input[type='number']::-webkit-outer-spin-button,
.zone-records-table input[type='number']::-webkit-inner-spin-button {
  appearance: none;
  margin: 0;
}
.zone-records-table tr.zone-record-comment [data-slot='td'] {
  background: color-mix(in oklab, var(--ui-bg-elevated) 55%, transparent);
}
.zone-records-table tr.zone-record-comment input {
  font-style: italic;
}
.zone-records-table tr.zone-record-domain [data-slot='td'] {
  background: color-mix(in oklab, var(--ui-primary) 10%, var(--ui-bg-elevated));
}
.zone-records-table tr.zone-record-domain input {
  font-weight: 600;
}
.zone-records-table tr.zone-record-changed > [data-slot='td'] {
  background: color-mix(
    in oklab,
    var(--ui-warning, var(--color-warning, oklch(0.75 0.15 85))) 16%,
    transparent
  );
}
.zone-records-table tr.zone-record-changed.zone-record-comment > [data-slot='td'] {
  background: color-mix(
    in oklab,
    var(--ui-warning, var(--color-warning, oklch(0.75 0.15 85))) 18%,
    color-mix(in oklab, var(--ui-bg-elevated) 55%, transparent)
  );
}
.zone-records-table tr.zone-record-changed.zone-record-domain > [data-slot='td'] {
  background: color-mix(
    in oklab,
    var(--ui-warning, var(--color-warning, oklch(0.75 0.15 85))) 18%,
    color-mix(in oklab, var(--ui-primary) 10%, var(--ui-bg-elevated))
  );
}
.zone-records-table tr.zone-record-changed > [data-slot='td']:first-child {
  box-shadow: inset 2px 0 0 var(--ui-warning, var(--color-warning, oklch(0.75 0.15 85)));
}
.zone-records-table tr.zone-record-changed [data-slot='td']:hover {
  background: color-mix(
    in oklab,
    var(--ui-warning, var(--color-warning, oklch(0.75 0.15 85))) 24%,
    transparent
  );
}
.zone-records-table tr.zone-record-changed [data-slot='td']:focus-within {
  background: color-mix(
    in oklab,
    var(--ui-warning, var(--color-warning, oklch(0.75 0.15 85))) 12%,
    var(--ui-bg)
  );
}
.zone-col-head {
  display: flex;
  align-items: center;
  min-height: 1.25rem;
  padding-inline-end: 0.5rem;
}
.zone-col-resizer {
  position: absolute;
  top: 0;
  right: -3px;
  z-index: 2;
  width: 7px;
  height: 100%;
  padding: 0;
  border: 0;
  cursor: col-resize;
  background: transparent;
}
.zone-col-resizer:hover,
.zone-col-resizer:focus-visible {
  background: color-mix(in oklab, var(--ui-primary) 55%, transparent);
}
.zone-rdata-fields {
  display: flex;
  align-items: stretch;
  width: 100%;
  min-width: 0;
}
.zone-rdata-fields > :not(:first-child) {
  border-inline-start: 1px solid var(--ui-border-accented);
}
</style>
