// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { computed, onBeforeUnmount, ref, toValue, watch } from 'vue'

// Resizable table columns: drag a handle in a header cell (`onPointerDown`)
// to set that column's width, double-click it (`reset`) to go back to the
// table's own widths. `table` is a ref to the <table>, whose header cells
// line up one to one with its columns (no colspan); `storageKey` (a value,
// ref or getter) names the widths saved in localStorage. The first resize
// fixes every column at its current width, so `widths` then holds all of
// them and the table is `total` wide: resizing one column leaves the others
// alone. `widths` is null while the table has its own widths.
const MIN_PX = 24

function load(key) {
  try {
    const list = JSON.parse(localStorage.getItem(key))
    return Array.isArray(list) && list.every((w) => Number.isFinite(w)) ? list : null
  } catch {
    return null
  }
}

function store(key, list) {
  try {
    if (list) localStorage.setItem(key, JSON.stringify(list))
    else localStorage.removeItem(key)
  } catch {
    // Not saved: the widths last until the page reloads.
  }
}

export function useColumnResize({ table, storageKey }) {
  const widths = ref(null)
  watch(
    () => toValue(storageKey),
    (key) => (widths.value = load(key)),
    { immediate: true },
  )
  const total = computed(() => widths.value?.reduce((sum, w) => sum + w, 0) ?? 0)

  let col = -1
  let startX = 0
  let startW = 0

  function onPointerMove(event) {
    event.preventDefault()
    const list = [...widths.value]
    list[col] = Math.max(MIN_PX, Math.round(startW + event.clientX - startX))
    widths.value = list
  }

  function end() {
    window.removeEventListener('pointermove', onPointerMove, true)
    window.removeEventListener('pointerup', onPointerUp, true)
    window.removeEventListener('pointercancel', onPointerUp, true)
    document.body.style.cursor = ''
    document.body.style.userSelect = ''
    col = -1
  }

  function onPointerUp() {
    const resized = col >= 0
    end()
    if (resized) store(toValue(storageKey), widths.value)
  }

  function onPointerDown(event) {
    if (event.button !== 0) return
    const th = event.target.closest('th')
    const cells = [...(table.value?.querySelectorAll('thead > tr > th') ?? [])]
    if (!th || !cells.length) return
    event.preventDefault()
    event.stopPropagation()
    if (widths.value?.length !== cells.length) {
      widths.value = cells.map((c) => Math.round(c.getBoundingClientRect().width))
    }
    col = th.cellIndex
    startX = event.clientX
    startW = widths.value[col]
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
    window.addEventListener('pointermove', onPointerMove, { passive: false, capture: true })
    window.addEventListener('pointerup', onPointerUp, true)
    window.addEventListener('pointercancel', onPointerUp, true)
  }

  function reset() {
    widths.value = null
    store(toValue(storageKey), null)
  }

  onBeforeUnmount(end)
  return { widths, total, onPointerDown, reset }
}
