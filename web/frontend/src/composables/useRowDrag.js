// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { onBeforeUnmount } from 'vue'

// Drag-and-drop reordering of table rows by a grip handle, with the same
// ghost and drop line as the DNS records grid. `wrap` is a ref to an element
// containing the table (the scroll container, if it scrolls); rows are the
// <tr>s matching the optional `rowSelector` (by default every tbody's direct
// <tr>s), hidden ones included so indexes match. `label(index)` is the ghost text; `onMove(from, to)`
// is called on drop with the row's old and new index; the optional
// `onClick(index)` when the grip is released without dragging.
const THRESHOLD_PX = 4
const EDGE_PX = 64
const MAX_STEP_PX = 24

export function useRowDrag({ wrap, label, onMove, onClick, rowSelector = 'tbody > tr' }) {
  let from = null
  let moved = false
  let startY = 0
  let x = 0
  let y = 0
  let raf = 0
  let ghost = null
  let line = null

  function rows() {
    return [...(wrap.value?.querySelectorAll(rowSelector) ?? [])]
  }

  function gapAt(clientY) {
    const list = rows()
    for (let i = 0; i < list.length; i++) {
      if (list[i].hidden) continue
      const { top, bottom } = list[i].getBoundingClientRect()
      if (clientY < (top + bottom) / 2) return i
    }
    return list.length
  }

  function paint() {
    const pad = 8
    const gx = Math.min(Math.max(pad, x + 16), window.innerWidth - ghost.offsetWidth - pad)
    const gy = Math.min(Math.max(pad, y + 16), window.innerHeight - ghost.offsetHeight - pad)
    ghost.style.transform = `translate(${gx}px, ${gy}px)`
    ghost.style.opacity = '1'

    const list = rows()
    const table = wrap.value?.querySelector('table')
    if (!list.length || !table) return
    const gap = gapAt(y)
    const box = table.getBoundingClientRect()
    const clip = wrap.value.getBoundingClientRect()
    const left = Math.max(box.left, clip.left)
    const shown = list.filter((tr) => !tr.hidden)
    const lineY =
      gap >= list.length
        ? shown[shown.length - 1].getBoundingClientRect().bottom
        : list[gap].getBoundingClientRect().top
    line.style.opacity = '1'
    line.style.width = `${Math.min(box.right, clip.right) - left}px`
    line.style.transform = `translate(${left}px, ${lineY - 1.5}px)`
  }

  function edgeStep(top, bottom) {
    if (y < top + EDGE_PX) return -Math.ceil(((top + EDGE_PX - y) / EDGE_PX) * MAX_STEP_PX)
    if (y > bottom - EDGE_PX) return Math.ceil(((y - bottom + EDGE_PX) / EDGE_PX) * MAX_STEP_PX)
    return 0
  }

  function tick() {
    raf = 0
    if (from == null || !moved) return
    const el = wrap.value
    const r = el.getBoundingClientRect()
    const dy = edgeStep(Math.max(0, r.top), Math.min(window.innerHeight, r.bottom))
    if (dy) {
      const before = el.scrollTop
      el.scrollTop += dy
      if (el.scrollTop === before) window.scrollBy(0, dy)
      paint()
    }
    raf = requestAnimationFrame(tick)
  }

  function start() {
    moved = true
    document.body.style.cursor = 'grabbing'
    document.body.style.userSelect = 'none'
    ghost = document.createElement('div')
    ghost.className =
      'row-drag-ghost fixed z-50 pointer-events-none rounded-md border border-primary/50 bg-elevated px-3 py-1.5 text-sm shadow-lg max-w-lg truncate'
    ghost.textContent = label(from)
    line = document.createElement('div')
    line.className = 'row-drag-line'
    document.body.append(ghost, line)
    rows()[from]?.classList.add('row-dragging')
  }

  function end() {
    window.removeEventListener('pointermove', onPointerMove, true)
    window.removeEventListener('pointerup', onPointerUp, true)
    window.removeEventListener('pointercancel', onPointerUp, true)
    cancelAnimationFrame(raf)
    raf = 0
    document.body.style.cursor = ''
    document.body.style.userSelect = ''
    ghost?.remove()
    line?.remove()
    ghost = line = null
    rows().forEach((tr) => tr.classList.remove('row-dragging'))
    from = null
    moved = false
  }

  function onPointerMove(event) {
    if (!moved && Math.abs(event.clientY - startY) < THRESHOLD_PX) return
    if (!moved) start()
    event.preventDefault()
    x = event.clientX
    y = event.clientY
    paint()
    if (!raf) raf = requestAnimationFrame(tick)
  }

  function onPointerUp(event) {
    const src = from
    const clicked = !moved && event.type === 'pointerup'
    const gap = moved && event.type === 'pointerup' ? gapAt(event.clientY) : -1
    end()
    if (src != null && clicked) onClick?.(src)
    if (src == null || gap < 0) return
    const to = gap > src ? gap - 1 : gap
    if (to !== src) onMove(src, to)
  }

  function onPointerDown(index, event) {
    if (event.button !== 0) return
    event.preventDefault()
    from = index
    moved = false
    startY = event.clientY
    window.addEventListener('pointermove', onPointerMove, { passive: false, capture: true })
    window.addEventListener('pointerup', onPointerUp, true)
    window.addEventListener('pointercancel', onPointerUp, true)
  }

  onBeforeUnmount(end)
  return { onPointerDown }
}
