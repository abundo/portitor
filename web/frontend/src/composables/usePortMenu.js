// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// usePortMenu: a menu of service names and their ports (fwconfig.Services)
// for a port list input, shown by PortMenu; a datalist cannot show a name
// and its port on one line. It offers the names that start with the last
// entry typed, or whose port does, leaving out those already in the list.
// Bind open to the input's click and input events (not focus, so the arrow
// keys can move into the input without it), close to blur, and give the
// keys to onKeydown first: with the menu open the arrows move in it, Enter
// and Tab pick, Escape closes it. A pick replaces the last entry and sends
// an input event, so v-model sees it. The callers load the object store.
import { markRaw, onBeforeUnmount, ref } from 'vue'
import { useObjectStore } from '@/stores/objects'

export function usePortMenu() {
  const objects = useObjectStore()
  const menu = ref(null) // { el, top, left, width, items, active }

  function matches(text) {
    const parts = text.split(',')
    const last = parts.pop().trim().toLowerCase()
    const used = new Set(parts.map((p) => p.trim().toLowerCase()))
    return objects.services.filter(
      (it) => !used.has(it.name) && (it.name.startsWith(last) || String(it.port).startsWith(last)),
    )
  }

  // Scrolling anything but the menu moves the input away from it.
  function onScroll(event) {
    if (!event.target.closest?.('.port-menu')) close()
  }

  function open(event) {
    const el = event.target
    const items = matches(el.value)
    if (!items.length) return close()
    if (!menu.value) window.addEventListener('scroll', onScroll, true)
    const rect = el.getBoundingClientRect()
    menu.value = {
      el: markRaw(el),
      top: rect.bottom,
      left: rect.left,
      width: rect.width,
      items,
      active: -1,
    }
  }

  function close() {
    if (menu.value) window.removeEventListener('scroll', onScroll, true)
    menu.value = null
  }
  onBeforeUnmount(close)

  function pick(it) {
    const { el } = menu.value
    const head = el.value
      .split(',')
      .slice(0, -1)
      .map((p) => p.trim())
      .filter((p) => p)
    el.value = [...head, it.name].join(', ')
    el.dispatchEvent(new Event('input', { bubbles: true }))
    close()
  }

  // onKeydown tells whether it handled the key.
  function onKeydown(event) {
    const m = menu.value
    if (!m || event.isComposing) return false
    const n = m.items.length
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      m.active = (m.active + (event.key === 'ArrowDown' ? 1 : n - 1 + (m.active < 0))) % n
    } else if ((event.key === 'Enter' || event.key === 'Tab') && m.active >= 0) {
      pick(m.items[m.active])
    } else if (event.key === 'Escape') {
      close()
    } else {
      return false
    }
    event.preventDefault()
    // Escape would close a modal around the input too.
    event.stopPropagation()
    return true
  }

  return { menu, open, close, pick, onKeydown }
}
