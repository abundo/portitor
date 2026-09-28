// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// usePortMenu: a menu of service names and their ports (the custom services
// and fwconfig.Services) for a port list input, shown by PortMenu; a
// datalist cannot show a name and its port on one line. While typing it
// offers the names that start with the last entry, or whose port does; on a
// click, or when the last entry is complete (a name, port or range), every
// name, and a pick is added to the list. Names already in the list are left
// out. The menu ends with an entry that creates a custom service
// (useServiceDialog), named after the last entry if that is a new name.
// Bind open to the input's click and input events (not focus, so the arrow
// keys can move into the input without it), close to blur, and give the
// keys to onKeydown first: with the menu open the arrows move in it, Enter
// and Tab pick, Escape closes it. A pick, or a created service, completes
// the last entry or is added after it, and sends an input event, so
// v-model sees it. The callers load the object store.
import { markRaw, onBeforeUnmount, ref } from 'vue'
import { useServiceDialog } from '@/composables/useServiceDialog'
import { useObjectStore } from '@/stores/objects'

const nameRe = /^[a-z][a-z0-9_.-]*$/
const portRe = /^\d+(\s*-\s*\d+)?$/

export function usePortMenu() {
  const objects = useObjectStore()
  const dialog = useServiceDialog()
  const menu = ref(null) // { el, top, left, width, items, newName, append, active }

  const isName = (s) => objects.portNames.some((it) => it.name === s)

  // Scrolling the page or a box around the input moves the input away from
  // the menu. Other scrolling (the menu's own, the log panel following new
  // lines) leaves it, and so does the input's: it scrolls sideways as text
  // beyond its width is typed.
  function onScroll(event) {
    const el = menu.value?.el
    if (el && event.target !== el && event.target.contains?.(el)) close()
  }

  function open(event) {
    const el = event.target
    const parts = el.value.split(',').map((p) => p.trim().toLowerCase())
    const last = parts.at(-1)
    const used = new Set(parts.slice(0, -1))
    // A complete last entry stays when the input is clicked: the menu then
    // offers every other name, to add. Typing filters by the last entry.
    const append = !!last && event.type === 'click' && (isName(last) || portRe.test(last))
    if (append) used.add(last)
    const filter = append ? '' : last
    const items = objects.portNames.filter(
      (it) =>
        !used.has(it.name) && (it.name.startsWith(filter) || String(it.port).startsWith(filter)),
    )
    const newName = !append && nameRe.test(last) && !isName(last) ? last : ''
    // Digits that match nothing get no menu; a new name gets the create entry.
    if (!items.length && !newName && !append) return close()
    if (!menu.value) window.addEventListener('scroll', onScroll, true)
    const rect = el.getBoundingClientRect()
    menu.value = {
      el: markRaw(el),
      top: rect.bottom,
      left: rect.left,
      width: rect.width,
      items,
      newName,
      append,
      active: -1,
    }
  }

  function close() {
    if (menu.value) window.removeEventListener('scroll', onScroll, true)
    menu.value = null
  }
  onBeforeUnmount(close)

  // setLast replaces the last entry of the input with name, or with append
  // adds name after it.
  function setLast(el, name, append) {
    const parts = el.value.split(',').map((p) => p.trim())
    if (!append) parts.pop()
    el.value = [...parts.filter((p) => p), name].join(', ')
    el.dispatchEvent(new Event('input', { bubbles: true }))
  }

  function pick(it) {
    setLast(menu.value.el, it.name, menu.value.append)
    close()
  }

  // create opens the dialog for a new custom service; once it is saved,
  // its name goes in place of the last entry and the input gets the focus
  // back. Callers that save on blur skip it while the dialog is open.
  async function create() {
    const { el, newName, append } = menu.value
    close()
    const svc = await dialog.create(newName)
    if (!el.isConnected) return
    if (svc) setLast(el, svc.name, append || !newName)
    close() // the input event opened it again
    el.focus()
  }

  // onKeydown tells whether it handled the key. The create entry comes
  // after the items.
  function onKeydown(event) {
    const m = menu.value
    if (!m || event.isComposing) return false
    const n = m.items.length + 1
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      m.active = (m.active + (event.key === 'ArrowDown' ? 1 : n - 1 + (m.active < 0))) % n
    } else if ((event.key === 'Enter' || event.key === 'Tab') && m.active >= 0) {
      if (m.active < m.items.length) pick(m.items[m.active])
      else create()
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

  return { menu, open, close, pick, create, onKeydown }
}
