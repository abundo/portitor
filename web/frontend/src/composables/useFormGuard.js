// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Unsaved changes (AGENTS.md, GUI design rules). A form registers how to
// tell it has changes; leaving the page (the router), switching instance
// (the topbar) or logging out asks "Discard them?" first through
// confirmDiscard(), and closing or reloading the tab gets the browser's own
// warning.
//
// useFormGuard(source, open, onClose): a dialog form. `source` is the form
// (a reactive, a ref or a getter), `open` the dialog's open ref. The form is
// recorded once the dialog has opened and rendered; close() asks if it
// differs, then calls onClose (default: open = false). Cancel and the
// modal's X go through close(); Save and Delete close the dialog directly.
//
// useUnsaved(dirty): a page with its own test for changes.
//
// usePageForm(source): a form on the page itself. mark() records the form
// as saved: call it once the form is loaded and after each save.
import { nextTick, onScopeDispose, shallowRef, toValue, watch } from 'vue'
import { useConfirm } from '@/composables/useConfirm'

// forms holds the mounted forms: { dirty: () => bool, discard: () => void }.
const forms = new Set()

export const hasUnsaved = () => [...forms].some((f) => f.dirty())

window.addEventListener('beforeunload', (e) => {
  if (hasUnsaved()) e.preventDefault()
})

function askDiscard() {
  return useConfirm().ask({
    title: 'Unsaved changes',
    message: 'You have changes that are not saved. Discard them?',
  })
}

// confirmDiscard resolves to true when nothing is unsaved or the user
// discards it (dialogs holding changes close); false on No.
export async function confirmDiscard() {
  const dirty = [...forms].filter((f) => f.dirty())
  if (!dirty.length) return true
  if (!(await askDiscard())) return false
  for (const f of dirty) f.discard()
  return true
}

export function useUnsaved(dirty, discard = () => {}) {
  const entry = { dirty, discard }
  forms.add(entry)
  onScopeDispose(() => forms.delete(entry))
}

// tracker records a snapshot of source and compares against it.
// saved is a ref so a render that called dirty() before mark() renders again
// after it (the fields may be in child slots that the render doesn't track).
function tracker(source) {
  const saved = shallowRef(null)
  const snapshot = () => JSON.stringify(toValue(source))
  return {
    mark: () => (saved.value = snapshot()),
    clear: () => (saved.value = null),
    dirty: () => saved.value !== null && snapshot() !== saved.value,
  }
}

export function usePageForm(source) {
  const t = tracker(source)
  useUnsaved(t.dirty)
  return { mark: t.mark, dirty: t.dirty }
}

export function useFormGuard(source, open, onClose = () => (open.value = false)) {
  const t = tracker(source)
  useUnsaved(t.dirty, onClose)

  watch(open, async (o) => {
    t.clear()
    if (!o) return
    await nextTick()
    if (open.value) t.mark()
  })

  async function close() {
    if (t.dirty() && !(await askDiscard())) return
    onClose()
  }

  // onUpdateOpen is the modal's @update:open: only a close goes through.
  const onUpdateOpen = (o) => o || close()

  return { close, dirty: t.dirty, onUpdateOpen }
}
