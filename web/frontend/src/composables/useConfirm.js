// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// useConfirm: a Yes/No question (ConfirmDialog, mounted once in AppLayout,
// so it stacks over a form's modal). confirmDelete(what, detail) asks
// "Delete <what>?" and resolves to true on Yes, false on No or when the
// dialog is closed.
import { reactive } from 'vue'

const state = reactive({ open: false, title: '', message: '', detail: '', resolve: null })

export function useConfirm() {
  function ask({ title, message, detail = '' }) {
    state.resolve?.(false)
    return new Promise((resolve) =>
      Object.assign(state, { open: true, title, message, detail, resolve }),
    )
  }

  function confirmDelete(what, detail = '') {
    return ask({ title: 'Delete', message: `Delete ${what}?`, detail })
  }

  function done(yes) {
    const resolve = state.resolve
    Object.assign(state, { open: false, resolve: null })
    resolve?.(yes)
  }

  return { state, ask, confirmDelete, done }
}
