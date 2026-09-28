// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// useServiceDialog: the dialog that creates a custom service from a rule's
// Service cell (ServiceDialog, mounted once in AppLayout, so it outlives the
// cell's menu and stacks over a form's modal). create(name) opens it with a
// suggested name and resolves to the created service, or null if the
// dialog was closed without saving.
import { reactive } from 'vue'

const state = reactive({ open: false, name: '', resolve: null })

export function useServiceDialog() {
  function create(name = '') {
    state.resolve?.(null)
    return new Promise((resolve) => Object.assign(state, { open: true, name, resolve }))
  }

  function done(svc) {
    const resolve = state.resolve
    Object.assign(state, { open: false, resolve: null })
    resolve?.(svc)
  }

  return { state, create, done }
}
