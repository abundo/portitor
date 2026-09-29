<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// ConfirmDialog: the Yes/No question of useConfirm. Mounted once in
// AppLayout. No has the focus, so Enter doesn't delete by accident.
// Modals stack by the order of their portals in the page, which depends on
// which was opened first; the z-index keeps this one above a form's modal.
import { useConfirm } from '@/composables/useConfirm'

const { state, done } = useConfirm()
const ui = { overlay: 'z-60', content: 'z-60' }
</script>

<template>
  <UModal
    :open="state.open"
    :title="state.title"
    :ui="ui"
    :dismissible="false"
    @update:open="(o) => o || done(false)"
  >
    <template #body>
      <p class="text-sm">{{ state.message }}</p>
      <p v-if="state.detail" class="mt-2 text-sm text-muted">{{ state.detail }}</p>
    </template>
    <template #footer>
      <div class="flex w-full justify-end gap-2">
        <UButton color="neutral" variant="outline" autofocus @click="done(false)">No</UButton>
        <UButton color="error" @click="done(true)">Yes</UButton>
      </div>
    </template>
  </UModal>
</template>
