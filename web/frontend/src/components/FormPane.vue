<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// FormPane: a form shown beside a tree (Hosts & prefixes) in place of a
// dialog. The title and the buttons (slot actions: Delete, Cancel, Save)
// stay at the top while the form (the default slot) scrolls under them.
defineProps({ title: { type: String, default: '' } })
</script>

<template>
  <div class="flex h-full min-h-0 flex-col">
    <div class="mb-3 flex flex-wrap items-center gap-2 border-b border-default pb-2">
      <h2 class="min-w-0 text-lg font-semibold">{{ title }}</h2>
      <div class="ms-auto flex flex-wrap items-center gap-2">
        <slot name="actions" />
      </div>
    </div>
    <div class="min-h-0 flex-1 overflow-y-auto pe-1">
      <slot />
    </div>
  </div>
</template>
