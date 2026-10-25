<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// FormHeader: a page form's title with its Save button (AGENTS.md, GUI
// design rules), kept at the top of the page while the form scrolls under
// it. The default slot holds the buttons. The negative top cancels the
// main area's padding, which sticky positioning keeps clear.
defineProps({ title: { type: String, default: '' } })
</script>

<template>
  <div
    class="sticky -top-4 z-20 mb-2 flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-default bg-default py-2 md:-top-6"
  >
    <h2 class="flex min-w-0 flex-wrap items-center gap-2 text-xl font-semibold">
      <slot name="title">{{ title }}</slot>
    </h2>
    <div class="ms-auto flex flex-wrap items-center gap-2">
      <slot />
    </div>
  </div>
</template>
