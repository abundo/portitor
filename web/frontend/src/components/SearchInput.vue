<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// SearchInput: the search field above a table (AGENTS.md, GUI design
// rules), with an X that clears it; Escape clears it too. Enter does not
// submit a form around it.
const search = defineModel({ type: String, default: '' })
defineProps({
  placeholder: { type: String, default: 'Search' },
  size: { type: String, default: 'sm' },
})
</script>

<template>
  <UInput
    v-model="search"
    icon="i-lucide-search"
    :placeholder="placeholder"
    :aria-label="placeholder"
    :size="size"
    class="w-64 max-w-full"
    :ui="{ trailing: 'pe-1' }"
    @keydown.enter.prevent
    @keydown.esc="search = ''"
  >
    <template v-if="search" #trailing>
      <UButton
        color="neutral"
        variant="link"
        :size="size"
        icon="i-lucide-x"
        aria-label="Clear search"
        title="Clear search"
        @click="search = ''"
      />
    </template>
  </UInput>
</template>
