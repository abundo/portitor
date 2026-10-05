<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// The Refresh button of a view that refreshes itself (useAutoRefresh): while
// it runs, its icon turns slowly and its label names the interval; after an
// hour it stops and says so. A click refreshes at once, and starts another
// hour when stopped.
import { computed } from 'vue'

const props = defineProps({
  // What useAutoRefresh returns.
  auto: { type: Object, required: true },
  loading: { type: Boolean, default: false },
  size: { type: String, default: 'md' },
})

const tooltip = computed(() =>
  props.auto.running
    ? `Refreshes automatically every ${props.auto.seconds} s, for an hour. Click to refresh now.`
    : 'Automatic refresh stopped after an hour. Click to refresh, and refresh automatically for another hour.',
)
</script>

<template>
  <UTooltip :text="tooltip">
    <UButton
      color="neutral"
      variant="outline"
      :size="size"
      :loading="loading"
      :label="auto.running ? `Auto · ${auto.seconds} s` : 'Auto stopped'"
      :icon="auto.running ? 'i-lucide-refresh-cw' : 'i-lucide-circle-pause'"
      :ui="{
        leadingIcon: loading || !auto.running ? '' : 'animate-spin [animation-duration:3s]',
      }"
      @click="auto.refresh()"
    />
  </UTooltip>
</template>
