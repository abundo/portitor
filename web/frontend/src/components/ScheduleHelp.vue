<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// ScheduleHelp: presets for a cron schedule and its next runs as
// portitor-web computes them, updated as the schedule is typed.
import { ref, watch } from 'vue'
import { api } from '@/api'
import { when } from '@/utils/time'

const model = defineModel({ type: String, default: '' })

const presets = [
  { label: 'Every 5 min', value: '*/5 * * * *' },
  { label: 'Every 15 min', value: '*/15 * * * *' },
  { label: 'Hourly', value: '@hourly' },
  { label: 'Daily 03:00', value: '0 3 * * *' },
  { label: 'Weekly, Sun 03:00', value: '0 3 * * sun' },
  { label: 'Monthly', value: '@monthly' },
]

const next = ref([])
const error = ref('')
// pending: the shown answer is not for the current text yet.
const pending = ref(false)
let timer = null
let seq = 0
watch(
  model,
  (v) => {
    clearTimeout(timer)
    pending.value = true
    if (!v?.trim()) {
      next.value = []
      error.value = ''
      return
    }
    timer = setTimeout(async () => {
      const mine = ++seq
      try {
        const res = await api.schedulePreview(v)
        if (mine !== seq) return
        next.value = res.next ?? []
        error.value = res.error ?? ''
        pending.value = false
      } catch {
        // The preview is a convenience; saving reports real errors.
      }
    }, 250)
  },
  { immediate: true },
)
</script>

<template>
  <div class="space-y-2 text-sm">
    <div class="flex flex-wrap gap-1">
      <UButton
        v-for="p in presets"
        :key="p.value"
        size="xs"
        :variant="model === p.value ? 'solid' : 'soft'"
        color="neutral"
        :label="p.label"
        @click="model = p.value"
      />
    </div>
    <p class="text-xs text-muted">
      minute hour day-of-month month day-of-week: <code>*</code>, <code>5</code>, <code>1-5</code>,
      <code>*/15</code>, <code>1,15</code>; names like <code>mon</code> and <code>jan</code>;
      <code>@hourly</code>, <code>@daily</code>, <code>@weekly</code>, <code>@monthly</code>. In the
      firewall's time zone.
    </p>
    <p v-if="error" class="text-error">{{ error }}</p>
    <div v-else-if="next.length" class="text-xs">
      <span class="text-muted">Next runs:</span>
      {{ next.map(when).join(' · ') }}
    </div>
    <p v-else-if="model?.trim() && !pending" class="text-xs text-warning">
      This schedule never fires.
    </p>
  </div>
</template>
