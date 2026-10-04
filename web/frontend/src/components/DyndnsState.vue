<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed } from 'vue'
import { useDeployStore } from '@/stores/deploy'
import { useInstanceStore } from '@/stores/instances'
import { ago } from '@/utils/time'

// What the agent reports for the selected instance's DNS update client;
// the page refreshes the deploy store's status.
const props = defineProps({ name: { type: String, required: true } })
const deploy = useDeployStore()
const store = useInstanceStore()

const state = computed(() =>
  (deploy.status?.dyndns ?? []).find(
    (s) => s.instance === store.current?.name && s.name === props.name,
  ),
)
const stateColor = { ok: 'success', error: 'error', waiting: 'warning' }
</script>

<template>
  <div v-if="state" class="space-y-0.5 text-xs">
    <UBadge :color="stateColor[state.state] ?? 'neutral'" variant="subtle" size="sm">
      {{ state.state }}
    </UBadge>
    <div v-if="state.ipv4 || state.ipv6" class="font-mono">
      {{ [state.ipv4, state.ipv6].filter(Boolean).join(', ') }}
    </div>
    <div v-if="state.server" class="font-mono text-muted">nameserver {{ state.server }}</div>
    <div class="text-muted">updated {{ ago(state.last_update) }}</div>
    <div v-if="state.last_error" class="text-error">{{ state.last_error }}</div>
  </div>
  <span v-else class="text-xs text-muted">not deployed</span>
</template>
