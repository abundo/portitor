<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- What the DHCP client holds on an interface: its address, or its state
     while it has none, and an info button with the lease's details. -->
<script setup>
import { computed } from 'vue'
import DhcpLeaseInfo from '@/components/DhcpLeaseInfo.vue'

const props = defineProps({
  lease: { type: Object, default: null },
  // The interface ignores the router the server offers.
  noDefaultRoute: { type: Boolean, default: false },
})

const bound = computed(() => props.lease?.state === 'bound')
const stateColor = computed(() =>
  bound.value ? 'success' : props.lease?.state === 'error' ? 'error' : 'neutral',
)
</script>

<template>
  <div v-if="lease" class="flex items-center gap-1">
    <span v-if="bound" class="font-mono text-xs">{{
      [lease.address, ...(lease.prefixes ?? []).map((p) => `${p} delegated`)]
        .filter(Boolean)
        .join(', ')
    }}</span>
    <UBadge v-else :color="stateColor" variant="subtle" size="sm" :label="lease.state" />
    <DhcpLeaseInfo :lease="lease" :no-default-route="noDefaultRoute" />
  </div>
</template>
