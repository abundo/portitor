<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { useInstanceStore } from '@/stores/instances'
const store = useInstanceStore()
</script>

<template>
  <slot v-if="store.currentId" />
  <div v-else class="card">
    <UAlert
      icon="i-lucide-boxes"
      title="No virtual firewall yet"
      description="Everything (interfaces, interface zones, rules, DNS, DHCP) belongs to a virtual firewall. Create the default virtual firewall first."
      :actions="[{ label: 'Create virtual firewall', to: '/virtual-firewalls' }]"
    />
  </div>
</template>
