<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- An info button for a DHCP client lease, with a popover with everything
     the server sent. -->
<script setup>
import DhcpLeaseDetails from '@/components/DhcpLeaseDetails.vue'

defineProps({
  lease: { type: Object, required: true },
  // The interface ignores the router the server offers.
  noDefaultRoute: { type: Boolean, default: false },
})
</script>

<template>
  <UPopover :content="{ side: 'bottom', align: 'start' }">
    <UButton
      size="xs"
      color="neutral"
      variant="ghost"
      icon="i-lucide-info"
      aria-label="DHCP lease details"
      @click.stop
    />
    <template #content>
      <div class="max-h-[80vh] max-w-lg overflow-y-auto p-3 text-sm">
        <div class="mb-2 font-semibold">
          {{ lease.family === 'ipv6' ? 'DHCPv6 lease' : 'DHCP lease' }} on
          <span class="font-mono">{{ lease.interface }}</span>
        </div>
        <DhcpLeaseDetails :lease="lease" :no-default-route="noDefaultRoute" />
      </div>
    </template>
  </UPopover>
</template>
