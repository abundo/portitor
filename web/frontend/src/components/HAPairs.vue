<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// Each HA pair as one: which host is active, whether the standby is ready,
// the configuration on both, and whether the pair can fail over now
// (the agent status's ha_pairs, web/hasummary.go).
import { computed } from 'vue'
import { useDeployStore } from '@/stores/deploy'

const deploy = useDeployStore()
const pairs = computed(() => deploy.status?.ha_pairs || [])

const icon = {
  ok: 'i-lucide-circle-check',
  warn: 'i-lucide-triangle-alert',
  fail: 'i-lucide-circle-x',
}
const tone = { ok: 'text-success', warn: 'text-warning', fail: 'text-error' }
const label = {
  active: 'Active host',
  standby: 'Standby',
  paths: 'Heartbeat paths',
  witness: 'Witness',
  watchdog: 'Watchdog',
  configuration: 'Configuration',
  release: 'Release',
  dhcp: 'DHCP leases',
}
</script>

<template>
  <div v-if="pairs.length" class="space-y-3">
    <UCard v-for="p in pairs" :key="p.name">
      <template #header>
        <div class="flex flex-wrap items-center gap-3">
          <UIcon name="i-lucide-server-cog" class="size-5" />
          <span class="font-semibold">HA pair {{ p.primary }} / {{ p.secondary }}</span>
          <UBadge
            :color="p.active ? 'success' : 'error'"
            variant="subtle"
            :label="p.active ? `${p.active} active` : 'none active'"
          />
          <UBadge
            :color="p.failover_ready ? 'success' : 'error'"
            variant="subtle"
            :label="p.failover_ready ? 'can fail over' : 'cannot fail over'"
          />
        </div>
      </template>
      <table class="text-sm">
        <tbody>
          <tr v-for="c in p.checks" :key="c.name">
            <td class="py-1 pr-2 align-top">
              <UIcon :name="icon[c.status]" :class="['size-4', tone[c.status]]" />
            </td>
            <td class="py-1 pr-4 align-top text-muted whitespace-nowrap">
              {{ label[c.name] || c.name }}
            </td>
            <td class="py-1">{{ c.message }}</td>
          </tr>
        </tbody>
      </table>
    </UCard>
  </div>
</template>
