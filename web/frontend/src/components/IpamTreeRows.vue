<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// Recursive rows of the IPAM tree. An `auto` node is there only because an
// interface has the address: it has no IPAM entry to delete (id 0).
defineOptions({ name: 'IpamTreeRows' })
defineProps({
  nodes: { type: Array, required: true },
  depth: { type: Number, default: 0 },
  collapsed: { type: Object, required: true },
  ifaceName: { type: Function, required: true },
  // readOnly leaves out the add and delete buttons (a viewer).
  readOnly: { type: Boolean, default: false },
})
const emit = defineEmits(['toggle', 'add-prefix', 'add-address', 'edit', 'remove'])
const key = (n) => `${n.kind}:${n.cidr}`
function pct(n) {
  return Math.round(n.used_frac * 100)
}
</script>

<template>
  <template v-for="n in nodes" :key="key(n)">
    <tr class="border-b border-default hover:bg-elevated/50">
      <td class="py-1.5 pr-2">
        <div class="flex items-center gap-1" :style="{ paddingLeft: `${depth * 1.25}rem` }">
          <UButton
            v-if="n.children.length"
            size="xs"
            color="neutral"
            variant="ghost"
            :icon="collapsed.has(key(n)) ? 'i-lucide-chevron-right' : 'i-lucide-chevron-down'"
            @click="emit('toggle', key(n))"
          />
          <span v-else class="inline-block w-6" />
          <UIcon
            :name="n.kind === 'prefix' ? 'i-lucide-network' : 'i-lucide-dot'"
            :class="n.kind === 'prefix' ? 'text-primary' : 'text-muted'"
          />
          <span class="font-mono" :class="n.kind === 'prefix' ? 'font-semibold' : ''">{{
            n.cidr
          }}</span>
        </div>
      </td>
      <td class="px-2 text-sm">
        {{ n.description }}
        <span v-if="n.dns_name" class="font-mono text-xs text-muted">{{ n.dns_name }}</span>
        <span v-if="n.auto && !n.description && !n.dns_name" class="text-xs text-muted">{{
          n.kind === 'prefix' ? 'from an interface address' : 'interface address'
        }}</span>
      </td>
      <td class="px-2 text-xs">
        <UBadge
          v-if="n.interface_id"
          color="primary"
          variant="subtle"
          :label="ifaceName(n.interface_id)"
        />
        <UBadge v-if="n.mac" color="neutral" variant="outline" :label="`reserved ${n.mac}`" />
        <UBadge v-if="n.ra_enabled" color="info" variant="subtle" label="RA" />
        <UBadge
          v-if="n.dhcp_enabled"
          color="info"
          variant="subtle"
          :label="`${n.cidr.includes(':') ? 'DHCPv6' : 'DHCP'} ${n.dhcp_range || ''}`"
        />
      </td>
      <td class="w-32 px-2">
        <div v-if="n.kind === 'prefix'" class="flex items-center gap-2">
          <UProgress :model-value="pct(n)" size="xs" class="w-16" />
          <span class="text-xs text-muted tabular-nums">{{ pct(n) }}%</span>
        </div>
      </td>
      <td class="py-1 text-right whitespace-nowrap">
        <template v-if="n.kind === 'prefix' && !readOnly">
          <UButton
            size="xs"
            color="neutral"
            variant="ghost"
            icon="i-lucide-plus"
            title="Add address"
            @click="emit('add-address', n)"
          />
          <UButton
            size="xs"
            color="neutral"
            variant="ghost"
            icon="i-lucide-git-branch-plus"
            title="Add sub-prefix"
            @click="emit('add-prefix', n)"
          />
        </template>
        <UButton
          size="xs"
          color="neutral"
          variant="ghost"
          :icon="readOnly ? 'i-lucide-eye' : 'i-lucide-pencil'"
          @click="emit('edit', n)"
        />
        <UButton
          v-if="!readOnly && !n.auto"
          size="xs"
          color="error"
          variant="ghost"
          icon="i-lucide-trash"
          @click="emit('remove', n)"
        />
        <span v-else-if="!readOnly" class="inline-block w-6" />
      </td>
    </tr>
    <IpamTreeRows
      v-if="n.children.length && !collapsed.has(key(n))"
      :nodes="n.children"
      :depth="depth + 1"
      :collapsed="collapsed"
      :iface-name="ifaceName"
      :read-only="readOnly"
      @toggle="emit('toggle', $event)"
      @add-prefix="emit('add-prefix', $event)"
      @add-address="emit('add-address', $event)"
      @edit="emit('edit', $event)"
      @remove="emit('remove', $event)"
    />
  </template>
</template>
