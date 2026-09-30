<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// Recursive rows of the IPAM tree. Edit is the first column; the adds are
// in the page's context menu (menu: a right click on a row), and an entry
// is deleted from its dialog (HostsPrefixesPage).
defineOptions({ name: 'IpamTreeRows' })
defineProps({
  nodes: { type: Array, required: true },
  depth: { type: Number, default: 0 },
  collapsed: { type: Object, required: true },
  ifaceName: { type: Function, required: true },
  // readOnly: a viewer, who views instead of edits.
  readOnly: { type: Boolean, default: false },
  // dnsListen(interfaceId): 'on' when the DNS server listens on the
  // interface, 'off' when it is set to but the server is disabled, else null.
  dnsListen: { type: Function, default: () => null },
})
const emit = defineEmits(['toggle', 'edit', 'menu'])
const key = (n) => `${n.kind}:${n.cidr}`
function pct(n) {
  return Math.round(n.used_frac * 100)
}
</script>

<template>
  <template v-for="n in nodes" :key="key(n)">
    <tr class="border-b border-default hover:bg-elevated/50" @contextmenu="emit('menu', $event, n)">
      <td class="py-1 pr-2 whitespace-nowrap">
        <UButton
          size="xs"
          color="neutral"
          variant="ghost"
          :icon="readOnly ? 'i-lucide-eye' : 'i-lucide-pencil'"
          :aria-label="readOnly ? 'View' : 'Edit'"
          :title="readOnly ? 'View' : 'Edit'"
          @click="emit('edit', n)"
        />
      </td>
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
        <template v-if="n.kind === 'address' && n.interface_id">
          <UBadge
            v-if="dnsListen(n.interface_id) === 'on'"
            color="success"
            variant="subtle"
            label="DNS"
            title="The DNS server listens on this address"
          />
          <UBadge
            v-else-if="dnsListen(n.interface_id) === 'off'"
            color="neutral"
            variant="subtle"
            label="DNS"
            title="Set to listen for DNS, but the instance's DNS server is disabled"
          />
        </template>
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
    </tr>
    <IpamTreeRows
      v-if="n.children.length && !collapsed.has(key(n))"
      :nodes="n.children"
      :depth="depth + 1"
      :collapsed="collapsed"
      :iface-name="ifaceName"
      :read-only="readOnly"
      :dns-listen="dnsListen"
      @toggle="emit('toggle', $event)"
      @edit="emit('edit', $event)"
      @menu="(e, node) => emit('menu', e, node)"
    />
  </template>
</template>
