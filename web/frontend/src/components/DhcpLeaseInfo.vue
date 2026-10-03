<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- An info button for a DHCP client lease, with a popover with everything
     the server sent. -->
<script setup>
import { computed } from 'vue'
import { ago, when } from '@/utils/time'

const props = defineProps({
  lease: { type: Object, required: true },
  // The interface ignores the router the server offers.
  noDefaultRoute: { type: Boolean, default: false },
})

// until renders how far ahead t (an ISO time) is.
function until(t) {
  const s = Math.round((new Date(t).getTime() - Date.now()) / 1000)
  if (s < 0) return 'passed'
  if (s < 120) return `in ${s}s`
  if (s < 7200) return `in ${Math.round(s / 60)}m`
  if (s < 172800) return `in ${Math.round(s / 3600)}h`
  return `in ${Math.round(s / 86400)}d`
}
const isSet = (t) => t && !t.startsWith('0001-')

const rows = computed(() => {
  const l = props.lease
  const r = [['State', l.state]]
  if (l.last_error) r.push(['Last error', l.last_error])
  if (l.address) r.push(['Address', l.address])
  if (l.prefixes?.length) r.push(['Delegated prefix', l.prefixes.join(', ')])
  if (l.router) r.push(['Router', l.router + (props.noDefaultRoute ? ' (ignored)' : '')])
  if (l.dns?.length) r.push(['DNS', l.dns.join(', ')])
  if (l.domain) r.push(['Domain', l.domain])
  if (l.search?.length) r.push(['Search', l.search.join(', ')])
  if (l.ntp?.length) r.push(['NTP', l.ntp.join(', ')])
  if (l.mtu) r.push(['MTU', `${l.mtu} (not applied)`])
  if (l.routes?.length) r.push(['Routes', `${l.routes.join(', ')} (not applied)`])
  if (l.server) r.push(['DHCP server', l.server])
  if (isSet(l.obtained)) r.push(['Obtained', `${when(l.obtained)} (${ago(l.obtained)})`])
  if (isSet(l.renew_after)) r.push(['Renews', `${when(l.renew_after)} (${until(l.renew_after)})`])
  if (isSet(l.rebind_after))
    r.push(['Rebinds', `${when(l.rebind_after)} (${until(l.rebind_after)})`])
  if (isSet(l.expires)) r.push(['Expires', `${when(l.expires)} (${until(l.expires)})`])
  return r
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
      <div class="max-w-lg p-3 text-sm">
        <div class="mb-2 font-semibold">
          {{ lease.family === 'ipv6' ? 'DHCPv6 lease' : 'DHCP lease' }} on
          <span class="font-mono">{{ lease.interface }}</span>
        </div>
        <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5">
          <template v-for="[k, v] in rows" :key="k">
            <dt class="text-muted">{{ k }}</dt>
            <dd class="font-mono text-xs break-all" :class="{ 'text-error': k === 'Last error' }">
              {{ v }}
            </dd>
          </template>
        </dl>
        <details v-if="lease.options?.length" class="mt-2">
          <summary class="cursor-pointer text-muted">
            All options ({{ lease.options.length }})
          </summary>
          <dl class="mt-1 grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5">
            <template v-for="o in lease.options" :key="o.code">
              <dt class="text-muted">{{ o.code }} {{ o.name }}</dt>
              <dd class="font-mono text-xs break-all whitespace-pre-wrap">{{ o.value }}</dd>
            </template>
          </dl>
        </details>
      </div>
    </template>
  </UPopover>
</template>
