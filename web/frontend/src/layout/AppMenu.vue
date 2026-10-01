<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { openConsoleWindow } from '@/composables/useConsoleWindow'
import { useInstanceStore } from '@/stores/instances'

const route = useRoute()
const auth = useAuthStore()
const instances = useInstanceStore()
// Each section is a collapsible item. Opening one closes the others; the
// section of the current page is opened when the route changes.
const tools = computed(() => [
  ...(auth.isAdmin
    ? [{ label: 'Console', icon: 'i-lucide-square-terminal', to: '/console', slot: 'console' }]
    : []),
  ...(auth.canDeploy
    ? [{ label: 'Packet capture', icon: 'i-lucide-radio-tower', to: '/capture' }]
    : []),
])
const sections = computed(() => [
  {
    label: 'Globals',
    value: 'globals',
    children: [
      { label: 'Instances', icon: 'i-lucide-boxes', to: '/instances' },
      { label: 'Links', icon: 'i-lucide-cable', to: '/links' },
      { label: 'DNS templates', icon: 'i-lucide-file-cog', to: '/dns-templates' },
    ],
  },
  {
    label: 'Network',
    value: 'network',
    children: [
      { label: 'Interfaces', icon: 'i-lucide-ethernet-port', to: '/interfaces' },
      { label: 'Interface zones', icon: 'i-lucide-layers', to: '/interface-zones' },
      { label: 'Routes', icon: 'i-lucide-route', to: '/routes' },
      { label: 'Hosts & prefixes', icon: 'i-lucide-tags', to: '/objects' },
    ],
  },
  {
    label: 'Firewall',
    value: 'firewall',
    children: [
      { label: 'Rules', icon: 'i-lucide-shield-check', to: '/firewall/rules' },
      { label: 'Services', icon: 'i-lucide-plug', to: '/firewall/services' },
      { label: 'NAT & port forwards', icon: 'i-lucide-arrow-right-left', to: '/firewall/nat' },
    ],
  },
  {
    label: 'Services',
    value: 'services',
    children: [
      { label: 'DNS', icon: 'i-lucide-globe', to: '/dns' },
      { label: 'DHCP', icon: 'i-lucide-list-ordered', to: '/dhcp' },
      { label: 'Dynamic DNS', icon: 'i-lucide-refresh-ccw-dot', to: '/dyndns' },
      { label: 'Scheduled tasks', icon: 'i-lucide-calendar-clock', to: '/tasks' },
    ],
  },
  {
    label: 'VPN',
    value: 'vpn',
    children: [{ label: 'WireGuard', icon: 'i-lucide-key-round', to: '/wireguard' }],
  },
  ...(tools.value.length ? [{ label: 'Tools', value: 'tools', children: tools.value }] : []),
  ...(auth.isAdmin
    ? [
        {
          label: 'Admin',
          value: 'admin',
          children: [
            { label: 'Updates', icon: 'i-lucide-package-check', to: '/updates' },
            { label: 'Settings', icon: 'i-lucide-settings', to: '/settings', exact: true },
            { label: 'Users', icon: 'i-lucide-users', to: '/settings/users' },
            { label: 'Roles', icon: 'i-lucide-shield-user', to: '/settings/roles' },
          ],
        },
      ]
    : []),
])

const items = computed(() => [
  [
    { label: 'Dashboard', icon: 'i-lucide-gauge', to: '/', exact: true },
    { label: 'Deploy', icon: 'i-lucide-rocket', to: '/deploy' },
  ],
  sections.value,
  [{ label: 'Help', icon: 'i-lucide-circle-help', to: '/help' }],
])

const open = ref(['network', 'firewall', 'services'])

function onOpen(value) {
  const next = Array.isArray(value) ? value : []
  const added = next.filter((v) => !open.value.includes(v))
  open.value = added.length ? added : next
}

function sectionOf(path) {
  return sections.value.find((s) =>
    s.children.some((c) =>
      c.exact ? path === c.to : path === c.to || path.startsWith(c.to + '/'),
    ),
  )?.value
}

watch(
  () => route.path,
  (path) => {
    const s = sectionOf(path)
    if (s && !open.value.includes(s)) open.value = [s]
  },
  { immediate: true },
)
</script>

<template>
  <UNavigationMenu
    :items="items"
    :model-value="open"
    type="multiple"
    orientation="vertical"
    class="w-full"
    @update:model-value="onOpen"
  >
    <template #console-trailing>
      <UTooltip text="Open console window">
        <UButton
          icon="i-lucide-plus"
          size="xs"
          color="neutral"
          variant="ghost"
          aria-label="Open console window"
          @click.stop.prevent="openConsoleWindow(instances.currentId)"
        />
      </UTooltip>
    </template>
  </UNavigationMenu>
</template>
