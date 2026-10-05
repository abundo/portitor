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
  ...(auth.canDeploy
    ? [{ label: 'Traceroute', icon: 'i-lucide-waypoints', to: '/traceroute' }]
    : []),
  ...(auth.isAdmin
    ? [{ label: 'Console', icon: 'i-lucide-square-terminal', to: '/console', slot: 'console' }]
    : []),
  ...(auth.canDeploy
    ? [{ label: 'Packet capture', icon: 'i-lucide-radio-tower', to: '/capture' }]
    : []),
])
const sections = computed(() => [
  ...(auth.user?.virtual_firewalls
    ? [
        {
          label: 'Globals',
          value: 'globals',
          children: [
            { label: 'Virtual firewalls', icon: 'i-lucide-boxes', to: '/virtual-firewalls' },
            { label: 'Links', icon: 'i-lucide-cable', to: '/links' },
          ],
        },
      ]
    : []),
  {
    label: 'Network',
    value: 'network',
    children: [
      { label: 'Interfaces', icon: 'i-lucide-ethernet-port', to: '/interfaces' },
      { label: 'Interface zones', icon: 'i-lucide-layers', to: '/interface-zones' },
      { label: 'Neighbours', icon: 'i-lucide-network', to: '/neighbours' },
      { label: 'Hosts & prefixes', icon: 'i-lucide-tags', to: '/hosts-prefixes' },
      { label: 'NAT64', icon: 'i-lucide-arrow-left-right', to: '/nat64' },
      { label: 'Tunnels', icon: 'i-lucide-train-front-tunnel', to: '/tunnels' },
    ],
  },
  {
    label: 'Routing',
    value: 'routing',
    children: [
      { label: 'Routing', icon: 'i-lucide-table', to: '/routing' },
      { label: 'Routing objects', icon: 'i-lucide-list-filter', to: '/routing-objects' },
      { label: 'Static', icon: 'i-lucide-signpost', to: '/static-routes' },
      { label: 'BFD', icon: 'i-lucide-heart-pulse', to: '/bfd' },
      { label: 'VRRP', icon: 'i-lucide-git-fork', to: '/vrrp' },
      { label: 'OSPF', icon: 'i-lucide-waypoints', to: '/ospf' },
      { label: 'BGP', icon: 'i-lucide-share-2', to: '/bgp' },
    ],
  },
  {
    label: 'Firewall',
    value: 'firewall',
    children: [
      { label: 'Rules', icon: 'i-lucide-shield-check', to: '/rules' },
      { label: 'Services', icon: 'i-lucide-plug', to: '/services' },
      { label: 'Rate limits', icon: 'i-lucide-gauge', to: '/rate-limits' },
      ...(auth.canDeploy
        ? [{ label: 'Connections', icon: 'i-lucide-activity', to: '/connections' }]
        : []),
    ],
  },
  {
    label: 'Services',
    value: 'services',
    children: [
      { label: 'Certificates', icon: 'i-lucide-badge-check', to: '/certificates' },
      { label: 'DHCP', icon: 'i-lucide-list-ordered', to: '/dhcp' },
      { label: 'DNS', icon: 'i-lucide-globe', to: '/dns' },
      { label: 'NTP', icon: 'i-lucide-clock', to: '/ntp' },
      { label: 'SNMP', icon: 'i-lucide-activity', to: '/snmp' },
      { label: 'Scheduled tasks', icon: 'i-lucide-calendar-clock', to: '/scheduled-tasks' },
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
            { label: 'Settings', icon: 'i-lucide-settings', to: '/settings', exact: true },
            { label: 'Updates', icon: 'i-lucide-package-check', to: '/updates' },
            { label: 'Backup & restore', icon: 'i-lucide-archive', to: '/backup' },
            { label: 'Users', icon: 'i-lucide-users', to: '/users' },
            { label: 'Roles', icon: 'i-lucide-shield-user', to: '/roles' },
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

const open = ref([])

function onOpen(value) {
  const next = Array.isArray(value) ? value : []
  const added = next.filter((v) => !open.value.includes(v))
  open.value = added.length ? added : next
}

// matches reports whether a menu item is the page
// at path.
function matches(item, path) {
  return item.exact ? path === item.to : path === item.to || path.startsWith(item.to + '/')
}

function sectionOf(path) {
  return sections.value.find((s) => s.children.some((c) => matches(c, path)))?.value
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
