<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()
const items = computed(() => [
  [
    { label: 'Dashboard', icon: 'i-lucide-gauge', to: '/', exact: true },
    { label: 'Deploy', icon: 'i-lucide-rocket', to: '/deploy' },
  ],
  [
    { label: 'Network', type: 'label' },
    { label: 'Instances', icon: 'i-lucide-boxes', to: '/instances' },
    { label: 'Links', icon: 'i-lucide-cable', to: '/links' },
    { label: 'Interfaces', icon: 'i-lucide-ethernet-port', to: '/interfaces' },
    { label: 'Routes', icon: 'i-lucide-route', to: '/routes' },
    { label: 'IP addresses', icon: 'i-lucide-network', to: '/ipam' },
    { label: 'Hosts & prefixes', icon: 'i-lucide-tags', to: '/objects' },
  ],
  [
    { label: 'Firewall', type: 'label' },
    { label: 'Interface zones', icon: 'i-lucide-layers', to: '/firewall/zones' },
    { label: 'Rules', icon: 'i-lucide-shield-check', to: '/firewall/rules' },
    { label: 'NAT & port forwards', icon: 'i-lucide-arrow-right-left', to: '/firewall/nat' },
    { label: 'IP lists', icon: 'i-lucide-list-x', to: '/firewall/ip-lists' },
  ],
  [
    { label: 'Services', type: 'label' },
    { label: 'DNS zones', icon: 'i-lucide-globe', to: '/dns', exact: true },
    { label: 'DNS templates', icon: 'i-lucide-file-cog', to: '/dns/templates' },
    { label: 'DHCP', icon: 'i-lucide-list-ordered', to: '/dhcp' },
    { label: 'WireGuard', icon: 'i-lucide-key-round', to: '/wireguard' },
    { label: 'Dynamic DNS', icon: 'i-lucide-refresh-ccw-dot', to: '/dyndns' },
    { label: 'Scheduled tasks', icon: 'i-lucide-calendar-clock', to: '/tasks' },
  ],
  [
    { label: 'Admin', type: 'label' },
    { label: 'Console', icon: 'i-lucide-square-terminal', to: '/console' },
    {
      label: 'Settings',
      icon: 'i-lucide-settings',
      defaultOpen: route.path.startsWith('/settings'),
      children: [
        { label: 'General', icon: 'i-lucide-sliders-horizontal', to: '/settings', exact: true },
        { label: 'Users', icon: 'i-lucide-users', to: '/settings/users' },
      ],
    },
  ],
  [{ label: 'Help', icon: 'i-lucide-circle-help', to: '/help' }],
])
</script>

<template>
  <UNavigationMenu :items="items" orientation="vertical" class="w-full" />
</template>
