<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { openConsoleWindow } from '@/composables/useConsoleWindow'

const route = useRoute()
const auth = useAuthStore()
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
    { label: 'Hosts & prefixes', icon: 'i-lucide-tags', to: '/objects' },
  ],
  [
    { label: 'Firewall', type: 'label' },
    { label: 'Interface zones', icon: 'i-lucide-layers', to: '/firewall/zones' },
    { label: 'Rules', icon: 'i-lucide-shield-check', to: '/firewall/rules' },
    { label: 'Services', icon: 'i-lucide-plug', to: '/firewall/services' },
    { label: 'NAT & port forwards', icon: 'i-lucide-arrow-right-left', to: '/firewall/nat' },
  ],
  [
    { label: 'Services', type: 'label' },
    { label: 'DNS', icon: 'i-lucide-globe', to: '/dns' },
    { label: 'DHCP', icon: 'i-lucide-list-ordered', to: '/dhcp' },
    { label: 'WireGuard', icon: 'i-lucide-key-round', to: '/wireguard' },
    { label: 'Dynamic DNS', icon: 'i-lucide-refresh-ccw-dot', to: '/dyndns' },
    { label: 'Scheduled tasks', icon: 'i-lucide-calendar-clock', to: '/tasks' },
  ],
  ...(auth.isAdmin
    ? [
        [
          { label: 'Admin', type: 'label' },
          { label: 'Console', icon: 'i-lucide-square-terminal', to: '/console', slot: 'console' },
          { label: 'Updates', icon: 'i-lucide-package-check', to: '/updates' },
          {
            label: 'Settings',
            icon: 'i-lucide-settings',
            defaultOpen: route.path.startsWith('/settings'),
            children: [
              {
                label: 'General',
                icon: 'i-lucide-sliders-horizontal',
                to: '/settings',
                exact: true,
              },
              { label: 'Users', icon: 'i-lucide-users', to: '/settings/users' },
            ],
          },
        ],
      ]
    : []),
  [{ label: 'Help', icon: 'i-lucide-circle-help', to: '/help' }],
])
</script>

<template>
  <UNavigationMenu :items="items" orientation="vertical" class="w-full">
    <template #console-trailing>
      <UTooltip text="Open console window">
        <UButton
          icon="i-lucide-plus"
          size="xs"
          color="neutral"
          variant="ghost"
          aria-label="Open console window"
          @click.stop.prevent="openConsoleWindow"
        />
      </UTooltip>
    </template>
  </UNavigationMenu>
</template>
