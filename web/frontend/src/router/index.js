// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createRouter, createWebHistory } from 'vue-router'
import AppLayout from '@/layout/AppLayout.vue'
import { useAuthStore } from '@/stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('@/views/LoginPage.vue'),
      meta: { public: true },
    },
    {
      path: '/',
      component: AppLayout,
      children: [
        { path: '', name: 'dashboard', component: () => import('@/views/DashboardPage.vue') },
        { path: 'instances', component: () => import('@/views/InstancesPage.vue') },
        { path: 'links', component: () => import('@/views/LinksPage.vue') },
        { path: 'interfaces', component: () => import('@/views/InterfacesPage.vue') },
        { path: 'routes', component: () => import('@/views/RoutesPage.vue') },
        { path: 'ipam', component: () => import('@/views/IpamPage.vue') },
        { path: 'objects', component: () => import('@/views/AddressObjectsPage.vue') },
        { path: 'firewall/zones', component: () => import('@/views/InterfaceZonesPage.vue') },
        { path: 'firewall/rules', component: () => import('@/views/RulesPage.vue') },
        { path: 'firewall/nat', component: () => import('@/views/NatPage.vue') },
        { path: 'firewall/ip-lists', component: () => import('@/views/IpListsPage.vue') },
        { path: 'dns', component: () => import('@/views/DnsPage.vue') },
        { path: 'dns/zones/:id', component: () => import('@/views/DnsZoneDetailPage.vue') },
        { path: 'dns/templates', component: () => import('@/views/DnsTemplatesPage.vue') },
        { path: 'dhcp', component: () => import('@/views/DhcpPage.vue') },
        { path: 'wireguard', component: () => import('@/views/WireguardPage.vue') },
        { path: 'dyndns', component: () => import('@/views/DynDnsPage.vue') },
        { path: 'tasks', component: () => import('@/views/TasksPage.vue') },
        { path: 'deploy', component: () => import('@/views/DeployPage.vue') },
        { path: 'console', component: () => import('@/views/ConsolePage.vue') },
        { path: 'updates', component: () => import('@/views/UpdatesPage.vue') },
        { path: 'settings', component: () => import('@/views/SettingsPage.vue') },
        { path: 'settings/users', component: () => import('@/views/UsersPage.vue') },
        { path: 'help/:doc?', component: () => import('@/views/HelpPage.vue') },
        { path: 'profile', component: () => import('@/views/ProfilePage.vue') },
        { path: 'profile/password', component: () => import('@/views/ChangePasswordPage.vue') },
      ],
    },
    { path: '/console/window', component: () => import('@/views/ConsoleWindowPage.vue') },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach((to) => {
  const auth = useAuthStore()
  if (!to.meta.public && !auth.isAuthenticated) {
    return { name: 'login', query: to.fullPath !== '/' ? { next: to.fullPath } : {} }
  }
  if (to.name === 'login' && auth.isAuthenticated) return { name: 'dashboard' }
})

export default router
