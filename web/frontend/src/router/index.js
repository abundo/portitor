// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createRouter, createWebHistory } from 'vue-router'
import AppLayout from '@/layout/AppLayout.vue'
import { useAuthStore } from '@/stores/auth'
import { confirmDiscard } from '@/composables/useFormGuard'

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
        { path: 'virtual-firewalls', component: () => import('@/views/InstancesPage.vue') },
        { path: 'links', component: () => import('@/views/LinksPage.vue') },
        { path: 'interfaces', component: () => import('@/views/InterfacesPage.vue') },
        { path: 'neighbours', component: () => import('@/views/NeighboursPage.vue') },
        { path: 'routing', component: () => import('@/views/RoutingPage.vue') },
        { path: 'static-routes', component: () => import('@/views/RoutesPage.vue') },
        { path: 'routing-objects', component: () => import('@/views/RoutingObjectsPage.vue') },
        { path: 'bgp', component: () => import('@/views/BgpPage.vue') },
        { path: 'ospf', component: () => import('@/views/OspfPage.vue') },
        { path: 'vrrp', component: () => import('@/views/VrrpPage.vue') },
        { path: 'bfd', component: () => import('@/views/BfdPage.vue') },
        { path: 'hosts-prefixes', component: () => import('@/views/HostsPrefixesPage.vue') },
        { path: 'interface-zones', component: () => import('@/views/InterfaceZonesPage.vue') },
        { path: 'rules', component: () => import('@/views/RulesPage.vue') },
        { path: 'services', component: () => import('@/views/ServicesPage.vue') },
        { path: 'rate-limits', component: () => import('@/views/RateLimitsPage.vue') },
        { path: 'nat', redirect: '/rules' },
        {
          path: 'connections',
          component: () => import('@/views/ConnectionsPage.vue'),
          meta: { deployer: true },
        },
        { path: 'dns', component: () => import('@/views/DnsPage.vue') },
        { path: 'dns/zones/:id', component: () => import('@/views/DnsZoneDetailPage.vue') },
        { path: 'dns/dynamic/:id', component: () => import('@/views/DnsDynamicZonePage.vue') },
        { path: 'dns-templates', redirect: { path: '/dns', query: { tab: 'templates' } } },
        { path: 'dhcp', component: () => import('@/views/DhcpPage.vue') },
        { path: 'wireguard', component: () => import('@/views/WireguardPage.vue') },
        { path: 'dns-update', redirect: '/dns' },
        { path: 'certificates', component: () => import('@/views/CertificatesPage.vue') },
        { path: 'scheduled-tasks', component: () => import('@/views/TasksPage.vue') },
        { path: 'deploy', component: () => import('@/views/DeployPage.vue') },
        {
          path: 'console',
          component: () => import('@/views/ConsolePage.vue'),
          meta: { admin: true },
        },
        {
          path: 'capture',
          component: () => import('@/views/CapturePage.vue'),
          meta: { deployer: true },
        },
        {
          path: 'traceroute',
          component: () => import('@/views/TracePage.vue'),
          meta: { deployer: true },
        },
        {
          path: 'updates',
          component: () => import('@/views/UpdatesPage.vue'),
          meta: { admin: true },
        },
        {
          path: 'settings',
          component: () => import('@/views/SettingsPage.vue'),
          meta: { admin: true },
        },
        {
          path: 'users',
          component: () => import('@/views/UsersPage.vue'),
          meta: { admin: true },
        },
        {
          path: 'roles',
          component: () => import('@/views/RolesPage.vue'),
          meta: { admin: true },
        },
        { path: 'help/:doc?', component: () => import('@/views/HelpPage.vue') },
        { path: 'profile', component: () => import('@/views/ProfilePage.vue') },
        { path: 'profile/password', component: () => import('@/views/ChangePasswordPage.vue') },
      ],
    },
    {
      path: '/console/window',
      component: () => import('@/views/ConsoleWindowPage.vue'),
      meta: { admin: true },
    },
    {
      path: '/capture/window',
      component: () => import('@/views/CaptureWindowPage.vue'),
      meta: { deployer: true },
    },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach((to) => {
  const auth = useAuthStore()
  if (!to.meta.public && !auth.isAuthenticated) {
    return { name: 'login', query: to.fullPath !== '/' ? { next: to.fullPath } : {} }
  }
  if (to.name === 'login' && auth.isAuthenticated) return { name: 'dashboard' }
  if (to.matched.some((r) => r.meta.admin) && !auth.isAdmin) return { name: 'dashboard' }
  // An instance admin captures on their instances.
  if (to.matched.some((r) => r.meta.deployer) && !auth.canDeploy) return { name: 'dashboard' }
})

// Leaving a page with unsaved changes asks first; a query change keeps the
// page, and the login page comes after a logout or an expired session.
router.beforeEach(async (to, from) => {
  if (to.name === 'login' || to.path === from.path) return
  if (!(await confirmDiscard())) return false
})

export default router
