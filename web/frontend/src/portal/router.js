// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// The portal's pages, in the URL's hash: the server serves the page at /
// alone, and /fw/<name>/ is the firewalls'.
import { createRouter, createWebHashHistory } from 'vue-router'
import { session, setUnauthorizedHandler } from './api'
import { confirmDiscard } from '@/composables/useFormGuard'
import PortalLayout from './PortalLayout.vue'

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('./PortalLogin.vue') },
    {
      path: '/',
      component: PortalLayout,
      children: [
        { path: '', name: 'firewalls', component: () => import('./FirewallsPage.vue') },
        { path: 'witness', name: 'witness', component: () => import('./WitnessPage.vue') },
      ],
    },
    { path: '/:rest(.*)', redirect: '/' },
  ],
})

router.beforeEach(async (to, from) => {
  if (to.name !== 'login' && !session.user) return { name: 'login' }
  if (to.name === 'login' && session.user) return { name: 'firewalls' }
  if (from.matched.length && to.path !== from.path && !(await confirmDiscard())) return false
})

setUnauthorizedHandler(() => {
  if (router.currentRoute.value.name !== 'login') router.push({ name: 'login' })
})

export default router
