// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { _api } from '@iconify/vue'
import ui from '@nuxt/ui/vue-plugin'

import App from './App.vue'
import router from './router'
import { setUnauthorizedHandler } from './api/http'
import { useAuthStore } from './stores/auth'

import '@/assets/tailwind.css'

// Icons are bundled at build time (vite.config.js); never fetch any.
_api.setFetch(async () => new Response('{}', { status: 404 }))

const app = createApp(App)
app.use(createPinia())

// Know who is logged in before the router's first guard runs.
const auth = useAuthStore()
await auth.fetchCurrentUser()
setUnauthorizedHandler(() => {
  auth.user = null
  if (router.currentRoute.value.name !== 'login') router.push({ name: 'login' })
})

app.use(router)
app.use(ui)
app.mount('#app')
