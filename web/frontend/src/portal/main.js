// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// portitor-web's own GUI (portal.html): its firewalls, HA firewalls and
// witness, in the firewall GUI's look (the same Nuxt UI, AppShell, DataGrid
// and dialogs). A firewall's GUI is its portitor-config's, served by the
// portal at /fw/<name>/ and opened as a page of its own.
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { _api } from '@iconify/vue'
import ui from '@nuxt/ui/vue-plugin'

import PortalApp from './PortalApp.vue'
import router from './router'
import { portal } from './api'

import '@/assets/tailwind.css'

// Icons are bundled at build time (vite.config.js); never fetch any.
_api.setFetch(async () => new Response('{}', { status: 404 }))

// Dark mode unless the user has chosen otherwise, as in the firewall GUI.
try {
  if (localStorage.getItem('vueuse-color-scheme') === null)
    localStorage.setItem('vueuse-color-scheme', 'dark')
} catch {
  // no storage: follow the system
}

await portal.session()
const app = createApp(PortalApp)
app.use(createPinia())
app.use(router)
app.use(ui)
app.mount('#app')
