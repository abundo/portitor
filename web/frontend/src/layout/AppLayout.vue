<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import AppMenu from './AppMenu.vue'
import AppTopbar from './AppTopbar.vue'
import AppLogPanel from './AppLogPanel.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import ServiceDialog from '@/components/ServiceDialog.vue'
import { useInstanceStore } from '@/stores/instances'
import { useDeployStore } from '@/stores/deploy'
import { useLogPanel } from '@/composables/useLogPanel'

const instances = useInstanceStore()
const deploy = useDeployStore()
const mobileMenu = ref(false)
// On a wide screen the menu is a sidebar the button hides and shows, and the
// browser remembers which; on a narrow one it is always hidden and the
// button opens it as a slideover.
const MENU_KEY = 'menu.open'
const wide = window.matchMedia('(min-width: 1024px)')
const sidebar = ref(readSidebar())

function readSidebar() {
  try {
    return localStorage.getItem(MENU_KEY) !== 'false'
  } catch {
    return true
  }
}

function toggleMenu() {
  if (!wide.matches) {
    mobileMenu.value = !mobileMenu.value
    return
  }
  sidebar.value = !sidebar.value
  try {
    localStorage.setItem(MENU_KEY, String(sidebar.value))
  } catch {
    // Not remembered; the toggle works without it.
  }
}
const { state: logPanel, note } = useLogPanel()
const route = useRoute()
const toast = useToast()

// Every toast also goes into the log panel's Agent log tab, which keeps it.
const seenToasts = new Set()
watch(
  () => toast.toasts.value.map((t) => t.id),
  () => {
    for (const t of toast.toasts.value) {
      if (seenToasts.has(t.id)) continue
      seenToasts.add(t.id)
      note(t)
    }
  },
  { immediate: true },
)

watch(
  () => route.path,
  () => (mobileMenu.value = false),
)

// The status call imports new physical interfaces of the firewall into
// the default instance; say so once, when it happens.
watch(
  () => deploy.status?.nic_sync,
  (sync) => {
    if (sync?.imported?.length) {
      const def = instances.list.find((i) => i.is_default)?.name ?? 'the default virtual firewall'
      toast.add({
        title: `Found ${sync.imported.join(', ')} on the firewall`,
        description: `Added to ${def} as it is configured now. Review before deploying.`,
        color: 'info',
        actions: [{ label: 'Interfaces', to: '/interfaces' }],
      })
    }
    for (const p of sync?.problems ?? []) toast.add({ title: p, color: 'warning' })
  },
)

onMounted(() => {
  instances.load()
  deploy.refresh()
})
</script>

<template>
  <div class="flex h-screen flex-col overflow-hidden">
    <AppTopbar @toggle-menu="toggleMenu" />
    <div class="flex min-h-0 flex-1">
      <aside
        v-if="sidebar"
        class="hidden w-60 shrink-0 overflow-y-auto border-r border-default p-3 lg:block"
      >
        <AppMenu />
      </aside>
      <main class="min-w-0 flex-1 overflow-auto p-4 md:p-6">
        <router-view :key="instances.currentId ?? 0" />
      </main>
    </div>
    <AppLogPanel v-if="logPanel.open" />
  </div>
  <USlideover v-model:open="mobileMenu" side="left" title="Menu">
    <template #body>
      <AppMenu />
    </template>
  </USlideover>
  <ServiceDialog />
  <ConfirmDialog />
</template>
