<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { setWarningsHandler } from '@/api/http'
import { onMounted, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import AppMenu from './AppMenu.vue'
import AppShell from './AppShell.vue'
import AppTopbar from './AppTopbar.vue'
import AppLogPanel from './AppLogPanel.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import ServiceDialog from '@/components/ServiceDialog.vue'
import { useInstanceStore } from '@/stores/instances'
import { useDeployStore } from '@/stores/deploy'
import { useLogPanel } from '@/composables/useLogPanel'
import { useAuthStore } from '@/stores/auth'
import { api } from '@/api'

const instances = useInstanceStore()
const auth = useAuthStore()
const deploy = useDeployStore()
// The version in the top bar is cosmetic: left out when it can't be read.
const build = ref(null)
onMounted(async () => {
  try {
    build.value = await api.version()
  } catch {
    // leave it out
  }
})
const { state: logPanel, note } = useLogPanel()
const toast = useToast()

// What a save leaves for the commit to refuse (AGENTS.md: messages are
// toasts).
setWarningsHandler((warnings) =>
  toast.add({ title: 'The commit would refuse', description: warnings, color: 'warning' }),
)

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

// Until two-factor login is set up (an admin requires it), the server
// answers only the profile's requests.
function loadAll() {
  instances.load()
  deploy.refresh()
}
onMounted(() => {
  if (!auth.mustSetupTotp) loadAll()
})
watch(
  () => auth.mustSetupTotp,
  (must) => !must && loadAll(),
)
</script>

<template>
  <AppShell :build="build">
    <template #topbar>
      <AppTopbar />
    </template>
    <template #menu>
      <AppMenu />
    </template>
    <router-view :key="instances.currentName ?? 0" />
    <template #bottom>
      <AppLogPanel v-if="logPanel.open" />
    </template>
  </AppShell>
  <ServiceDialog />
  <ConfirmDialog />
</template>
