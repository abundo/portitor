<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import AppMenu from './AppMenu.vue'
import AppTopbar from './AppTopbar.vue'
import ConfirmBanner from '@/components/ConfirmBanner.vue'
import { useInstanceStore } from '@/stores/instances'
import { useDeployStore } from '@/stores/deploy'

const instances = useInstanceStore()
const deploy = useDeployStore()
const mobileMenu = ref(false)
const route = useRoute()
const toast = useToast()

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
      const def = instances.list.find((i) => i.is_default)?.name ?? 'the default instance'
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
    <AppTopbar @toggle-menu="mobileMenu = !mobileMenu" />
    <ConfirmBanner />
    <div class="flex min-h-0 flex-1">
      <aside class="hidden w-60 shrink-0 overflow-y-auto border-r border-default p-3 lg:block">
        <AppMenu />
      </aside>
      <main class="min-w-0 flex-1 overflow-auto p-4 md:p-6">
        <router-view :key="instances.currentId ?? 0" />
      </main>
    </div>
  </div>
  <USlideover v-model:open="mobileMenu" side="left" title="Menu">
    <template #body>
      <AppMenu />
    </template>
  </USlideover>
</template>
