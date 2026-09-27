<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { watch } from 'vue'
import AppMenu from './AppMenu.vue'
import AppTopbar from './AppTopbar.vue'
import ConfirmBanner from '@/components/ConfirmBanner.vue'
import { useInstanceStore } from '@/stores/instances'
import { useDeployStore } from '@/stores/deploy'

const instances = useInstanceStore()
const deploy = useDeployStore()
const mobileMenu = ref(false)
const route = useRoute()

watch(
  () => route.path,
  () => (mobileMenu.value = false),
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
