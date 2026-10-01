<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useInstanceStore } from '@/stores/instances'
import CapturePage from '@/views/CapturePage.vue'

// The packet capture alone in a popup window (no menu or top bar), for the
// instance in ?instance=. The window keeps that instance: it is set in this
// window's store only, not saved as the main window's selection.
const route = useRoute()
const store = useInstanceStore()
const loaded = ref(false)

onMounted(async () => {
  await store.load()
  const id = Number(route.query.instance)
  if (store.list.some((i) => i.id === id)) store.currentId = id
  loaded.value = true
  document.title = `Packet capture · ${store.current?.name ?? ''} · Portitor`
})
</script>

<template>
  <div class="flex h-screen flex-col gap-2 bg-default p-3">
    <div v-if="loaded" class="text-sm text-muted">
      Packet capture on
      <span class="font-semibold text-highlighted">{{ store.current?.name }}</span>
    </div>
    <CapturePage v-if="loaded && store.current" in-window class="min-h-0 flex-1" />
  </div>
</template>
