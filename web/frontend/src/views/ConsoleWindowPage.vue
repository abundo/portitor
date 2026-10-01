<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useInstanceStore } from '@/stores/instances'
import ConsoleTerminal from '@/components/ConsoleTerminal.vue'

// The console alone in a popup window (no menu or top bar), in the
// namespace of the instance in ?instance=. The window keeps that instance:
// it is set in this window's store only.
const route = useRoute()
const store = useInstanceStore()
const loaded = ref(false)

onMounted(async () => {
  await store.load()
  const id = Number(route.query.instance)
  if (store.list.some((i) => i.id === id)) store.currentId = id
  loaded.value = true
  document.title = `Console · ${store.current?.name ?? ''} · Portitor`
})
</script>

<template>
  <div class="flex h-screen flex-col gap-2 bg-default p-2">
    <div v-if="loaded" class="text-sm text-muted">
      Console in
      <span class="font-semibold text-highlighted">{{ store.current?.name }}</span>
    </div>
    <ConsoleTerminal
      v-if="loaded && store.current"
      :instance="store.current.name"
      class="min-h-0 flex-1"
    />
  </div>
</template>
