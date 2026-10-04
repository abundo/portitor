<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '@/api'
import ServiceLog from '@/components/ServiceLog.vue'
import { useInstanceStore } from '@/stores/instances'

// The journals of an instance's services in a popup window (no menu or top
// bar), one tab each, for the instance in ?instance=. Every tab follows its
// log while the window is open, so switching tabs loses nothing. The window
// keeps that instance: it is set in this window's store only.
const route = useRoute()
const store = useInstanceStore()
const loaded = ref(false)
const error = ref('')
const units = ref([])
const tab = ref('')

const items = computed(() => units.value.map((u) => ({ label: u, value: u, slot: 'log' })))

onMounted(async () => {
  await store.load()
  const id = Number(route.query.instance)
  if (store.list.some((i) => i.id === id)) store.currentId = id
  const name = store.current?.name ?? ''
  document.title = `Service logs · ${name} · Portitor`
  try {
    const st = await api.agentStatus()
    const inst = st?.instances?.find((i) => i.name === name)
    units.value = Object.keys(inst?.services ?? {})
    tab.value = units.value[0] ?? ''
  } catch (err) {
    error.value = err.response?.data?.error ?? err.message
  }
  loaded.value = true
})
</script>

<template>
  <div class="flex h-screen flex-col gap-2 bg-default p-3">
    <div v-if="loaded" class="text-sm text-muted">
      Service logs of
      <span class="font-semibold text-highlighted">{{ store.current?.name }}</span>
    </div>
    <UAlert v-if="error" color="error" variant="subtle" :description="error" />
    <div v-else-if="loaded && !units.length" class="text-sm text-muted">
      No service in this virtual firewall.
    </div>
    <UTabs
      v-if="units.length"
      v-model="tab"
      :items="items"
      :unmount-on-hide="false"
      variant="link"
      class="min-h-0 flex-1"
      :ui="{ content: 'flex min-h-0 flex-1 flex-col data-[state=inactive]:hidden' }"
    >
      <template #log="{ item }">
        <ServiceLog
          :instance="store.current.name"
          :unit="item.value"
          :active="tab === item.value"
        />
      </template>
    </UTabs>
  </div>
</template>
