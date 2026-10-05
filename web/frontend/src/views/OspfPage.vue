<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- OSPF (FRR): the state of OSPFv2 (IPv4) and OSPFv3 (IPv6) as FRR has it
     (info), and each version's configuration (config). -->
<script setup>
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import NeedInstance from '@/components/NeedInstance.vue'
import OspfConfig from '@/components/OspfConfig.vue'
import OspfInfo from '@/components/OspfInfo.vue'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceStore } from '@/stores/instances'

const route = useRoute()
const router = useRouter()
const store = useInstanceStore()

const tabs = [
  { label: 'OSPF info', value: 'info', slot: 'info', icon: 'i-lucide-info' },
  { label: 'OSPFv2 config', value: 'v2-config', slot: 'config2', icon: 'i-lucide-settings' },
  { label: 'OSPFv3 config', value: 'v3-config', slot: 'config3', icon: 'i-lucide-settings' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'info'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'info' ? undefined : v } }),
})
const infoTab = computed(() => tab.value === 'info')

// ----- Info: loaded, and refreshed every 10 s, while an info tab is open.
const status = ref(null)
const statusError = ref('')
const loading = ref(false)
async function loadStatus() {
  loading.value = true
  try {
    status.value = await api.agentOspf()
    statusError.value = ''
  } catch (err) {
    statusError.value = errMsg(err)
  } finally {
    loading.value = false
  }
}
const auto = useAutoRefresh(loadStatus, { seconds: 10, active: () => infoTab.value })

const mine = computed(() =>
  status.value?.instances?.find((i) => i.instance === store.current?.name),
)
</script>

<template>
  <NeedInstance>
    <!-- The config tabs stay mounted, so their unsaved changes do too. -->
    <UTabs v-model="tab" :items="tabs" :unmount-on-hide="false">
      <template #info>
        <div class="card">
          <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <div class="text-lg font-semibold">OSPF info</div>
              <p class="max-w-3xl text-sm text-muted">
                The OSPFv2 and OSPFv3 router ids, neighbours, interfaces, areas and routes of this
                virtual firewall, as FRR has them.
              </p>
            </div>
            <AutoRefreshButton :auto="auto" :loading="loading" />
          </div>
          <UAlert
            v-if="statusError"
            class="mb-2"
            color="error"
            variant="subtle"
            :title="statusError"
          />
          <OspfInfo
            v-else
            :v2="mine?.v2"
            :v3="mine?.v3"
            :loaded="!!status"
            :loading="loading && !status"
          />
        </div>
      </template>
      <template #config2><OspfConfig :version="2" /></template>
      <template #config3><OspfConfig :version="3" /></template>
    </UTabs>
  </NeedInstance>
</template>
