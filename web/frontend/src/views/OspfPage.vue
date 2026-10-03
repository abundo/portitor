<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- OSPF (FRR): OSPFv2 (IPv4) and OSPFv3 (IPv6), each with its state as
     FRR has it (info) and its configuration (config). -->
<script setup>
import { computed, onBeforeUnmount, ref, watch } from 'vue'
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
  { label: 'OSPFv2 info', value: 'v2', slot: 'info2', icon: 'i-lucide-info' },
  { label: 'OSPFv2 config', value: 'v2-config', slot: 'config2', icon: 'i-lucide-settings' },
  { label: 'OSPFv3 info', value: 'v3', slot: 'info3', icon: 'i-lucide-info' },
  { label: 'OSPFv3 config', value: 'v3-config', slot: 'config3', icon: 'i-lucide-settings' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'v2'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'v2' ? undefined : v } }),
})
const infoTab = computed(() => !tab.value.endsWith('-config'))

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
let timer = null
watch(
  infoTab,
  (on) => {
    clearInterval(timer)
    timer = null
    if (on) {
      loadStatus()
      timer = setInterval(loadStatus, 10000)
    }
  },
  { immediate: true },
)
onBeforeUnmount(() => clearInterval(timer))

const mine = computed(() =>
  status.value?.instances?.find((i) => i.instance === store.current?.name),
)
</script>

<template>
  <NeedInstance>
    <!-- The config tabs stay mounted, so their unsaved changes do too. -->
    <UTabs v-model="tab" :items="tabs" :unmount-on-hide="false">
      <template v-for="v in [2, 3]" :key="`info${v}`" #[`info${v}`]>
        <div class="card">
          <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <div class="text-lg font-semibold">OSPFv{{ v }} info</div>
              <p class="max-w-3xl text-sm text-muted">
                The OSPFv{{ v }} neighbours, interfaces, areas and routes of this virtual firewall,
                as FRR has them.
              </p>
            </div>
            <UButton
              icon="i-lucide-refresh-cw"
              color="neutral"
              variant="outline"
              label="Refresh"
              :loading="loading"
              @click="loadStatus"
            />
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
            :state="v === 2 ? mine?.v2 : mine?.v3"
            :version="v"
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
