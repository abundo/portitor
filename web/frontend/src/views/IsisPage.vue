<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- IS-IS (FRR): its state as FRR has it (info), and its configuration
     (config), of the main table or a VRF, chosen at the top. -->
<script setup>
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import NeedInstance from '@/components/NeedInstance.vue'
import IsisConfig from '@/components/IsisConfig.vue'
import IsisInfo from '@/components/IsisInfo.vue'
import VrfSelect from '@/components/VrfSelect.vue'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceStore } from '@/stores/instances'
import { useVrfChoice } from '@/composables/useVrfChoice'

const route = useRoute()
const router = useRouter()
const store = useInstanceStore()
const { vrf, vrfItems, vrfName } = useVrfChoice()

const tabs = [
  { label: 'IS-IS info', value: 'info', slot: 'info', icon: 'i-lucide-info' },
  { label: 'IS-IS config', value: 'config', slot: 'config', icon: 'i-lucide-settings' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'info'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'info' ? undefined : v } }),
})

// ----- Info: loaded, and refreshed every 10 s, while the info tab is open.
const status = ref(null)
const statusError = ref('')
const loading = ref(false)
async function loadStatus() {
  loading.value = true
  try {
    status.value = await api.agentIsis()
    statusError.value = ''
  } catch (err) {
    statusError.value = errMsg(err)
  } finally {
    loading.value = false
  }
}
const auto = useAutoRefresh(loadStatus, { seconds: 10, active: () => tab.value === 'info' })

const mine = computed(() =>
  status.value?.instances?.find(
    (i) => i.instance === store.current?.name && (i.vrf ?? '') === vrfName.value,
  ),
)
</script>

<template>
  <NeedInstance>
    <div class="mb-2"><VrfSelect v-model="vrf" :items="vrfItems" /></div>
    <!-- The config tab stays mounted, so its unsaved changes do too. -->
    <UTabs v-model="tab" :items="tabs" :unmount-on-hide="false">
      <template #info>
        <div class="card">
          <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
            <div>
              <div class="text-lg font-semibold">IS-IS info</div>
              <p class="max-w-3xl text-sm text-muted">
                The IS-IS system id, adjacencies, interfaces and routes of this virtual firewall{{
                  vrfName ? ` in VRF ${vrfName}` : ''
                }}.
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
          <IsisInfo v-else :state="mine" :loaded="!!status" :loading="loading && !status" />
        </div>
      </template>
      <!-- Keyed by the VRF: another VRF's IS-IS is another form. -->
      <template #config><IsisConfig :key="vrf" /></template>
    </UTabs>
  </NeedInstance>
</template>
