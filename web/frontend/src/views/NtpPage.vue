<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- NTP (chrony): its sources and statistics as chronyd has them (Info),
     and its servers and who it answers (Configuration). -->
<script setup>
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import AddrInput from '@/components/AddrInput.vue'
import EntriesEditor from '@/components/EntriesEditor.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import { api, instances, interfaces } from '@/api'
import { errMsg } from '@/api/http'
import { withLabel } from '@/composables/useInstanceRefs'
import { usePageForm } from '@/composables/useFormGuard'
import { useAuthStore } from '@/stores/auth'
import { useInstanceStore } from '@/stores/instances'
import { inlineField } from '@/utils/form'
import { useSearch, valuesText } from '@/utils/search'

const toast = useToast()
const auth = useAuthStore()
const store = useInstanceStore()
const readOnly = computed(() => !auth.canEdit)
const route = useRoute()
const router = useRouter()

const tabs = [
  { label: 'Info', value: 'info', slot: 'info', icon: 'i-lucide-info' },
  { label: 'Configuration', value: 'config', slot: 'config', icon: 'i-lucide-settings' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'info'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'info' ? undefined : v } }),
})

// ----- Info: loaded, and refreshed every 5 s, while its tab is open.
const status = ref(null)
const statusError = ref('')
const loading = ref(false)
async function loadStatus() {
  loading.value = true
  try {
    status.value = await api.agentNtp()
    statusError.value = ''
  } catch (err) {
    statusError.value = errMsg(err)
  } finally {
    loading.value = false
  }
}
const auto = useAutoRefresh(loadStatus, { seconds: 5, active: () => tab.value === 'info' })

const mine = computed(() =>
  status.value?.instances?.find((i) => i.instance === store.current?.name),
)
const sources = computed(() => mine.value?.sources ?? [])
const info = useSearch(sources, (s) => valuesText(s.name, s.address, s.mode, s.state, s.auth))
const stateColor = (s) =>
  s === 'selected'
    ? 'success'
    : s === 'combined'
      ? 'info'
      : s === 'falseticker' || s === 'unusable'
        ? 'error'
        : 'warning'
// seconds as µs or ms, the way chronyc shows offsets.
function secs(v) {
  const a = Math.abs(v)
  if (a < 0.001) return `${(v * 1e6).toFixed(0)} µs`
  if (a < 1) return `${(v * 1e3).toFixed(3)} ms`
  return `${v.toFixed(3)} s`
}
function ago(s) {
  if (s == null || s < 0) return ''
  if (s < 120) return `${s} s`
  if (s < 7200) return `${Math.round(s / 60)} m`
  if (s < 172800) return `${Math.round(s / 3600)} h`
  return `${Math.round(s / 86400)} d`
}
const reachBits = (r) => (r ?? 0).toString(2).padStart(8, '0')
const sourceColumns = [
  { accessorKey: 'address', header: 'Source' },
  { id: 'state', header: 'State' },
  { accessorKey: 'stratum', header: 'Stratum' },
  { id: 'poll', header: 'Poll' },
  { id: 'reach', header: 'Reach' },
  { id: 'last_rx', header: 'Last sample' },
  { id: 'offset', header: 'Offset' },
  { id: 'error', header: '± error' },
  { id: 'std_dev', header: 'Std dev' },
  { id: 'frequency', header: 'Freq (ppm)' },
  { accessorKey: 'samples', header: 'Samples' },
  { id: 'auth', header: 'Auth' },
]

// The instance's ntp_* fields, and its interfaces' ntp_serve.
const form = reactive({
  ntp_enabled: false,
  ntp_servers: [],
  ntp_allow: [],
  ifaces: [], // { id, name, label, description, ntp_serve }
})
const pageForm = usePageForm(form)
const saving = ref(false)
let loaded = [] // the interfaces as loaded, to save only what changed

const serverColumns = [
  { key: 'address', label: 'Server', placeholder: 'time.cloudflare.com', class: 'min-w-56' },
  { key: 'pool', label: 'Pool', type: 'switch' },
  { key: 'iburst', label: 'iburst', type: 'switch' },
  { key: 'nts', label: 'NTS', type: 'switch' },
]

async function load() {
  const id = store.currentId
  if (!id) return
  const [inst, ifs] = await Promise.all([instances.get(id), interfaces.list({ instance_id: id })])
  loaded = ifs
  Object.assign(form, {
    ntp_enabled: inst.ntp_enabled ?? false,
    ntp_servers: (inst.ntp_servers ?? []).map((s) => ({
      address: s.address,
      pool: !!s.pool,
      iburst: !!s.iburst,
      nts: !!s.nts,
    })),
    ntp_allow: inst.ntp_allow ?? [],
    ifaces: ifs.map((i) => ({
      id: i.id,
      name: i.name,
      label: i.label,
      description: i.description,
      ntp_serve: i.ntp_serve ?? false,
    })),
  })
  pageForm.mark()
}
watch(() => store.currentId, load, { immediate: true })

const { search: ifaceSearch, filtered: shownIfaces } = useSearch(
  () => form.ifaces,
  (i) => `${withLabel(i.label, i.name)} ${i.description}`,
)

async function save() {
  saving.value = true
  try {
    const { ifaces, ...ntp } = form
    await instances.update(store.currentId, ntp)
    for (const i of ifaces) {
      const o = loaded.find((x) => x.id === i.id)
      if (o && !!o.ntp_serve !== i.ntp_serve)
        await interfaces.update(i.id, { ntp_serve: i.ntp_serve })
    }
    toast.add({ title: 'NTP saved', color: 'success' })
    await Promise.all([load(), store.load()])
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <NeedInstance>
    <UTabs v-model="tab" :items="tabs" :unmount-on-hide="false">
      <template #info>
        <div class="space-y-4 pt-2">
          <div class="card">
            <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <div class="text-lg font-semibold">NTP sources</div>
                <p class="max-w-3xl text-sm text-muted">
                  The time sources of this virtual firewall as chrony has them. Reach shows the last
                  8 polls (1: answered).
                </p>
              </div>
              <AutoRefreshButton :auto="auto" :loading="loading" />
            </div>
            <UAlert
              v-if="statusError || mine?.error"
              class="mb-2"
              color="error"
              variant="subtle"
              :title="statusError || mine.error"
            />
            <SearchInput v-model="info.search.value" class="mb-2" />
            <UTable
              :data="info.filtered.value"
              :columns="sourceColumns"
              :loading="loading && !status"
            >
              <template #address-cell="{ row }">
                <div v-if="row.original.name">{{ row.original.name }}</div>
                <span class="font-mono text-xs" :class="{ 'text-muted': row.original.name }">{{
                  row.original.address
                }}</span>
              </template>
              <template #state-cell="{ row }">
                <UBadge
                  :color="stateColor(row.original.state)"
                  variant="subtle"
                  :label="row.original.state"
                />
              </template>
              <template #poll-cell="{ row }">{{ row.original.poll }} s</template>
              <template #reach-cell="{ row }">
                <span class="font-mono text-xs">{{ reachBits(row.original.reach) }}</span>
              </template>
              <template #last_rx-cell="{ row }">{{ ago(row.original.last_rx) }}</template>
              <template #offset-cell="{ row }">{{ secs(row.original.offset) }}</template>
              <template #error-cell="{ row }">{{ secs(row.original.error) }}</template>
              <template #std_dev-cell="{ row }">{{ secs(row.original.std_dev) }}</template>
              <template #frequency-cell="{ row }">
                {{ row.original.frequency.toFixed(3) }} ±
                {{ row.original.freq_skew.toFixed(3) }}
              </template>
              <template #auth-cell="{ row }">
                <UBadge
                  v-if="row.original.auth"
                  color="success"
                  variant="outline"
                  :label="row.original.auth"
                />
              </template>
              <template #empty>
                <div class="py-4 text-center text-muted">
                  {{
                    !status
                      ? ''
                      : mine
                        ? 'No sources.'
                        : 'NTP is not running in this virtual firewall (turn it on under Configuration, then commit).'
                  }}
                </div>
              </template>
            </UTable>
          </div>

          <div v-if="mine && !mine.error" class="grid gap-4 lg:grid-cols-2">
            <div
              v-for="t in [
                { title: 'Tracking', rows: mine.tracking },
                { title: 'Server statistics', rows: mine.server_stats },
              ]"
              :key="t.title"
              class="card"
            >
              <div class="mb-2 text-lg font-semibold">{{ t.title }}</div>
              <table class="w-full text-sm">
                <tbody>
                  <tr
                    v-for="f in t.rows"
                    :key="f.name"
                    class="border-b border-default last:border-0"
                  >
                    <td class="py-1 pr-4 text-muted">{{ f.name }}</td>
                    <td class="py-1 font-mono text-xs">{{ f.value }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </template>

      <template #config>
        <div class="card mt-2">
          <form @submit.prevent="save">
            <h2 class="border-b border-default pb-1 mb-2 text-xl font-semibold">NTP</h2>
            <p class="mb-4 text-sm text-muted">
              chrony keeps the time from the servers below. On the default virtual firewall it sets
              the firewall's clock; on another it serves the time to its clients without setting the
              clock.
            </p>
            <fieldset :disabled="readOnly" class="space-y-3">
              <UFormField label="Enabled" :ui="inlineField">
                <USwitch v-model="form.ntp_enabled" />
              </UFormField>
              <UFormField
                label="Servers"
                help="Pool: a name that resolves to several servers (pool.ntp.org). iburst: sync faster at start. NTS: authenticated time (Network Time Security), from a server that supports it."
                :ui="inlineField"
              >
                <EntriesEditor
                  v-model="form.ntp_servers"
                  :columns="serverColumns"
                  :new-entry="() => ({ address: '', pool: false, iburst: true, nts: false })"
                  :disabled="readOnly"
                  add-label="Add server"
                  empty="No servers."
                />
              </UFormField>
            </fieldset>

            <h2 class="border-b border-default pb-1 mt-8 mb-2 text-xl font-semibold">NTP server</h2>
            <p class="mb-4 text-sm text-muted">
              The firewall answers NTP clients on the interfaces turned on here, and of those only
              the allowed clients.
            </p>
            <!-- Outside the form's fieldset, so a viewer can search too. -->
            <div class="mb-2">
              <SearchInput v-model="ifaceSearch" />
            </div>
            <fieldset :disabled="readOnly" class="min-w-0 overflow-x-auto">
              <table class="w-full text-sm">
                <thead>
                  <tr class="border-b border-default text-left text-xs text-muted">
                    <th class="py-1 pr-4 font-medium">Interface</th>
                    <th class="pr-4 font-medium">Description</th>
                    <th class="pr-4 font-medium">Answer NTP clients</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="i in shownIfaces"
                    :key="i.id"
                    class="border-b border-default last:border-0"
                  >
                    <td class="py-1 pr-4 font-mono">{{ withLabel(i.label, i.name) }}</td>
                    <td class="py-1 pr-4">{{ i.description }}</td>
                    <td class="py-1 pr-4">
                      <USwitch
                        v-model="i.ntp_serve"
                        :aria-label="`Answer NTP clients on ${i.name}`"
                      />
                    </td>
                  </tr>
                  <tr v-if="!shownIfaces.length">
                    <td colspan="3" class="py-2 text-muted">
                      {{
                        form.ifaces.length
                          ? 'No interface matches.'
                          : 'This virtual firewall has no interfaces.'
                      }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </fieldset>
            <fieldset :disabled="readOnly" class="mt-3 space-y-3">
              <UFormField
                label="Allowed clients"
                help="Prefixes or hosts by name. Empty: any client on those interfaces."
                :ui="inlineField"
              >
                <AddrInput v-model="form.ntp_allow" multiple placeholder="192.168.1.0/24" />
              </UFormField>
            </fieldset>

            <div v-if="!readOnly" class="mt-4">
              <UButton type="submit" :loading="saving">Save</UButton>
            </div>
          </form>
        </div>
      </template>
    </UTabs>
  </NeedInstance>
</template>
