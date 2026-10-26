<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- NAT64: Jool's sessions and counters (NAT64 info), and the prefix, the
     pool and DNS64 (NAT64 config). -->
<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import FormHeader from '@/components/FormHeader.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import TagsInput from '@/components/TagsInput.vue'
import { api, instances, interfaces } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceRefs, withLabel } from '@/composables/useInstanceRefs'
import { usePageForm } from '@/composables/useFormGuard'
import { useAuthStore } from '@/stores/auth'
import { useInstanceStore } from '@/stores/instances'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import { inlineField } from '@/utils/form'
import { useSearch, valuesText } from '@/utils/search'

const toast = useToast()
const auth = useAuthStore()
const store = useInstanceStore()
const readOnly = computed(() => !auth.canEdit)
const { ifaceText } = useInstanceRefs()
const route = useRoute()
const router = useRouter()

const tabs = [
  { label: 'NAT64 info', value: 'info', slot: 'info', icon: 'i-lucide-info' },
  { label: 'NAT64 config', value: 'config', slot: 'config', icon: 'i-lucide-settings' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'info'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'info' ? undefined : v } }),
})

// ----- NAT64 info: loaded, and refreshed every 5 s, while its tab is open.
const status = ref(null)
const statusError = ref('')
const loading = ref(false)
async function loadStatus() {
  loading.value = true
  try {
    status.value = await api.agentNat64()
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
const sessionCount = computed(() =>
  Object.values(mine.value?.session_counts ?? {}).reduce((a, b) => a + b, 0),
)
const hostPort = (a, p) => (a.includes(':') ? `[${a}]:${p}` : `${a}:${p}`)
const sessions = computed(() => mine.value?.sessions ?? [])
const sessionSearch = useSearch(sessions, (s) =>
  valuesText(
    s.protocol,
    hostPort(s.source6, s.port6),
    hostPort(s.dest6, s.dest_port6),
    hostPort(s.source4, s.port4),
    hostPort(s.dest4, s.dest_port4),
    s.state,
  ),
)
const sessionColumns = [
  { accessorKey: 'protocol', header: 'Protocol' },
  { id: 'source6', header: 'IPv6 client' },
  { id: 'dest6', header: 'IPv6 destination' },
  { id: 'source4', header: 'IPv4 source' },
  { id: 'dest4', header: 'IPv4 destination' },
  { accessorKey: 'expires', header: 'Expires in' },
  { accessorKey: 'state', header: 'State' },
]
const stats = computed(() => mine.value?.stats ?? [])
const statSearch = useSearch(stats, (s) => valuesText(s.name, s.value, s.explanation))
const statColumns = [
  { accessorKey: 'name', header: 'Counter' },
  { accessorKey: 'value', header: 'Value' },
  { accessorKey: 'explanation', header: 'Meaning' },
]

// The instance's nat64_* and dns64 fields.
const form = reactive({
  nat64_prefix: '64:ff9b::/96',
  nat64: false,
  nat64_pool4: [],
  dns64: false,
})
const pageForm = usePageForm(form)
const saving = ref(false)
// The interfaces with 464XLAT, set under Interfaces.
const xlatIfaces = ref([])

async function load() {
  const id = store.currentId
  if (!id) return
  const [inst, ifs] = await Promise.all([instances.get(id), interfaces.list({ instance_id: id })])
  Object.assign(form, {
    nat64_prefix: inst.nat64_prefix || '64:ff9b::/96',
    nat64: inst.nat64 ?? false,
    nat64_pool4: inst.nat64_pool4 ?? [],
    dns64: inst.dns64 ?? false,
  })
  xlatIfaces.value = ifs.filter((i) => i.xlat464).map((i) => withLabel(i.label, i.name))
  pageForm.mark()
}
watch(() => store.currentId, load, { immediate: true })

async function save() {
  saving.value = true
  try {
    await instances.update(store.currentId, { ...form })
    toast.add({ title: 'NAT64 saved', color: 'success' })
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
                <div class="text-lg font-semibold">NAT64 sessions</div>
                <p class="max-w-3xl text-sm text-muted">
                  The translations of this virtual firewall: the IPv6 client and the address it sent
                  to in the NAT64 prefix, and the IPv4 addresses they are translated to.
                  <template v-if="mine && !mine.error">
                    Prefix <span class="font-mono">{{ mine.prefix }}</span
                    ><template v-if="mine.pool4.length">
                      ; IPv4 pool
                      {{
                        mine.pool4.map((p) => `${p.address} (${ifaceText(p.interface)})`).join(', ')
                      }}</template
                    >.
                  </template>
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
            <div v-if="mine && !mine.error" class="mb-2 flex flex-wrap gap-2">
              <UBadge
                v-for="p in ['tcp', 'udp', 'icmp']"
                :key="p"
                color="neutral"
                variant="subtle"
                :label="`${p.toUpperCase()} ${mine.session_counts[p] ?? 0}`"
              />
              <span v-if="sessionCount > sessions.length" class="text-sm text-muted">
                showing the first {{ sessions.length }} of {{ sessionCount }}
              </span>
            </div>
            <SearchInput v-model="sessionSearch.search.value" class="mb-2" />
            <UTable
              :data="sessionSearch.filtered.value"
              :columns="sessionColumns"
              :loading="loading && !status"
            >
              <template #protocol-cell="{ row }">{{
                row.original.protocol.toUpperCase()
              }}</template>
              <template #source6-cell="{ row }">
                <span class="font-mono text-xs">{{
                  hostPort(row.original.source6, row.original.port6)
                }}</span>
              </template>
              <template #dest6-cell="{ row }">
                <span class="font-mono text-xs">{{
                  hostPort(row.original.dest6, row.original.dest_port6)
                }}</span>
              </template>
              <template #source4-cell="{ row }">
                <span class="font-mono text-xs">{{
                  hostPort(row.original.source4, row.original.port4)
                }}</span>
              </template>
              <template #dest4-cell="{ row }">
                <span class="font-mono text-xs">{{
                  hostPort(row.original.dest4, row.original.dest_port4)
                }}</span>
              </template>
              <template #empty>
                <div class="py-4 text-center text-muted">
                  {{
                    !status
                      ? ''
                      : mine
                        ? sessions.length
                          ? 'No session matches.'
                          : 'No sessions.'
                        : 'This virtual firewall does not translate (turn on Translate here under NAT64 config, then commit).'
                  }}
                </div>
              </template>
            </UTable>
          </div>

          <div v-if="mine && !mine.error" class="card">
            <div class="mb-2 text-lg font-semibold">Counters</div>
            <p class="mb-2 text-sm text-muted">
              Jool's counters since it started; zero ones are left out.
            </p>
            <SearchInput v-model="statSearch.search.value" class="mb-2" />
            <UTable :data="statSearch.filtered.value" :columns="statColumns">
              <template #name-cell="{ row }">
                <span class="font-mono text-xs">{{ row.original.name }}</span>
              </template>
              <template #explanation-cell="{ row }">
                <span class="text-muted whitespace-normal">{{ row.original.explanation }}</span>
              </template>
              <template #empty>
                <div class="py-4 text-center text-muted">
                  {{ stats.length ? 'No counter matches.' : 'No counters yet.' }}
                </div>
              </template>
            </UTable>
          </div>
        </div>
      </template>

      <template #config>
        <div class="card mt-2">
          <form @submit.prevent="save">
            <FormHeader title="NAT64">
              <UButton v-if="!readOnly" type="submit" :loading="saving">Save</UButton>
            </FormHeader>
            <p class="mb-4 text-sm text-muted">
              For IPv6-only clients: IPv6 packets to the NAT64 prefix are translated to IPv4, here
              or by another router (PLAT). Only packets coming in on an interface with 464XLAT are
              translated.
            </p>
            <fieldset :disabled="readOnly" class="space-y-3">
              <UFormField
                label="NAT64 prefix"
                help="The well-known prefix 64:ff9b::/96, or a network-specific one of length 32, 40, 48, 56, 64 or 96."
                :ui="inlineField"
              >
                <UInput v-model="form.nat64_prefix" class="w-full" placeholder="64:ff9b::/96" />
              </UFormField>
              <UFormField
                label="Translate here"
                help="Translate to IPv4 on this firewall (Jool). Off: another router is the NAT64 gateway."
                :ui="inlineField"
              >
                <USwitch v-model="form.nat64" />
              </UFormField>
              <UFormField
                v-if="form.nat64"
                label="IPv4 pool"
                help="One address for each interface with 464XLAT, used inside the firewall; the NAT rules then apply as to any IPv4 client. Empty: 192.0.0.0/29 (RFC 7335), masqueraded where it leaves, for up to 8 interfaces. A pool of your own must not overlap an address or route of the firewall."
                :ui="inlineField"
              >
                <TagsInput v-model="form.nat64_pool4" placeholder="198.18.0.0/24" />
              </UFormField>
              <UFormField
                label="DNS64"
                help="The DNS server answers a name that has only IPv4 addresses with IPv6 addresses in the NAT64 prefix."
                :ui="inlineField"
              >
                <USwitch v-model="form.dns64" />
              </UFormField>
            </fieldset>

            <h2 class="border-b border-default pb-1 mt-8 mb-2 text-xl font-semibold">464XLAT</h2>
            <p class="text-sm text-muted">
              Turned on per interface under
              <RouterLink to="/interfaces" class="text-primary">Interfaces</RouterLink>: the router
              advertisements announce the NAT64 prefix (PREF64) and DHCPv4 sends option 108
              (IPv6-only preferred).
            </p>
            <p class="mt-2 text-sm">
              <template v-if="xlatIfaces.length">On: {{ xlatIfaces.join(', ') }}</template>
              <span v-else class="text-muted">No interface has 464XLAT.</span>
            </p>
          </form>
        </div>
      </template>
    </UTabs>
  </NeedInstance>
</template>
