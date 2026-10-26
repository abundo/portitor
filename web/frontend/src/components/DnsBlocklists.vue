<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// DNS blocklists: the selected virtual firewall's response policy zones,
// which the agent downloads and BIND answers from, with their state from
// the agent; and the names no blocklist blocks (the instance's
// dns_blocklist_allow). A new blocklist may start from a public one
// (dnsBlocklistFeeds). The key is write-only: the server never sends it
// back, and empty keeps it.
import { computed, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import CrudPage from '@/components/CrudPage.vue'
import FormHeader from '@/components/FormHeader.vue'
import TagsInput from '@/components/TagsInput.vue'
import { api, dnsBlocklists, instances } from '@/api'
import { errMsg } from '@/api/http'
import { useStatusRefresh } from '@/composables/useAutoRefresh'
import { usePageForm } from '@/composables/useFormGuard'
import { useAuthStore } from '@/stores/auth'
import { useDeployStore } from '@/stores/deploy'
import { useInstanceStore } from '@/stores/instances'
import { dnsBlocklistFeeds } from '@/utils/dnsBlocklistFeeds'
import { inlineField } from '@/utils/form'
import { ago, datetime } from '@/utils/time'

// active: the tab is shown, so the agent's status is polled.
const props = defineProps({ active: { type: Boolean, default: false } })

const toast = useToast()
const auth = useAuthStore()
const store = useInstanceStore()
const deploy = useDeployStore()
const readOnly = computed(() => !auth.canEdit)
const { auto, loading } = useStatusRefresh({ active: () => props.active })
const params = computed(() => ({ instance_id: store.currentId }))
const page = ref(null)

const actions = [
  { label: 'NXDOMAIN: the name does not exist', value: 'nxdomain' },
  { label: 'NODATA: the name has no records', value: 'nodata' },
  { label: 'Drop: no answer at all', value: 'drop' },
  { label: 'Log only: answer, and log what would be blocked', value: 'log' },
]
const actionLabel = { nxdomain: 'NXDOMAIN', nodata: 'NODATA', drop: 'drop', log: 'log only' }
const refreshes = [
  { label: 'Every 10 minutes', value: 10 },
  { label: 'Every hour', value: 60 },
  { label: 'Every 6 hours', value: 360 },
  { label: 'Every 12 hours', value: 720 },
  { label: 'Every day', value: 1440 },
  { label: 'Every week', value: 10080 },
]
const refreshLabel = (m) =>
  refreshes.find((r) => r.value === m)?.label.replace('Every', 'every') ?? `every ${m} min`

// What the agent reports for each deployed blocklist of the virtual
// firewall, by name.
const states = computed(() =>
  Object.fromEntries(
    (deploy.status?.dns_blocklists ?? [])
      .filter((s) => s.instance === store.current?.name)
      .map((s) => [s.name, s]),
  ),
)
const stateColor = { ok: 'success', error: 'error', fetching: 'info' }

const feedItems = [
  { label: 'None: enter the URLs below', value: 'custom' },
  ...dnsBlocklistFeeds.map((f) => ({ label: f.label, value: f.key })),
]
const feedOf = (form) => dnsBlocklistFeeds.find((f) => f.key === form.feed)
const keyed = (form) => (form.urls ?? []).some((u) => u.includes('{key}'))

// pickFeed fills the form from a public blocklist, keeping a name and
// description the user typed.
function pickFeed(form, key) {
  const prev = feedOf(form)
  form.feed = key
  const f = feedOf(form)
  if (!f) return
  if (!form.name || form.name === prev?.key) form.name = f.key
  if (!form.description || form.description === prev?.description) form.description = f.description
  form.urls = [...f.urls]
  form.refresh = f.refresh
}

const columns = [
  { key: 'name', label: 'Name', class: 'font-mono font-medium' },
  { key: 'enabled', label: 'On', format: (r) => (r.enabled ? 'yes' : 'no') },
  { key: 'action', label: 'Action', format: (r) => actionLabel[r.action] ?? r.action },
  { key: 'refresh', label: 'Download', format: (r) => refreshLabel(r.refresh) },
  { key: 'state', label: 'State', format: (r) => states.value[r.name]?.state ?? '' },
  {
    key: 'names',
    label: 'Entries',
    format: (r) => states.value[r.name]?.names?.toLocaleString() ?? '',
  },
  {
    key: 'updated',
    label: 'Updated',
    format: (r) => (states.value[r.name] ? ago(states.value[r.name].updated) : ''),
  },
  { key: 'description', label: 'Description' },
]
const fields = [
  {
    key: 'feed',
    label: 'Blocklist',
    type: 'custom',
    show: (f) => !f.id,
  },
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'hagezi-tif',
    hint: "Lowercase letters, digits and '-', at most 32.",
  },
  { key: 'description', label: 'Description' },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  {
    key: 'urls',
    label: 'URLs',
    type: 'tags',
    required: true,
    placeholder: 'https://big.oisd.nl/rpz',
    hint: 'One to four: an RPZ zone file, a list of domains or a hosts file (or a zip of one), downloaded into one list. {key} stands for the key.',
  },
  {
    key: 'auth_key',
    label: 'Key',
    type: 'password',
    placeholder: 'abuse.ch Auth-Key',
    hint: 'Goes where {key} is in the URLs (URLhaus). Stored on the firewall, never shown; empty keeps it.',
    show: (f) => keyed(f) || f.has_auth_key,
  },
  {
    key: 'clear_auth_key',
    label: 'Remove the key',
    type: 'switch',
    show: (f) => f.has_auth_key && !keyed(f),
  },
  { key: 'action', label: 'Action', type: 'select', items: actions },
  {
    key: 'refresh',
    label: 'Download',
    type: 'select',
    items: refreshes,
    hint: 'Asks only for changes; BIND reloads the list when it changed.',
  },
]
const defaults = () => ({
  feed: 'custom',
  enabled: true,
  urls: [],
  action: 'nxdomain',
  refresh: 720,
})

async function download(row) {
  try {
    await api.refreshDNSBlocklist(row.id)
    toast.add({ title: `Downloading ${row.name}`, color: 'info' })
    setTimeout(() => deploy.refresh(), 2000)
  } catch (err) {
    toast.add({ title: errMsg(err, 'Download failed to start'), color: 'error' })
  }
}

// The names no blocklist blocks: the instance's dns_blocklist_allow.
const allow = reactive({ names: [] })
const allowForm = usePageForm(allow)
const saving = ref(false)

async function loadAllow() {
  if (!store.currentId) return
  const inst = await instances.get(store.currentId)
  allow.names = inst.dns_blocklist_allow ?? []
  allowForm.mark()
}
watch(() => store.currentId, loadAllow, { immediate: true })

async function saveAllow() {
  saving.value = true
  try {
    await instances.update(store.currentId, { dns_blocklist_allow: allow.names })
    toast.add({ title: 'Allowed names saved', color: 'success' })
    await loadAllow()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div class="space-y-4 pt-2">
    <CrudPage
      ref="page"
      title="DNS blocklists"
      noun="DNS blocklist"
      description="Domains of malware, phishing and scams that this virtual firewall's DNS server does not resolve: response policy zones (RPZ) in BIND, which the firewall downloads and keeps current. A name in a list blocks the names below it too. Blocked queries are logged in the DNS server's log. Commit to deploy a change; the firewall downloads a new list at once."
      :api="dnsBlocklists"
      :params="params"
      :columns="columns"
      :fields="fields"
      :defaults="defaults"
      :search-text="(r) => states[r.name]?.last_error ?? ''"
      new-label="New blocklist"
    >
      <template #toolbar-end>
        <AutoRefreshButton :auto="auto" :loading="loading" />
      </template>
      <template #cell-state="{ row }">
        <UTooltip
          v-if="states[row.name]"
          :text="states[row.name].last_error || `Next download ${datetime(states[row.name].next)}`"
        >
          <UBadge
            :color="stateColor[states[row.name].state] ?? 'neutral'"
            variant="subtle"
            :label="states[row.name].state"
          />
        </UTooltip>
        <span v-else-if="row.enabled" class="text-muted">not deployed</span>
      </template>
      <template #row-actions="{ row }">
        <UButton
          v-if="!readOnly && states[row.name]"
          size="sm"
          variant="outline"
          color="neutral"
          icon="i-lucide-download"
          aria-label="Download now"
          title="Download now"
          :loading="states[row.name].state === 'fetching'"
          @click="download(row)"
        />
      </template>
      <template #field-feed="{ form }">
        <div class="w-full space-y-1">
          <USelect
            :model-value="form.feed"
            :items="feedItems"
            class="w-full"
            @update:model-value="(v) => pickFeed(form, v)"
          />
          <p class="text-xs text-muted">
            {{
              feedOf(form)?.note ??
              'A public list, free to use: fills in the name, description, URLs and download interval.'
            }}
          </p>
        </div>
      </template>
    </CrudPage>

    <div class="card">
      <form @submit.prevent="saveAllow">
        <FormHeader title="Allowed names">
          <UButton v-if="!readOnly" type="submit" :loading="saving">Save</UButton>
        </FormHeader>
        <p class="mt-3 mb-4 text-sm text-muted">
          Domains that no blocklist blocks, nor the names below them: for a site a list blocks by
          mistake. Commit to deploy.
        </p>
        <fieldset :disabled="readOnly">
          <UFormField label="Domains" :ui="inlineField">
            <TagsInput v-model="allow.names" placeholder="example.com" />
          </UFormField>
        </fieldset>
      </form>
    </div>
  </div>
</template>
