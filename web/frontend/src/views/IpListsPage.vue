<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import CrudPage from '@/components/CrudPage.vue'
import { api, ipLists } from '@/api'
import { errMsg } from '@/api/http'
import { useDeployStore } from '@/stores/deploy'
import { useObjectStore } from '@/stores/objects'
import { ago } from '@/utils/time'

const toast = useToast()
const deploy = useDeployStore()
const objects = useObjectStore()
onMounted(() => deploy.refresh())

// What the agent reports for each deployed list, by name.
const states = computed(() =>
  Object.fromEntries((deploy.status?.ip_lists ?? []).map((s) => [s.name, s])),
)
const stateColor = { ok: 'success', error: 'error', fetching: 'info' }

const sources = [
  { label: 'CrowdSec Local API (as a bouncer)', value: 'crowdsec' },
  { label: 'URL: one address or prefix per line', value: 'url' },
]
const sourceLabel = { crowdsec: 'CrowdSec LAPI', url: 'URL' }

const columns = [
  { key: 'name', label: 'Name', class: 'font-medium', format: (r) => `@${r.name}` },
  { key: 'source', label: 'Source', format: (r) => sourceLabel[r.source] ?? r.source },
  { key: 'url', label: 'URL', class: 'font-mono text-xs break-all' },
  { key: 'state', label: 'State' },
  { key: 'description', label: 'Description' },
]
const fields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'crowdsec',
    hint: 'Rules use it as @name.',
  },
  { key: 'description', label: 'Description' },
  { key: 'source', label: 'Source', type: 'select', items: sources },
  {
    key: 'url',
    label: 'URL',
    required: true,
    placeholder: 'http://127.0.0.1:8080 or https://…',
    hint: "CrowdSec: the engine's Local API; it returns its ban decisions, community blocklists included. URL: plain text, one address or prefix per line, # and ; start comments. A CrowdSec blocklist integration (Console, Blocklists, Integrations), Spamhaus DROP and FireHOL lists work this way.",
  },
  {
    key: 'api_key',
    label: 'Bouncer API key',
    type: 'password',
    placeholder: 'from: cscli bouncers add portitor',
    hint: 'Stored on the server and never shown again. Leave empty to keep the stored key.',
    show: (f) => f.source === 'crowdsec',
  },
  {
    key: 'username',
    label: 'Username',
    placeholder: 'empty: no authentication',
    show: (f) => f.source !== 'crowdsec',
  },
  {
    key: 'password',
    label: 'Password',
    type: 'password',
    hint: 'HTTP basic auth. Stored on the server and never shown again. Leave empty to keep the stored password.',
    show: (f) => f.source !== 'crowdsec' && !!f.username,
  },
]

async function refresh(row) {
  try {
    await api.refreshIPList(row.id)
    toast.add({ title: `Downloading @${row.name}`, color: 'info' })
    setTimeout(() => deploy.refresh(), 2000)
  } catch (err) {
    toast.add({ title: errMsg(err, 'Download failed to start'), color: 'error' })
  }
}
</script>

<template>
  <CrudPage
    title="IP lists"
    description="Address lists the firewall downloads: the ban decisions of a CrowdSec engine, or any list with one address or prefix per line. Use a list as @name in a rule's source or destination, say to drop everything from @crowdsec; it becomes an nftables set in each instance whose rules use it, and matches IPv4 and IPv6. A list is downloaded when it is first deployed and whenever a scheduled task says so; the last download stays in force if a later one fails."
    :api="ipLists"
    :columns="columns"
    :fields="fields"
    :defaults="{ source: 'crowdsec' }"
    new-label="New IP list"
    :item-name="(r) => `@${r.name}`"
    @changed="objects.load(true)"
  >
    <template #cell-state="{ row }">
      <div v-if="states[row.name]" class="space-y-0.5 text-xs">
        <UBadge :color="stateColor[states[row.name].state] ?? 'neutral'" variant="subtle" size="sm">
          {{ states[row.name].state }}
        </UBadge>
        <div v-if="states[row.name].updated">
          {{ states[row.name].ipv4 }} IPv4, {{ states[row.name].ipv6 }} IPv6
          <span v-if="states[row.name].skipped" class="text-muted">
            ({{ states[row.name].skipped }} skipped)
          </span>
        </div>
        <div class="text-muted">updated {{ ago(states[row.name].updated) }}</div>
        <div v-if="states[row.name].last_error" class="text-error">
          {{ states[row.name].last_error }}
        </div>
      </div>
      <span v-else class="text-xs text-muted">not deployed</span>
    </template>
    <template #row-actions="{ row }">
      <UButton
        size="xs"
        color="neutral"
        variant="ghost"
        icon="i-lucide-refresh-cw"
        title="Download now"
        :disabled="!states[row.name] || states[row.name].state === 'fetching'"
        @click="refresh(row)"
      />
    </template>
  </CrudPage>
</template>
