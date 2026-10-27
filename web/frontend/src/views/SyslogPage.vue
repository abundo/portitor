<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- Syslog: the firewall's journal and rsyslog, which sends it to remote
     syslog servers (Syslog info), and those servers (Syslog configuration).
     Both are the firewall's, not a virtual firewall's: the servers are rows
     of its host, the default virtual firewall. -->
<script setup>
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import ServiceLog from '@/components/ServiceLog.vue'
import { api, syslogServers } from '@/api'
import { errMsg } from '@/api/http'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import { useAuthStore } from '@/stores/auth'
import { useInstanceStore } from '@/stores/instances'
import { bytes } from '@/utils/bytes'
import { ago, datetime } from '@/utils/time'

const auth = useAuthStore()
const store = useInstanceStore()
const route = useRoute()
const router = useRouter()

// The selected virtual firewall's firewall, and its host.
const host = computed(() => store.host)
const firewallName = computed(() => store.firewallName(store.firewallId) || host.value?.name || '')

const tabs = [
  { label: 'Syslog info', value: 'info', slot: 'info', icon: 'i-lucide-info' },
  { label: 'Syslog configuration', value: 'config', slot: 'config', icon: 'i-lucide-settings' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'info'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'info' ? undefined : v } }),
})

// ----- Info: loaded, and refreshed every 10 s, while its tab is open.
const status = ref(null)
const statusError = ref('')
const loading = ref(false)
async function loadStatus() {
  if (!store.firewallId) return
  loading.value = true
  try {
    status.value = await api.agentSyslog(store.firewallId)
    statusError.value = ''
  } catch (err) {
    statusError.value = errMsg(err)
  } finally {
    loading.value = false
  }
}
const auto = useAutoRefresh(loadStatus, { seconds: 10, active: () => tab.value === 'info' })
watch(
  () => store.firewallId,
  () => {
    status.value = null
    loadStatus()
  },
)

const stateColor = (s) =>
  ({ active: 'success', failed: 'error', activating: 'warning', reloading: 'warning' })[s] ??
  'neutral'
const protocolLabel = (s) => `${s.protocol.toUpperCase()} ${s.port}`

// ----- Configuration: the host's syslog servers.
const protocolItems = [
  { label: 'UDP', value: 'udp' },
  { label: 'TCP', value: 'tcp' },
]
const formatItems = [
  { label: 'RFC 3164 (BSD syslog)', value: 'rfc3164' },
  { label: 'RFC 5424', value: 'rfc5424' },
]
const severityItems = [
  { label: 'emerg (0)', value: 'emerg' },
  { label: 'alert (1)', value: 'alert' },
  { label: 'crit (2)', value: 'crit' },
  { label: 'err (3)', value: 'err' },
  { label: 'warning (4)', value: 'warning' },
  { label: 'notice (5)', value: 'notice' },
  { label: 'info (6)', value: 'info' },
  { label: 'debug (7)', value: 'debug' },
]
const formatLabel = (v) => formatItems.find((i) => i.value === v)?.label ?? v
const columns = [
  { key: 'address', label: 'Server', class: 'font-mono' },
  { key: 'enabled', label: 'Enabled' },
  { key: 'protocol', label: 'Protocol', format: (s) => protocolLabel(s) },
  { key: 'format', label: 'Format', format: (s) => formatLabel(s.format) },
  { key: 'severity', label: 'Severity', format: (s) => `${s.severity} and more urgent` },
  { key: 'description', label: 'Description' },
]
const fields = [
  {
    key: 'address',
    label: 'Address',
    required: true,
    placeholder: '192.0.2.10',
    hint: 'The IPv4 or IPv6 address of the syslog server.',
  },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  { key: 'description', label: 'Description' },
  { key: 'protocol', label: 'Protocol', type: 'select', items: protocolItems },
  {
    key: 'port',
    label: 'Port',
    type: 'number',
    hint: '514 is the usual syslog port, over UDP and TCP.',
  },
  {
    key: 'format',
    label: 'Format',
    type: 'select',
    items: formatItems,
    hint: 'RFC 5424 over TCP is sent with octet counting (RFC 6587).',
  },
  {
    key: 'severity',
    label: 'Severity',
    type: 'select',
    items: severityItems,
    hint: 'Sends the entries of this severity and the more urgent ones.',
  },
]
const defaults = {
  address: '',
  enabled: true,
  description: '',
  protocol: 'udp',
  port: 514,
  format: 'rfc3164',
  severity: 'info',
}
</script>

<template>
  <NeedInstance>
    <UTabs v-model="tab" :items="tabs">
      <template #info>
        <div class="space-y-4 pt-2">
          <div class="card">
            <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <div class="text-lg font-semibold">Syslog</div>
                <p class="max-w-3xl text-sm text-muted">
                  Firewall {{ firewallName }} keeps its logs, and those of all its virtual
                  firewalls, in the systemd journal. rsyslog sends the journal to the syslog servers
                  under Syslog configuration.
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
            <table v-if="status" class="text-sm">
              <tbody>
                <tr>
                  <td class="py-1 pr-6 text-muted">rsyslog</td>
                  <td class="py-1">
                    <span class="mr-2 font-mono text-xs">{{ status.unit }}</span>
                    <UBadge
                      :color="stateColor(status.state)"
                      variant="subtle"
                      :label="status.state || 'unknown'"
                    />
                    <span v-if="status.since" class="ml-2 text-muted"
                      >since {{ datetime(status.since) }} ({{ ago(status.since) }})</span
                    >
                  </td>
                </tr>
                <tr>
                  <td class="py-1 pr-6 align-top text-muted">Syslog servers</td>
                  <td class="py-1">
                    <div v-if="!status.servers.length" class="text-muted">
                      None deployed: the journal is kept on the firewall only.
                    </div>
                    <div v-for="s in status.servers" :key="`${s.address} ${s.protocol} ${s.port}`">
                      <span class="font-mono">{{ s.address }}</span>
                      {{ protocolLabel(s) }}, {{ formatLabel(s.format) }}, {{ s.severity }} and more
                      urgent
                    </div>
                  </td>
                </tr>
                <tr>
                  <td class="py-1 pr-6 text-muted">Journal</td>
                  <td class="py-1">
                    {{ bytes(status.journal_bytes) }},
                    {{
                      status.journal_persistent
                        ? 'kept on disk (/var/log/journal)'
                        : 'in memory only (/run/log/journal): lost at reboot'
                    }}
                  </td>
                </tr>
                <tr v-if="status.journal_since">
                  <td class="py-1 pr-6 text-muted">Oldest entry</td>
                  <td class="py-1">{{ datetime(status.journal_since) }}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="card">
            <div class="mb-2 text-lg font-semibold">Journal</div>
            <p class="mb-3 max-w-3xl text-sm text-muted">
              The firewall's journal as it comes (journalctl --follow), starting with its last 500
              entries.
            </p>
            <div v-if="auth.isAdmin" class="flex h-[60vh] min-h-64 flex-col">
              <ServiceLog
                :key="store.firewallId"
                endpoint="/agent/journal"
                :request="{ firewall_id: store.firewallId }"
              />
            </div>
            <div v-else class="text-sm text-muted">
              The journal holds every virtual firewall's logs: only global admins follow it.
            </div>
          </div>
        </div>
      </template>

      <template #config>
        <div class="pt-2">
          <CrudPage
            v-if="host"
            title="Syslog servers"
            :description="`The remote syslog servers firewall ${firewallName} sends its journal to, with rsyslog. They are the firewall's: every virtual firewall's logs go to them. Commit to apply a change. The firewall's output chain lets the messages out to these servers by itself.`"
            :api="syslogServers"
            :params="{ instance_id: host.id }"
            :columns="columns"
            :fields="fields"
            :defaults="defaults"
            noun="syslog server"
            new-label="Add server"
            :item-name="(s) => `syslog server ${s.address} (${protocolLabel(s)})`"
          />
          <div v-else class="card text-sm text-muted">
            The syslog servers are the firewall's, set on its default virtual firewall, which you
            can't see.
          </div>
        </div>
      </template>
    </UTabs>
  </NeedInstance>
</template>
