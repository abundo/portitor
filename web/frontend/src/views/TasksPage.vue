<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import CrudPage from '@/components/CrudPage.vue'
import ScheduleHelp from '@/components/ScheduleHelp.vue'
import { api, ipLists, tasks } from '@/api'
import { errMsg } from '@/api/http'
import { useDeployStore } from '@/stores/deploy'
import { ago, when } from '@/utils/time'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const toast = useToast()
const deploy = useDeployStore()
const lists = ref([])
onMounted(async () => {
  deploy.refresh()
  lists.value = await ipLists.list().catch(() => [])
})
const listItems = computed(() =>
  lists.value.map((l) => ({ label: `@${l.name}`, value: l.id, description: l.description })),
)
const listName = (id) => lists.value.find((l) => l.id === id)?.name ?? ''

// What the agent reports for each deployed task, by name.
const states = computed(() =>
  Object.fromEntries((deploy.status?.tasks ?? []).map((s) => [s.name, s])),
)
const resultColor = { ok: 'success', error: 'error' }

const kinds = [
  { label: 'Download an IP list', value: 'iplist' },
  { label: 'Run a command', value: 'command' },
]

const columns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'schedule', label: 'Schedule', class: 'font-mono' },
  { key: 'what', label: 'Does' },
  { key: 'next', label: 'Next run' },
  { key: 'last', label: 'Last run' },
  { key: 'enabled', label: 'Enabled' },
]
const fields = [
  { key: 'name', label: 'Name', required: true, placeholder: 'crowdsec' },
  { key: 'description', label: 'Description' },
  { key: 'kind', label: 'Task', type: 'select', items: kinds },
  {
    key: 'ip_list_id',
    label: 'IP list',
    type: 'select',
    items: () => listItems.value,
    show: (f) => f.kind === 'iplist',
    hint: 'Downloaded again, and its sets reloaded in every virtual firewall whose rules use it.',
  },
  {
    key: 'command',
    label: 'Command',
    type: 'textarea',
    show: (f) => f.kind === 'command',
    hint: "Run with /bin/bash -c on the firewall host as the agent's console user (console_user in agent.yaml), in its home directory. Refused when the console is off.",
  },
  {
    key: 'timeout',
    label: 'Timeout (seconds)',
    type: 'number',
    show: (f) => f.kind === 'command',
    hint: '0: 3600. The command, and everything it started, is killed then.',
  },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  {
    key: 'schedule',
    label: 'Schedule',
    required: true,
    placeholder: '*/15 * * * *',
    hint: 'A task does not start again while it is still running.',
  },
]

async function runNow(row) {
  try {
    await api.runTask(row.id)
    toast.add({ title: `Started ${row.name}`, color: 'info' })
    setTimeout(() => deploy.refresh(), 2000)
  } catch (err) {
    toast.add({ title: errMsg(err, 'Task failed to start'), color: 'error' })
  }
}
</script>

<template>
  <CrudPage
    title="Scheduled tasks"
    noun="task"
    description="Jobs the firewall runs on a cron schedule, in its own time zone: download an IP list again, or run a shell command. Tasks take effect when deployed; Next and Last run are what the firewall reports."
    :api="tasks"
    shared
    :columns="columns"
    :fields="fields"
    :defaults="{ kind: 'iplist', schedule: '*/15 * * * *', enabled: true, timeout: 0 }"
    new-label="New task"
  >
    <template #cell-what="{ row }">
      <span v-if="row.kind === 'iplist'"
        >download <span class="font-medium">@{{ listName(row.ip_list_id) }}</span></span
      >
      <code v-else class="line-clamp-2 text-xs break-all" :title="row.command">{{
        row.command
      }}</code>
    </template>
    <template #cell-next="{ row }">
      <span v-if="states[row.name]?.next" class="text-xs">{{ when(states[row.name].next) }}</span>
      <span v-else-if="states[row.name]" class="text-xs text-muted">never</span>
      <span v-else class="text-xs text-muted">{{ row.enabled ? 'not deployed' : 'disabled' }}</span>
    </template>
    <template #cell-last="{ row }">
      <div v-if="states[row.name]" class="space-y-0.5 text-xs">
        <UBadge v-if="states[row.name].running" color="info" variant="subtle" size="sm">
          running
        </UBadge>
        <UBadge
          v-else-if="states[row.name].last_result"
          :color="resultColor[states[row.name].last_result] ?? 'neutral'"
          variant="subtle"
          size="sm"
        >
          {{ states[row.name].last_result }}
        </UBadge>
        <div class="text-muted">{{ ago(states[row.name].last_start) }}</div>
        <div v-if="states[row.name].last_error" class="text-error">
          {{ states[row.name].last_error }}
        </div>
        <pre
          v-if="states[row.name].output"
          class="max-h-24 max-w-xs overflow-auto rounded bg-elevated p-1 text-[11px] whitespace-pre-wrap"
          >{{ states[row.name].output }}</pre
        >
      </div>
    </template>
    <template #row-actions="{ row }">
      <UButton
        v-if="auth.isAdmin"
        size="xs"
        color="neutral"
        variant="ghost"
        icon="i-lucide-play"
        title="Run now"
        :disabled="!states[row.name] || states[row.name].running"
        @click="runNow(row)"
      />
    </template>
    <template #form-extra="{ form }">
      <ScheduleHelp v-model="form.schedule" />
    </template>
  </CrudPage>
</template>
