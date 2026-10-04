<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import DyndnsClientForm from '@/components/DyndnsClientForm.vue'
import DyndnsState from '@/components/DyndnsState.vue'
import ZoneRecordsTable from '@/components/ZoneRecordsTable.vue'
import { api, dyndnsClients, dyndnsRecords } from '@/api'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { useDeployStore } from '@/stores/deploy'
import { useInstanceStore } from '@/stores/instances'
import { useUnsaved } from '@/composables/useFormGuard'
import { dynamicZoneLabel } from '@/utils/dns'
import { fromApiRecord, isIPv4Address, isIPv6Address, toApiRecords } from '@/utils/zoneRecords'

// A DNS update client's zone: its records, edited as a zone's, and its
// settings (provider, key, interface) in the client's form, behind Settings.
const auth = useAuthStore()
const route = useRoute()
const router = useRouter()
const deploy = useDeployStore()
onMounted(() => deploy.refresh())
const settings = ref(null)
const toast = useToast()
const store = useInstanceStore()
const client = ref(null)
const records = ref([])
const saved = ref('[]')
const saving = ref(false)

// fwconfig.DynDNSRecordTypes
const types = ['A', 'AAAA', 'CNAME', 'TXT']

// The fields a DNS update record has (no MAC).
const payload = (rows) =>
  toApiRecords(rows).map((r) => {
    delete r.mac
    return r
  })
const dirty = computed(() => JSON.stringify(payload(records.value)) !== saved.value)

function load(list) {
  records.value = list.map(fromApiRecord)
  saved.value = JSON.stringify(payload(records.value))
}

onMounted(async () => {
  try {
    const [c, r] = await Promise.all([
      dyndnsClients.get(route.params.id),
      dyndnsRecords.list({ client_id: route.params.id }),
    ])
    client.value = c
    load(r)
  } catch (err) {
    toast.add({ title: errMsg(err, 'Failed to load zone'), color: 'error' })
  }
})

// A/AAAA and TXT may be empty: they follow the interface, or hold the time
// of the last update.
function problem(rows) {
  for (const [i, r] of rows.entries()) {
    const msg =
      (r.type === 'A' && r.value && !isIPv4Address(r.value) && 'A must be an IPv4 address') ||
      (r.type === 'AAAA' && r.value && !isIPv6Address(r.value) && 'AAAA must be an IPv6 address') ||
      (r.type === 'CNAME' && !r.value && 'a CNAME needs its target')
    if (msg) return `Record ${i + 1}: ${msg}`
  }
  return null
}

// After the settings form saved or deleted the client.
const deleted = ref(false)
async function onChanged() {
  try {
    client.value = await dyndnsClients.get(client.value.id)
  } catch {
    deleted.value = true
    router.push('/dns?tab=zones')
  }
}

async function save() {
  const rows = payload(records.value)
  const msg = problem(rows)
  if (msg) {
    toast.add({ title: msg, color: 'error' })
    return
  }
  saving.value = true
  try {
    load(await api.saveDyndnsRecords(client.value.id, rows))
    toast.add({ title: 'Records saved. Commit to apply.', color: 'success' })
  } catch (err) {
    toast.add({ title: errMsg(err, 'Failed to save records'), color: 'error' })
  } finally {
    saving.value = false
  }
}

useUnsaved(() => !deleted.value && dirty.value)
</script>

<template>
  <div v-if="client" class="space-y-4">
    <div class="flex flex-wrap items-center gap-2">
      <UButton to="/dns?tab=zones" color="neutral" variant="ghost" icon="i-lucide-arrow-left" />
      <div class="font-mono text-lg font-semibold">{{ client.zone }}</div>
      <UBadge color="neutral" variant="subtle">{{ dynamicZoneLabel }}</UBadge>
      <span class="text-sm text-muted">instance {{ store.nameOf(client.instance_id) }}</span>
      <UButton
        class="ms-auto"
        color="neutral"
        variant="outline"
        :icon="auth.canEdit ? 'i-lucide-settings' : 'i-lucide-eye'"
        label="Settings"
        @click="auth.canEdit ? settings.openEdit(client) : settings.openView(client)"
      />
    </div>
    <DyndnsState :name="client.name" />

    <div class="card space-y-3">
      <p class="text-sm text-muted">
        Kept up to date on another nameserver by DNS updates ({{ client.name }}); the nameserver or
        provider, key and interface are under Settings. A and AAAA with an empty value follow the
        interface's address; TXT with an empty value holds the time of the last update. TTL empty:
        300. One record per name and type; a name with a CNAME can have no other records.
      </p>
      <ZoneRecordsTable v-model="records" :types="types" simple :disabled="!auth.canEdit">
        <template #leading-actions>
          <UButton
            v-if="auth.canEdit"
            type="button"
            :loading="saving"
            :disabled="!dirty"
            @click="save"
          >
            Save
          </UButton>
        </template>
      </ZoneRecordsTable>
    </div>
    <DyndnsClientForm ref="settings" @changed="onChanged" />
  </div>
</template>
