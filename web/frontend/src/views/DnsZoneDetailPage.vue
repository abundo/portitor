<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import ZoneRecordsTable from '@/components/ZoneRecordsTable.vue'
import { api, dnsDnssecPolicies, dnsRecords, dnsSoaTemplates, dnsTemplates, dnsZones } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceStore } from '@/stores/instances'
import { builtinTemplate, zoneTypes } from '@/utils/dns'
import { formatZoneFile, parseZoneFile } from '@/utils/zoneFile'
import { fromApiRecord, toApiRecords, validateZoneRecords } from '@/utils/zoneRecords'
import { useAuthStore } from '@/stores/auth'
import { useConfirm } from '@/composables/useConfirm'
import { useUnsaved } from '@/composables/useFormGuard'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()
const { confirmDelete } = useConfirm()
const toast = useToast()
const store = useInstanceStore()
const zone = ref(null)
const templates = ref([])
const soas = ref([])
const policies = ref([])
const saving = ref(false)
const form = reactive({ name: '', dns_template_id: 0, description: '' })
const activeTab = ref('records')

const NONE = 0
const isForward = computed(() => zone.value?.type === 'forward')
const typeLabel = computed(
  () => zoneTypes.find((t) => t.value === zone.value?.type)?.label ?? zone.value?.type,
)
const tabItems = computed(() => [
  { label: 'Zone info', value: 'info', slot: 'info' },
  { label: 'Records', value: 'records', slot: 'records' },
])
const templateItems = computed(() => [
  { label: '— built-in (NS localhost)', value: NONE },
  ...templates.value.map((t) => ({ label: t.name, value: t.id })),
])

// The template the form has selected (not necessarily saved yet), and what
// it resolves to; the built-in one when there is none.
const template = computed(() => templates.value.find((t) => t.id === form.dns_template_id))
const effective = computed(() => {
  const t = template.value
  if (!t) return { ...builtinTemplate, policy: null }
  return {
    default_ttl: t.default_ttl,
    nameservers: t.nameservers ?? [],
    soa: soas.value.find((s) => s.id === t.soa_template_id) ?? null,
    policy: policies.value.find((p) => p.id === t.dnssec_policy_id) ?? null,
  }
})
const dirty = computed(
  () =>
    zone.value &&
    (form.name !== zone.value.name ||
      form.dns_template_id !== (zone.value.dns_template_id ?? NONE) ||
      form.description !== zone.value.description),
)

function fill(z) {
  zone.value = z
  form.name = z.name
  form.dns_template_id = z.dns_template_id ?? NONE
  form.description = z.description ?? ''
}

onMounted(async () => {
  try {
    const [z, t, s, p, r] = await Promise.all([
      dnsZones.get(route.params.id),
      dnsTemplates.list(),
      dnsSoaTemplates.list(),
      dnsDnssecPolicies.list(),
      dnsRecords.list({ zone_id: route.params.id }),
    ])
    loadRecords(r)
    templates.value = t
    soas.value = s
    policies.value = p
    fill(z)
    if (z.type !== 'forward') activeTab.value = 'info'
  } catch (err) {
    toast.add({ title: errMsg(err, 'Failed to load zone'), color: 'error' })
  }
})

async function save() {
  saving.value = true
  try {
    fill(
      await dnsZones.update(zone.value.id, {
        name: form.name,
        dns_template_id: form.dns_template_id === NONE ? null : form.dns_template_id,
        description: form.description,
      }),
    )
    toast.add({ title: 'Zone saved. Deploy to apply.', color: 'success' })
  } catch (err) {
    toast.add({ title: errMsg(err, 'Failed to save zone'), color: 'error' })
  } finally {
    saving.value = false
  }
}

// Delete lives here, not in the zones table (AGENTS.md, GUI design rules).
const deleted = ref(false)
async function remove() {
  if (!(await confirmDelete(`DNS zone ${zone.value.name}`))) return
  try {
    await dnsZones.remove(zone.value.id)
    deleted.value = true
    router.push('/dns?tab=zones')
  } catch (err) {
    toast.add({ title: errMsg(err, 'Delete failed'), color: 'error' })
  }
}

// Records: the grid edits the whole list; Save replaces the zone's records.
const records = ref([])
const savedRecords = ref('[]')
const savingRecords = ref(false)
const importInput = ref(null)
const instance = computed(() => store.list.find((i) => i.id === zone.value?.instance_id))
const recordsDirty = computed(
  () => JSON.stringify(toApiRecords(records.value)) !== savedRecords.value,
)

function loadRecords(list) {
  records.value = list.map(fromApiRecord)
  savedRecords.value = JSON.stringify(toApiRecords(records.value))
}

const recordStrings = {
  'zoneRecords.nameRequired': 'Name is required',
  'zoneRecords.typeRequired': 'Type is required',
  'zoneRecords.unknownType': 'Unknown type {type}',
  'zoneRecords.valueRequired': 'Value is required',
  'zoneRecords.aMustBeIpv4': 'A record must be an IPv4 address',
  'zoneRecords.aaaaMustBeIpv6': 'AAAA record must be an IPv6 address',
  'zoneRecords.macOnlyA': 'MAC is only valid on A and AAAA records',
  'zoneRecords.macInvalid': 'MAC must be 12 hex digits (aa:bb:cc:dd:ee:ff)',
  'zoneRecords.recordN': 'Record {n}: {message}',
}
function recordT(key, params = {}) {
  let s = recordStrings[key] ?? key
  for (const [k, v] of Object.entries(params)) s = s.replaceAll(`{${k}}`, String(v))
  return s
}

async function saveRecords() {
  const problem = validateZoneRecords(records.value, recordT)
  if (problem) {
    toast.add({ title: problem, color: 'error' })
    return
  }
  savingRecords.value = true
  try {
    loadRecords(await api.saveZoneRecords(zone.value.id, toApiRecords(records.value)))
    toast.add({ title: 'Records saved. Deploy to apply.', color: 'success' })
  } catch (err) {
    toast.add({ title: errMsg(err, 'Failed to save records'), color: 'error' })
  } finally {
    savingRecords.value = false
  }
}

function exportZoneFile() {
  const soa = effective.value.soa
  const text = formatZoneFile({
    origin: zone.value.name,
    soa: soa && { ...soa, ttl: soa.minimum, serial: 1 },
    defaultTtl: effective.value.default_ttl,
    nameservers: effective.value.nameservers,
    records: toApiRecords(records.value),
    comment: zone.value.description,
  })
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }))
  const a = document.createElement('a')
  a.href = url
  a.download = `${zone.value.name.replace(/[^\w.-]+/g, '_')}.zone`
  a.click()
  URL.revokeObjectURL(url)
}

async function onImportFile(event) {
  const file = event.target.files?.[0]
  event.target.value = ''
  if (!file) return
  try {
    const parsed = parseZoneFile(await file.text(), zone.value.name)
    records.value = parsed.records
    const skipped = []
    if (parsed.skippedSoa) skipped.push('SOA')
    if (parsed.skippedApexNs) skipped.push('NS for @')
    toast.add({
      title: `Imported ${parsed.records.length} records`,
      description: `${skipped.length ? `${skipped.join(', ')} skipped (they come from the DNS template). ` : ''}Save to keep them.`,
      color: 'success',
    })
    const unsupported = parsed.unsupported || []
    if (unsupported.length) {
      const lines = unsupported.map((u) => u.message)
      toast.add({
        title: `${unsupported.length} unsupported record(s) skipped`,
        description: lines.slice(0, 12).join('; ') + (lines.length > 12 ? '; …' : ''),
        color: 'warning',
      })
    }
  } catch (err) {
    toast.add({ title: err.message || 'Could not import the file', color: 'error' })
  }
}

useUnsaved(() => !deleted.value && (!!dirty.value || recordsDirty.value))
</script>

<template>
  <div v-if="zone" class="space-y-4">
    <div class="flex flex-wrap items-center gap-2">
      <UButton to="/dns?tab=zones" color="neutral" variant="ghost" icon="i-lucide-arrow-left" />
      <div class="font-mono text-lg font-semibold">{{ zone.name }}</div>
      <UBadge color="neutral" variant="subtle">{{ typeLabel }}</UBadge>
      <UBadge v-if="effective.policy" color="success" variant="subtle" icon="i-lucide-lock">
        DNSSEC: {{ effective.policy.name }}
      </UBadge>
      <span class="text-sm text-muted">instance {{ store.nameOf(zone.instance_id) }}</span>
    </div>

    <div class="card">
      <UTabs v-model="activeTab" :items="tabItems" :unmount-on-hide="false">
        <template #info>
          <form class="pt-4" @submit.prevent="save">
            <fieldset :disabled="!auth.isAdmin" class="space-y-4">
              <div class="grid gap-x-4 gap-y-3 sm:grid-cols-2">
                <UFormField label="Name" required>
                  <UInput v-model="form.name" class="w-full font-mono" />
                </UFormField>
                <UFormField
                  label="DNS template"
                  help="SOA, NS and default TTL come from the template."
                >
                  <USelect v-model="form.dns_template_id" :items="templateItems" class="w-full" />
                </UFormField>
              </div>
              <UFormField label="Description">
                <UTextarea v-model="form.description" class="w-full" :rows="3" />
              </UFormField>
              <div class="flex gap-2">
                <UButton v-if="auth.isAdmin" type="submit" :loading="saving" :disabled="!dirty"
                  >Save</UButton
                >
                <UButton
                  to="/dns-templates"
                  color="neutral"
                  variant="ghost"
                  icon="i-lucide-file-cog"
                  label="Edit templates"
                />
                <UButton
                  v-if="auth.isAdmin"
                  class="ms-auto"
                  color="error"
                  variant="ghost"
                  icon="i-lucide-trash"
                  label="Delete"
                  @click="remove"
                />
              </div>
            </fieldset>
          </form>
          <div class="mt-6 space-y-4 border-t border-default pt-4">
            <div class="text-sm font-semibold">SOA &amp; NS</div>
            <p class="text-sm text-muted">
              <template v-if="template"
                >From DNS template <b>{{ template.name }}</b
                >.</template
              >
              <template v-else>No DNS template: built-in values.</template>
              <template v-if="dirty"> Not saved yet.</template>
            </p>
            <template v-if="effective.soa">
              <div class="grid gap-x-4 gap-y-3 sm:grid-cols-2">
                <UFormField label="Primary nameserver (MNAME)">
                  <UInput
                    :model-value="effective.soa.mname + '.'"
                    disabled
                    class="w-full font-mono"
                  />
                </UFormField>
                <UFormField label="Mailbox (RNAME)">
                  <UInput
                    :model-value="effective.soa.rname + '.'"
                    disabled
                    class="w-full font-mono"
                  />
                </UFormField>
              </div>
              <div class="grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-6">
                <UFormField label="Serial">
                  <UInput model-value="dnsmgr2" disabled class="w-full" />
                </UFormField>
                <UFormField label="Refresh">
                  <UInput :model-value="effective.soa.refresh" disabled class="w-full" />
                </UFormField>
                <UFormField label="Retry">
                  <UInput :model-value="effective.soa.retry" disabled class="w-full" />
                </UFormField>
                <UFormField label="Expire">
                  <UInput :model-value="effective.soa.expire" disabled class="w-full" />
                </UFormField>
                <UFormField label="Minimum">
                  <UInput :model-value="effective.soa.minimum" disabled class="w-full" />
                </UFormField>
                <UFormField label="Default TTL">
                  <UInput :model-value="effective.default_ttl" disabled class="w-full" />
                </UFormField>
              </div>
            </template>
            <div>
              <div class="mb-1 text-sm font-medium">Nameservers (NS for @)</div>
              <ul class="font-mono text-sm">
                <li v-for="(ns, i) in effective.nameservers" :key="i">
                  {{ ns.name }}.
                  <span v-if="ns.address" class="text-muted">{{ ns.address }}</span>
                </li>
              </ul>
            </div>
            <div>
              <div class="mb-1 text-sm font-medium">DNSSEC</div>
              <p v-if="effective.policy" class="text-sm">
                Signed inline with policy <b>{{ effective.policy.name }}</b> (KSK
                {{ effective.policy.ksk_algorithm }}, ZSK {{ effective.policy.zsk_algorithm }}).
              </p>
              <p v-else class="text-sm text-muted">Not signed.</p>
            </div>
          </div>
        </template>

        <template #records>
          <div class="pt-4">
            <template v-if="isForward">
              <p class="mb-3 text-sm text-muted">
                Leave TTL empty to use the template default ({{ effective.default_ttl }}). SOA and
                NS for @ come from the DNS template and are skipped on import. IPAM addresses with a
                DNS name are added automatically and are not listed here. Type ; in an empty name
                for a comment; right-click for more.
              </p>
              <ZoneRecordsTable
                v-model="records"
                :show-mac="!!instance?.dhcp_enabled"
                :instance="instance?.name ?? ''"
                :disabled="!auth.isAdmin"
              >
                <template #leading-actions>
                  <UButton
                    v-if="auth.isAdmin"
                    type="button"
                    :loading="savingRecords"
                    :disabled="!recordsDirty"
                    @click="saveRecords"
                  >
                    Save
                  </UButton>
                </template>
                <template #actions>
                  <UButton
                    type="button"
                    color="neutral"
                    variant="outline"
                    icon="i-lucide-download"
                    title="Download as a BIND zone file"
                    @click="exportZoneFile"
                  >
                    Export
                  </UButton>
                  <UButton
                    v-if="auth.isAdmin"
                    type="button"
                    color="neutral"
                    variant="outline"
                    icon="i-lucide-upload"
                    title="Replaces all records. SOA and NS for @ are ignored."
                    @click="importInput?.click()"
                  >
                    Import
                  </UButton>
                </template>
              </ZoneRecordsTable>
              <input
                ref="importInput"
                type="file"
                accept=".txt,.zone,text/plain"
                class="hidden"
                @change="onImportFile"
              />
            </template>
            <p v-else class="text-sm text-muted">
              Reverse zones have no records of their own: PTRs are generated from the A/AAAA records
              and IPAM names in the forward zones.
            </p>
          </div>
        </template>
      </UTabs>
    </div>
  </div>
</template>
