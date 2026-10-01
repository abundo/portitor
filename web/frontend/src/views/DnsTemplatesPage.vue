<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { onMounted, ref } from 'vue'
import CrudPage from '@/components/CrudPage.vue'
import { dnsDnssecPolicies, dnsSoaTemplates, dnsTemplates } from '@/api'

// SOA templates and DNSSEC policies feed the DNS templates' selects.
const soas = ref([])
const policies = ref([])
const templatesPage = ref(null)

async function loadRefs() {
  ;[soas.value, policies.value] = await Promise.all([
    dnsSoaTemplates.list(),
    dnsDnssecPolicies.list(),
  ])
  templatesPage.value?.reload()
}
onMounted(loadRefs)

const nameOf = (list, id) => list.find((x) => x.id === id)?.name ?? ''

// Nameservers are rows of a name and an optional IPv4 or IPv6 address (a
// second row of the name for the other); the builder adds the address of
// one inside a zone to it as an A / AAAA record.
const newNameserver = () => ({ name: '', address: '' })
function addNameserver(form) {
  form.nameservers = [...(form.nameservers ?? []), newNameserver()]
}
function removeNameserver(form, i) {
  form.nameservers = form.nameservers.filter((_, j) => j !== i)
}

const soaColumns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'mname', label: 'Primary NS (MNAME)', class: 'font-mono' },
  { key: 'rname', label: 'Mailbox (RNAME)', class: 'font-mono' },
  { key: 'refresh', label: 'Refresh' },
  { key: 'retry', label: 'Retry' },
  { key: 'expire', label: 'Expire' },
  { key: 'minimum', label: 'Minimum' },
]
const soaFields = [
  { key: 'name', label: 'Name', required: true },
  {
    key: 'mname',
    label: 'Primary nameserver (MNAME)',
    required: true,
    placeholder: 'ns1.example.com',
  },
  {
    key: 'rname',
    label: 'Mailbox (RNAME)',
    required: true,
    placeholder: 'hostmaster.example.com',
    hint: 'hostmaster@example.com is accepted and stored as hostmaster.example.com.',
  },
  { key: 'refresh', label: 'Refresh (seconds)', type: 'number' },
  { key: 'retry', label: 'Retry (seconds)', type: 'number' },
  { key: 'expire', label: 'Expire (seconds)', type: 'number' },
  {
    key: 'minimum',
    label: 'Minimum (seconds)',
    type: 'number',
    hint: 'How long resolvers cache a "no such name" answer.',
  },
]
const soaDefaults = { refresh: 86400, retry: 7200, expire: 3600000, minimum: 3600 }

const algorithms = [
  'ecdsap256sha256',
  'ecdsap384sha384',
  'ed25519',
  'ed448',
  'rsasha256',
  'rsasha512',
].map((a) => ({ label: a, value: a }))
const durationHint = 'BIND duration, e.g. P1Y, 30d or PT12H. Empty: BIND default.'
const policyColumns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  {
    key: 'ksk',
    label: 'KSK',
    format: (r) => `${r.ksk_algorithm}, ${r.ksk_lifetime || 'unlimited'}`,
  },
  {
    key: 'zsk',
    label: 'ZSK',
    format: (r) => `${r.zsk_algorithm}, ${r.zsk_lifetime || 'unlimited'}`,
  },
  { key: 'signatures_validity', label: 'Signatures valid' },
]
const policyFields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    hint: 'default, insecure and none are BIND built-ins.',
  },
  { key: 'ksk_algorithm', label: 'KSK algorithm', type: 'select', items: algorithms },
  {
    key: 'ksk_lifetime',
    label: 'KSK lifetime',
    placeholder: 'unlimited',
    hint: 'Empty: unlimited.',
  },
  { key: 'zsk_algorithm', label: 'ZSK algorithm', type: 'select', items: algorithms },
  { key: 'zsk_lifetime', label: 'ZSK lifetime', placeholder: '30d', hint: 'Empty: unlimited.' },
  { key: 'purge_keys', label: 'purge-keys', placeholder: '90d', hint: durationHint },
  {
    key: 'signatures_validity',
    label: 'signatures-validity',
    placeholder: '14d',
    hint: durationHint,
  },
  {
    key: 'signatures_validity_dnskey',
    label: 'signatures-validity-dnskey',
    placeholder: '14d',
    hint: durationHint,
  },
  { key: 'signatures_refresh', label: 'signatures-refresh', placeholder: '5d', hint: durationHint },
]
const policyDefaults = {
  ksk_algorithm: 'ecdsap256sha256',
  ksk_lifetime: '',
  zsk_algorithm: 'ecdsap256sha256',
  zsk_lifetime: '',
}

const templateColumns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'soa', label: 'SOA', format: (r) => nameOf(soas.value, r.soa_template_id) },
  { key: 'default_ttl', label: 'Default TTL' },
  { key: 'nameservers', label: 'Nameservers', class: 'font-mono' },
  {
    key: 'dnssec',
    label: 'DNSSEC',
    format: (r) => nameOf(policies.value, r.dnssec_policy_id) || '—',
  },
  { key: 'description', label: 'Description' },
]
const templateFields = [
  { key: 'name', label: 'Name', required: true },
  {
    key: 'soa_template_id',
    label: 'SOA template',
    type: 'select',
    items: () => soas.value.map((s) => ({ label: s.name, value: s.id })),
  },
  { key: 'default_ttl', label: 'Default TTL (seconds)', type: 'number' },
  {
    key: 'nameservers',
    label: 'Nameservers (NS)',
    type: 'custom',
    hint: 'Written as the NS records of every zone using this template. The address is optional: a nameserver inside a zone of the instance gets it as an A / AAAA record there. For both an IPv4 and an IPv6 address, add the nameserver twice.',
  },
  {
    key: 'dnssec_policy_id',
    label: 'DNSSEC policy',
    type: 'select',
    nullable: true,
    items: () => policies.value.map((p) => ({ label: p.name, value: p.id })),
    hint: '—: the zones are not signed.',
  },
  { key: 'description', label: 'Description' },
]
const templateDefaults = () => ({
  soa_template_id: soas.value[0]?.id,
  default_ttl: 3600,
  nameservers: [newNameserver()],
})
</script>

<template>
  <div class="space-y-4">
    <CrudPage
      ref="templatesPage"
      title="DNS templates"
      noun="DNS template"
      description="A zone's template gives it its SOA, default TTL, NS records and optional DNSSEC policy. Templates are shared by all instances."
      :api="dnsTemplates"
      shared
      :columns="templateColumns"
      :fields="templateFields"
      :defaults="templateDefaults"
      new-label="New template"
      :blocked-reason="soas.length ? '' : 'Create an SOA template first.'"
    >
      <template #cell-nameservers="{ row }">
        <div v-for="(ns, i) in row.nameservers" :key="i" class="font-mono">
          {{ ns.name }}
          <span v-if="ns.address" class="text-muted">({{ ns.address }})</span>
        </div>
      </template>
      <template #field-nameservers="{ form }">
        <div class="space-y-2">
          <div v-for="(ns, i) in form.nameservers" :key="i" class="flex items-center gap-2">
            <UInput
              v-model="ns.name"
              placeholder="ns1.example.com"
              class="min-w-0 flex-1"
              :ui="{ base: 'font-mono' }"
              aria-label="Nameserver"
            />
            <UInput
              v-model="ns.address"
              placeholder="IPv4 or IPv6 (optional)"
              class="min-w-0 flex-1"
              :ui="{ base: 'font-mono' }"
              aria-label="Address"
            />
            <UButton
              icon="i-lucide-x"
              color="neutral"
              variant="ghost"
              size="sm"
              :disabled="form.nameservers.length === 1"
              title="Remove"
              aria-label="Remove"
              @click="removeNameserver(form, i)"
            />
          </div>
          <UButton
            icon="i-lucide-plus"
            color="neutral"
            variant="outline"
            block
            aria-label="Add a nameserver"
            title="Add a nameserver"
            @click="addNameserver(form)"
          />
        </div>
      </template>
    </CrudPage>
    <CrudPage
      title="SOA templates"
      noun="SOA template"
      description="Start of authority for the zones whose DNS template uses it. The serial is set by dnsmgr2 on each change (YYYYMMDDnn)."
      :api="dnsSoaTemplates"
      shared
      :columns="soaColumns"
      :fields="soaFields"
      :defaults="soaDefaults"
      new-label="New SOA template"
      @changed="loadRefs"
    />
    <CrudPage
      title="DNSSEC policies"
      noun="DNSSEC policy"
      description="BIND dnssec-policy statements. Zones whose DNS template has a policy are signed by BIND (inline signing); keys are kept in the instance's BIND directory."
      :api="dnsDnssecPolicies"
      shared
      :columns="policyColumns"
      :fields="policyFields"
      :defaults="policyDefaults"
      new-label="New policy"
      @changed="loadRefs"
    />
  </div>
</template>
