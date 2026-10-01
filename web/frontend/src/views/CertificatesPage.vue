<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, ref } from 'vue'
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { api, certificates } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useDeployStore } from '@/stores/deploy'
import { ago, when } from '@/utils/time'
import { valuesText } from '@/utils/search'

const { store, ifaceItems, ifaceName } = useInstanceRefs()
const deploy = useDeployStore()
onMounted(() => deploy.refresh())

// The ACME CAs by name (fwconfig.ACMECAs).
const cas = ref([])
onMounted(async () => (cas.value = await api.acmeCAs()))
const caLabel = (name) => cas.value.find((c) => c.name === name)?.label ?? name

// What the agent reports for the instance's certificates, by name.
const states = computed(() => {
  const m = {}
  for (const s of deploy.status?.certificates ?? []) {
    if (s.instance === store.current?.name) m[s.name] = s
  }
  return m
})
const stateColor = { ok: 'success', error: 'error', issuing: 'info' }

const columns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'domains', label: 'Domains', class: 'font-mono', format: (r) => r.domains.join(', ') },
  { key: 'interface_id', label: 'Interface', format: (r) => ifaceName(r.interface_id) },
  { key: 'ca', label: 'CA', format: (r) => caLabel(r.ca) },
  { key: 'state', label: 'State' },
  { key: 'enabled', label: 'Enabled' },
]
const fields = computed(() => [
  { key: 'name', label: 'Name', required: true, placeholder: 'www' },
  { key: 'description', label: 'Description' },
  {
    key: 'domains',
    label: 'Domains',
    type: 'tags',
    required: true,
    placeholder: 'www.example.com',
    hint: 'The DNS names in the certificate, the first one its subject. Each must resolve to an address of the interface below. No wildcards.',
  },
  {
    key: 'interface_id',
    label: 'Interface',
    type: 'select',
    items: () => ifaceItems.value,
    required: true,
    hint: "Where the CA's HTTP-01 requests come in. Port 80 is opened on it only while a challenge is answered.",
  },
  {
    key: 'email',
    label: 'Email',
    placeholder: 'admin@example.com',
    hint: "The ACME account's contact. Optional.",
  },
  {
    key: 'ca',
    label: 'CA',
    type: 'select',
    items: cas.value.map((c) => ({ label: c.label, value: c.name })),
    hint: 'Try the staging CA first: its test certificates are not trusted, but its rate limits are much higher.',
  },
  {
    key: 'key_type',
    label: 'Key type',
    type: 'select',
    items: [
      { label: 'ECDSA P-256', value: 'ec256' },
      { label: 'ECDSA P-384', value: 'ec384' },
      { label: 'RSA 2048', value: 'rsa2048' },
      { label: 'RSA 3072', value: 'rsa3072' },
      { label: 'RSA 4096', value: 'rsa4096' },
    ],
  },
  {
    key: 'challenge',
    label: 'Challenge',
    type: 'select',
    items: [{ label: 'HTTP-01 (port 80)', value: 'http-01' }],
  },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
])
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="Certificates"
      noun="certificate"
      description="TLS certificates from Let's Encrypt (ACME), got by the firewall and renewed when two thirds of their lifetime have passed. The CA checks each domain over HTTP on port 80, which the firewall opens on the certificate's interface only while it answers. To serve the GUI itself with one, set tls_certificate: <instance>/<name> in web.yaml."
      :api="certificates"
      :params="{ instance_id: store.currentId }"
      :columns="columns"
      :fields="fields"
      :defaults="{
        enabled: true,
        domains: [],
        ca: 'letsencrypt',
        key_type: 'ec256',
        challenge: 'http-01',
      }"
      new-label="New certificate"
      :search-text="(row) => valuesText(states[row.name])"
    >
      <template #cell-state="{ row }">
        <div v-if="states[row.name]" class="space-y-0.5 text-xs">
          <UBadge
            :color="stateColor[states[row.name].state] ?? 'neutral'"
            variant="subtle"
            size="sm"
          >
            {{ states[row.name].state }}
          </UBadge>
          <div v-if="states[row.name].not_after">
            valid until {{ when(states[row.name].not_after) }}
          </div>
          <div v-if="states[row.name].issuer" class="text-muted">
            {{ states[row.name].issuer }}
          </div>
          <div v-if="states[row.name].last_attempt" class="text-muted">
            ordered {{ ago(states[row.name].last_attempt) }}
          </div>
          <div v-if="states[row.name].last_error" class="text-error">
            {{ states[row.name].last_error }}
          </div>
          <div class="font-mono text-muted">{{ states[row.name].dir }}</div>
        </div>
        <span v-else class="text-xs text-muted">not deployed</span>
      </template>
    </CrudPage>
  </NeedInstance>
</template>
