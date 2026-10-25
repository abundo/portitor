<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import CrudPage from '@/components/CrudPage.vue'
import { api, firewalls } from '@/api'
import { errMsg } from '@/api/http'
import { useDeployStore } from '@/stores/deploy'
import { useInstanceStore } from '@/stores/instances'

const deploy = useDeployStore()
const instStore = useInstanceStore()

const toast = useToast()
// isPrimary: the firewall has an HA secondary.
const isPrimary = (f) => !!f.id && instStore.firewalls.some((x) => x.ha_primary_id === f.id)
// The pair's witness string, for its external witness.
const witness = ref('')
async function showWitness(f) {
  try {
    witness.value = await api.witnessString(f.id)
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
async function copyWitness() {
  await navigator.clipboard.writeText(witness.value)
  toast.add({ title: 'Witness string copied', color: 'success' })
}

// The agent's answer in the last status poll, by firewall id.
const statusOf = (id) => deploy.status?.firewalls?.find((f) => f.id === id)

const columns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'agent_url', label: 'Agent', class: 'font-mono text-xs' },
  {
    key: 'status',
    label: 'Status',
    format: (r) => {
      const st = statusOf(r.id)
      if (!st) return ''
      return st.error || [st.hostname, st.version].filter(Boolean).join(' · ')
    },
  },
  {
    key: 'ha_primary_id',
    label: 'HA',
    format: (r) => {
      let role = ''
      if (r.ha_primary_id) role = `secondary of ${instStore.firewallName(r.ha_primary_id)}`
      const sec = instStore.firewalls.find((f) => f.ha_primary_id === r.id)
      if (sec) role = `primary of ${sec.name}`
      const ha = statusOf(r.id)?.ha
      if (!role || !ha) return role
      if (ha.fenced) return `${role} · fenced`
      return `${role} · ${ha.peer_alive ? 'peer alive' : 'peer gone, witness vote'}`
    },
  },
  { key: 'generation', label: 'Generation' },
  { key: 'description', label: 'Description' },
]

const fields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'branch',
    hint: 'Lowercase letters and digits, max 12. Its host becomes a virtual firewall of this name.',
  },
  { key: 'description', label: 'Description' },
  {
    key: 'ha_primary_id',
    label: 'HA secondary of',
    type: 'select',
    nullable: true,
    items: (f) =>
      instStore.firewalls
        .filter((x) => x.id !== f.id && !x.ha_primary_id)
        .map((x) => ({ label: x.name, value: x.id })),
    disabled: (f) => !!f.id,
    hint: "Makes it the HA secondary of that firewall: it runs the primary's virtual firewalls and tasks, with the peer values (addresses, VRRP priority, router ids) where the two differ, and a commit deploys to both. Set when the firewall is created.",
  },
  {
    key: 'agent_url',
    label: 'Agent URL',
    placeholder: 'https://192.168.1.1:8443',
    hint: "Its address on the network, which its HA peer uses too (not 127.0.0.1 in a pair). portitor-config reaches its own host's agent at the agent_url in its config.yaml.",
  },
  {
    key: 'ha_witness',
    label: 'HA witness',
    type: 'select',
    items: [
      { label: "This firewall's portitor-config", value: 'local' },
      { label: 'External: portitor-web on a third host', value: 'external' },
    ],
    show: isPrimary,
    hint: "The pair's third vote. Its portitor-config here keeps the pair active while the two can't hear each other, but goes with this host: without an external witness the secondary stays fenced when this one is lost, until it is promoted. An external witness (portitor-web, or portitor-web witness, on another host) gets the witness string below; commit after changing this.",
  },
  {
    key: 'witness_string',
    label: 'Witness string',
    type: 'custom',
    show: (f) => isPrimary(f) && f.ha_witness === 'external',
  },
  {
    key: 'config_url',
    label: 'portitor-config URL',
    placeholder: 'https://192.168.1.1:8444',
    show: (f) => !!f.ha_primary_id || instStore.firewalls.some((x) => x.ha_primary_id === f.id),
    hint: "This host's portitor-config as its HA peer reaches it. The secondary copies the primary's configuration from there, and either takes it over when promoted.",
  },
  {
    key: 'config_fingerprint',
    label: 'portitor-config fingerprint',
    show: (f) => !!f.ha_primary_id || instStore.firewalls.some((x) => x.ha_primary_id === f.id),
    hint: 'Pins its certificate (SHA-256 of its tls_cert): portitor-config fingerprint on that host.',
  },
  {
    key: 'agent_token',
    label: 'Token',
    type: 'password',
    hint: 'From portitor-agent init on the firewall. Stored on the server, never shown again; leave empty to keep the stored token.',
  },
  {
    key: 'agent_fingerprint',
    label: 'Certificate fingerprint (SHA-256)',
    hint: "Pins the agent's self-signed certificate. Empty: verify against system CAs.",
  },
]
</script>

<template>
  <CrudPage
    title="Firewalls"
    description="This firewall and its HA secondary, each through its agent: portitor-config deploys to its own firewall and its secondary only. portitor-agent init on a host prints its agent's token and certificate fingerprint. The firewall's host is a virtual firewall of its own."
    :api="firewalls"
    shared
    noun="firewall"
    :columns="columns"
    :fields="fields"
    new-label="New firewall"
    @changed="instStore.load()"
  >
    <template #field-witness_string="{ form }">
      <div class="space-y-2">
        <div class="flex gap-2">
          <UButton size="xs" variant="outline" label="Show" @click="showWitness(form)" />
          <UButton
            v-if="witness"
            size="xs"
            variant="outline"
            icon="i-lucide-copy"
            label="Copy"
            @click="copyWitness"
          />
        </div>
        <p v-if="witness" class="font-mono text-xs break-all">{{ witness }}</p>
        <p class="text-xs text-muted">
          Under witness: in portitor-web's web.yaml on the third host. It holds the witness secret,
          which opens the vote alone.
        </p>
      </div>
    </template>
    <template #cell-ha_primary_id="{ row }">
      <span :class="statusOf(row.id)?.ha?.fenced ? 'text-error' : ''">
        {{ columns.find((c) => c.key === 'ha_primary_id').format(row) }}
      </span>
    </template>
    <template #cell-status="{ row }">
      <span :class="statusOf(row.id)?.error ? 'text-error' : 'text-muted'">
        {{ columns.find((c) => c.key === 'status').format(row) }}
      </span>
    </template>
  </CrudPage>
</template>
