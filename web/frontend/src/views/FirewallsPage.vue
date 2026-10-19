<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed } from 'vue'
import CrudPage from '@/components/CrudPage.vue'
import DriftPanel from '@/components/DriftPanel.vue'
import { firewalls } from '@/api'
import { useDeployStore } from '@/stores/deploy'
import { useInstanceStore } from '@/stores/instances'

const deploy = useDeployStore()
const instStore = useInstanceStore()

// The agent's answer in the last status poll, by firewall id.
// The firewalls with portitor-config, each with its drift.
const withConfig = computed(() => instStore.firewalls.filter((f) => f.config_url))
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
  { key: 'agent_url', label: 'Agent URL', placeholder: 'https://192.168.1.1:8443' },
  {
    key: 'ha_url',
    label: 'HA URL',
    placeholder: 'agent URL',
    show: (f) => !!f.ha_primary_id || instStore.firewalls.some((x) => x.ha_primary_id === f.id),
    hint: "The agent URL its HA peer reaches it at, when portitor-web's differs (127.0.0.1, say). Empty: the agent URL.",
  },
  {
    key: 'config_url',
    label: 'portitor-config URL',
    placeholder: 'https://192.168.1.1:8444',
    hint: "The firewall's own portitor-config: its virtual firewalls are pushed there and committed through it, the agent asked for live data only. Empty: deployed to the agent.",
  },
  {
    key: 'config_token',
    label: 'portitor-config token',
    type: 'password',
    show: (f) => !!f.config_url,
    hint: 'Its manager_token_file. Stored on the server, never shown again; leave empty to keep it.',
  },
  {
    key: 'config_fingerprint',
    label: 'portitor-config fingerprint',
    show: (f) => !!f.config_url,
    hint: "Pins portitor-config's certificate (SHA-256). Empty: verify against system CAs.",
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
    description="The hosts Portitor deploys to, each through its agent. Run portitor-agent init --host <address> on a firewall; it prints the token and the certificate fingerprint. Each firewall's host is a virtual firewall of its own; the others are put on a firewall in their form. A commit deploys to every firewall whose configuration changed."
    :api="firewalls"
    shared
    noun="firewall"
    :columns="columns"
    :fields="fields"
    new-label="New firewall"
    @changed="instStore.load()"
  >
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
  <DriftPanel v-for="f in withConfig" :key="f.id" :firewall="f" class="mt-4" />
</template>
