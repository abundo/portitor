<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import CrudPage from '@/components/CrudPage.vue'
import { api, firewalls } from '@/api'
import { errMsg } from '@/api/http'
import { useConfirm } from '@/composables/useConfirm'
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

// inPair: the firewall is a primary or a secondary.
const inPair = (f) => !!f.id && (!!f.ha_primary_id || isPrimary(f))
const when = (t) => (t ? new Date(t).toLocaleString() : '')
const stateText = {
  active: 'active: open, forwarding and answering for the pair\'s addresses',
  standby: 'standby: closed, ready to take over',
  fenced: 'fenced: closed, hears neither its peer nor the witness',
  stale: 'stale: closed, its peer was promoted while it was away',
}
// haRows: what the host says of its place in the pair.
function haRows(f) {
  const ha = statusOf(f.id)?.ha
  if (!ha?.node) return []
  const rows = [
    ['State', stateText[ha.state] || ha.state],
    ['Peer', (ha.peer_alive ? 'alive' : 'not heard') + (ha.peer_seen ? `, last heard ${when(ha.peer_seen)}` : '')],
    ['Witness vote', ha.vote_until ? `until ${when(ha.vote_until)}` : 'none'],
    ['Monitored interfaces', `${ha.health} of ${ha.monitored} up, peer ${ha.peer_health}`],
    ['Watchdog', ha.watchdog || ''],
    ['Term', String(ha.term ?? '')],
  ]
  for (const d of ha.dhcp || []) {
    const parts = []
    if (d.error) parts.push(`not sent: ${d.error}`)
    if (d.sent) parts.push(`sent to the peer ${when(d.sent)}`)
    if (d.received) parts.push(`received from the peer ${when(d.received)}`)
    rows.push([`DHCP leases, ${d.instance}`, parts.join('; ') || 'nothing sent or received yet'])
  }
  return rows
}
const switching = ref(false)
async function switchover(f) {
  const yes = await useConfirm().ask({
    title: 'Switch over',
    message: 'Hand the pair over to its standby?',
    detail:
      'The active host closes and the standby opens at once, with the same addresses; clients lose a packet or two. There is no automatic switch back.',
  })
  if (!yes) return
  switching.value = true
  try {
    const r = await api.haSwitchover(f.id)
    toast.add({ title: `${r.from} handed over to its standby`, color: 'success' })
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    switching.value = false
  }
}

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
      return `${role} · ${ha.state}${ha.peer_alive ? '' : ', peer gone'}`
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
    hint: "Letters, digits, '-', '_' and '.', max 63. Its host becomes a virtual firewall of this name.",
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
    hint: "Makes it the HA secondary of that firewall: it runs the primary's virtual firewalls and tasks, with the same addresses, and a commit deploys to both. Only its management interface has addresses of its own (HA peer addresses under Network → Interfaces); on the HA link the hosts use IPv6 link-local addresses by role. Set when the firewall is created.",
  },
  {
    key: 'ha_state',
    label: 'HA state',
    type: 'custom',
    show: inPair,
  },
  {
    key: 'agent_url',
    label: 'Agent URL',
    placeholder: 'https://192.168.1.1:8443',
    hint: "Its address on the network, which its HA peer and the witness use too: in a pair, its management address (not 127.0.0.1). portitor-config reaches its own host's agent at the agent_url in its config.yaml.",
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
    hint: "The pair's third vote, which a host needs to open when it doesn't hear its peer. This firewall's portitor-config goes with this host: when it is lost, nothing takes over by itself (open the other by hand with portitor request ha active, or promote it). An external witness (portitor-web, or portitor-web witness, on a third host on the management network) gets the witness string below, and fails over by itself; commit after changing this.",
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
    <template #field-ha_state="{ form }">
      <div class="space-y-2">
        <table v-if="haRows(form).length" class="text-sm">
          <tbody>
            <tr v-for="[k, v] in haRows(form)" :key="k">
              <td class="py-1 pr-4 align-top text-muted whitespace-nowrap">{{ k }}</td>
              <td class="py-1">{{ v }}</td>
            </tr>
          </tbody>
        </table>
        <p v-else class="text-sm text-muted">Not known: the agent doesn't answer, or the pair isn't committed yet.</p>
        <UButton
          size="xs"
          variant="outline"
          icon="i-lucide-arrow-left-right"
          label="Switch over"
          :loading="switching"
          @click="switchover(form)"
        />
      </div>
    </template>
    <template #cell-ha_primary_id="{ row }">
      <span :class="['fenced', 'stale'].includes(statusOf(row.id)?.ha?.state) ? 'text-error' : ''">
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
