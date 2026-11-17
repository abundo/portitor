<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import CrudPage from '@/components/CrudPage.vue'
import HAPairs from '@/components/HAPairs.vue'
import { api, firewalls } from '@/api'
import { errMsg } from '@/api/http'
import { config, path } from '@/api/config'
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
  active: "active: open, forwarding and answering for the pair's addresses",
  standby: 'standby: ready to take over',
  fenced: 'fenced: hears neither its peer nor the witness, so it does not take over',
  stale: 'stale: replaced by a promotion while it was away',
}
// haRows: what the host says of its place in the pair.
function haRows(f) {
  const ha = statusOf(f.id)?.ha
  if (!ha?.node) return []
  const rows = [
    ['State', stateText[ha.state] || ha.state],
    [
      'Peer',
      (ha.peer_alive ? 'alive' : 'not heard') +
        (ha.peer_seen ? `, last heard ${when(ha.peer_seen)}` : ''),
    ],
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
    message: 'Hand the cluster over to its standby?',
    detail:
      'The standby becomes active at once, with the same addresses; clients lose a packet or two.',
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

// The pair's check (the firewall's check action) and the switchover test.
const checked = ref(null)
const checking = ref(false)
const icon = {
  ok: 'i-lucide-circle-check',
  warn: 'i-lucide-triangle-alert',
  fail: 'i-lucide-circle-x',
}
const tone = { ok: 'text-success', warn: 'text-warning', fail: 'text-error' }
const pairPath = (f) => path(['firewall', f.name])
async function checkPair(f) {
  checking.value = true
  try {
    checked.value = await config.view(pairPath(f), 'check')
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    checking.value = false
  }
}
const testing = ref(false)
async function testSwitchover(f) {
  const yes = await useConfirm().ask({
    title: 'Test switchover',
    message: 'Switch the cluster over to its standby and back?',
    detail:
      'Only when the check says the cluster can fail over. The active firewall hands over, and back after a few seconds; clients lose a packet or two each time.',
  })
  if (!yes) return
  testing.value = true
  try {
    const r = await config.action(pairPath(f), 'test-switchover')
    toast.add({
      title: `Switched to ${r.to} in ${r['there-ms']} ms and back to ${r.from} in ${r['back-ms']} ms`,
      description: 'Until the other firewall was active, as the agents tell it.',
      color: 'success',
    })
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    testing.value = false
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
    label: 'Cluster',
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
    label: 'Cluster secondary of',
    type: 'select',
    nullable: true,
    items: (f) =>
      instStore.firewalls
        .filter((x) => x.id !== f.id && !x.ha_primary_id)
        .map((x) => ({ label: x.name, value: x.id })),
    disabled: (f) => !!f.id,
    hint: "Makes it the secondary of that firewall in a firewall cluster: it runs the primary's virtual firewalls and tasks, with the same addresses, and a commit deploys to both. Only its management interface has addresses of its own (Cluster peer addresses under Network → Interfaces). Set when the firewall is created.",
  },
  {
    key: 'ha_state',
    label: 'Cluster state',
    type: 'custom',
    show: inPair,
  },
  {
    key: 'agent_url',
    label: 'Agent URL',
    placeholder: 'https://192.168.1.1:8443',
    hint: "Its address on the network, which its cluster peer and the witness use too: in a cluster, its management address (not 127.0.0.1). portitor-config reaches its own host's agent at the agent_url in its config.yaml.",
  },
  {
    key: 'ha_witness',
    label: 'Cluster witness',
    type: 'select',
    items: [
      { label: "This firewall's portitor-config", value: 'local' },
      { label: 'External: portitor-manager on a third host', value: 'external' },
    ],
    show: isPrimary,
    hint: "The cluster's third vote, which a standby needs to become active when it can't hear its peer. This firewall's portitor-config goes down with this firewall: when it is lost, nothing takes over by itself (see the cluster runbook). An external witness (portitor-manager on a third host on the management network) gets the witness string below, and the cluster fails over by itself; commit after changing this.",
  },
  {
    key: 'ha_preempt',
    label: 'Primary takes over again',
    type: 'switch',
    show: isPrimary,
    hint: 'When the secondary is active and this primary is back and healthy for 30 s, the secondary hands over to it. The configuration is edited on the primary: while the secondary is active its portitor-config is a read-only replica. Commit after changing this.',
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
    hint: "This firewall's portitor-config as its cluster peer reaches it. The secondary copies the primary's configuration from there, and either takes it over when promoted.",
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
  <div class="space-y-6">
    <CrudPage
      title="Firewalls"
      description="This firewall and its cluster secondary, each through its agent: portitor-config deploys to its own firewall and its secondary only. portitor-agent init on a host prints its agent's token and certificate fingerprint. The firewall's host is a virtual firewall of its own."
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
            In portitor-manager on the third host (Cluster witness, or portitor-manager
            add-witness). It holds the witness secret, which opens the vote alone.
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
          <p v-else class="text-sm text-muted">
            Not known: the agent doesn't answer, or the cluster isn't committed yet.
          </p>
          <div class="flex flex-wrap gap-2">
            <UButton
              size="xs"
              variant="outline"
              icon="i-lucide-arrow-left-right"
              label="Switch over"
              :loading="switching"
              @click="switchover(form)"
            />
            <UButton
              size="xs"
              variant="outline"
              icon="i-lucide-list-checks"
              label="Check cluster"
              :loading="checking"
              @click="checkPair(form)"
            />
            <UButton
              size="xs"
              variant="outline"
              icon="i-lucide-flask-conical"
              label="Test switchover"
              :loading="testing"
              @click="testSwitchover(form)"
            />
          </div>
          <table v-if="checked" class="text-sm">
            <tbody>
              <tr v-for="c in checked.checks" :key="c.name">
                <td class="py-1 pr-2 align-top">
                  <UIcon :name="icon[c.status]" :class="['size-4', tone[c.status]]" />
                </td>
                <td class="py-1">{{ c.message }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
      <template #cell-ha_primary_id="{ row }">
        <span
          :class="['fenced', 'stale'].includes(statusOf(row.id)?.ha?.state) ? 'text-error' : ''"
        >
          {{ columns.find((c) => c.key === 'ha_primary_id').format(row) }}
        </span>
      </template>
      <template #cell-status="{ row }">
        <span :class="statusOf(row.id)?.error ? 'text-error' : 'text-muted'">
          {{ columns.find((c) => c.key === 'status').format(row) }}
        </span>
      </template>
    </CrudPage>
    <HAPairs />
  </div>
</template>
