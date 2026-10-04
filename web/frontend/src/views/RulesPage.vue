<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import NatTable from '@/components/NatTable.vue'
import NftImportDialog from '@/components/NftImportDialog.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import RulesTable from '@/components/RulesTable.vue'
import { onMounted, onUnmounted, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api as backend, instances, rateLimits, rules } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useObjectStore } from '@/stores/objects'
import { useAuthStore } from '@/stores/auth'
import { useDeployStore } from '@/stores/deploy'
import { autoDescription, autoFamily, autoService } from '@/utils/services'

const { store, ifaceRefItems } = useInstanceRefs()
const objects = useObjectStore()
const auth = useAuthStore()
const deploy = useDeployStore()
onMounted(() => objects.load().catch(() => {}))

// Input rules for DHCP, DNS and WireGuard come from the services'
// configuration; they are shown read-only above the input rules.
const autoRules = ref([])
async function loadAutoRules() {
  if (!store.currentId) return
  autoRules.value = await backend.autoRules(store.currentId).catch(() => [])
}
watch(() => store.currentId, loadAutoRules, { immediate: true })
// The instance's rate limits, for the rule form (Rate limits page).
const limits = ref([])
async function loadLimits() {
  if (!store.currentId) return
  limits.value = await rateLimits.list({ instance_id: store.currentId }).catch(() => [])
}
watch(() => store.currentId, loadLimits, { immediate: true })
// lockedRow shows a locked row of a chain's table in the rule form
// (read-only): an auto rule, or { builtin } for the invalid packets, the port
// forwards' accept or the policy. What it matches takes the Services field's
// place.
const builtins = {
  invalid: {
    match: 'ct state invalid',
    action: 'drop',
    description: 'invalid: no known connection, dropped before the rules',
  },
  dnat: {
    match: 'ct status dnat',
    action: 'accept',
    description: 'port forwards: connections to a port forward that no rule above decided on',
  },
  policy: {
    match: 'no rule matched',
    action: 'drop',
    description: "policy: traffic no rule accepted, dropped by the chain's policy",
  },
}
function lockedRow(chain, a) {
  const row = {
    chain,
    in_interfaces: [],
    out_interfaces: [],
    family: 'any',
    services: [],
    src_addrs: [],
    dst_addrs: [],
    enabled: true,
  }
  const b = builtins[a.builtin]
  if (b) {
    const log = { invalid: 'log_invalid', policy: 'log_drops' }[a.builtin]
    return {
      ...row,
      match: b.match,
      action: b.action,
      log: !!log && (store.current?.[log] ?? []).includes(chain),
      description: `auto: ${b.description}`,
    }
  }
  const family = autoFamily(a)
  return {
    ...row,
    match: autoService(a),
    in_interfaces: a.in_interfaces ?? [],
    family: family === 'any' ? 'any' : family.toLowerCase(),
    src_addrs: a.source ?? [],
    action: 'accept',
    log: (store.current?.log_auto ?? []).includes(a.service),
    description: `auto: ${autoDescription(a)}`,
  }
}
// Traffic per rule id since the last deploy (agentapi.RuleCounters) and
// the chains' own drops per instance name and chain (agentapi.ChainDrops),
// polled every 5 seconds while the page is open and visible; null when the
// agent can't be reached.
const counters = ref(null)
const drops = ref(null)
let countersTimer = null
let polling = false
async function pollCounters() {
  if (!document.hidden) {
    const r = await backend.agentRuleCounters().catch(() => null)
    counters.value = r ? (r.rules ?? {}) : null
    drops.value = r ? (r.drops ?? {}) : null
  }
  if (polling) countersTimer = setTimeout(pollCounters, 5000)
}
onMounted(() => {
  polling = true
  pollCounters()
})
onUnmounted(() => {
  polling = false
  clearTimeout(countersTimer)
})

// The locked rows have a Log box too, kept in the instance: log_drops and
// log_invalid list the chains that log what no rule matched and their
// invalid packets, log_auto the services of the auto rules that log.
const toast = useToast()

// Export: the nftables ruleset as the agent renders it, live or uncommitted.
const exportItems = [
  [
    { label: 'Live ruleset', onSelect: () => exportNftables('live') },
    { label: 'With uncommitted changes', onSelect: () => exportNftables('') },
  ],
]
// Import (a global admin's: it creates shared hosts/prefixes and services).
const importOpen = ref(false)
const page = ref(null)
const natKey = ref(0)
async function imported() {
  await page.value?.reload()
  natKey.value++
  deploy.changed()
}

async function exportNftables(from) {
  const name = store.current?.name
  if (!name) return
  try {
    const res = await backend.exportNftables(name, from)
    const url = URL.createObjectURL(res.data)
    const a = document.createElement('a')
    a.href = url
    a.download = `${name}.nft`
    a.click()
    URL.revokeObjectURL(url)
  } catch (err) {
    let msg = errMsg(err)
    const data = err?.response?.data
    if (data instanceof Blob)
      msg =
        (await data
          .text()
          .then((t) => JSON.parse(t).error)
          .catch(() => null)) ?? msg
    toast.add({ title: msg, color: 'error' })
  }
}
const logField = { policy: 'log_drops', invalid: 'log_invalid', auto: 'log_auto' }
const logBuiltin = (chain) => ({
  policy: (store.current?.log_drops ?? []).includes(chain),
  invalid: (store.current?.log_invalid ?? []).includes(chain),
  auto: store.current?.log_auto ?? [],
})
async function setLogBuiltin(chain, builtin, service, on) {
  const cur = store.current
  if (!cur) return
  const field = logField[builtin]
  const item = builtin === 'auto' ? service : chain
  const list = (cur[field] ?? []).filter((v) => v !== item)
  if (on) list.push(item)
  try {
    await instances.update(cur.id, { [field]: list })
  } catch (err) {
    toast.add({ title: errMsg(err, 'Save failed'), color: 'error' })
  }
  await store.load()
}

const opt = (list) => list.map((v) => ({ label: v || 'any', value: v }))

const fields = [
  {
    key: 'chain',
    label: 'Chain',
    type: 'select',
    items: [
      { label: 'forward: through the firewall', value: 'forward' },
      { label: 'input: to the firewall itself', value: 'input' },
      { label: 'output: from the firewall itself', value: 'output' },
    ],
  },
  {
    key: 'in_interfaces',
    label: 'Incoming interfaces',
    type: 'multiselect',
    items: () => ifaceRefItems.value,
    placeholder: 'any',
    show: (f) => f.chain !== 'output',
  },
  {
    key: 'out_interfaces',
    label: 'Outgoing interfaces',
    type: 'multiselect',
    items: () => ifaceRefItems.value,
    placeholder: 'any',
    show: (f) => f.chain !== 'input',
    hint: 'Interfaces and interface zones; empty matches any.',
  },
  {
    key: 'family',
    label: 'IP version',
    type: 'select',
    items: [
      { label: 'any', value: 'any' },
      { label: 'IPv4', value: 'ipv4' },
      { label: 'IPv6', value: 'ipv6' },
    ],
    hint: 'The addresses already decide it; needed only when they are any or IP lists.',
  },
  {
    key: 'services',
    label: 'Services',
    type: 'multiselect',
    items: () => objects.serviceItems,
    placeholder: 'any',
    show: (f) => !f.match,
    hint: 'The traffic must match one of them; empty matches any protocol. Services are defined on the Services page.',
  },
  {
    key: 'match',
    label: 'Match',
    type: 'custom',
    show: (f) => !!f.match,
    hint: 'Added by Portitor; the services and the virtual firewall settings decide it.',
  },
  {
    key: 'src_addrs',
    label: 'Source addresses',
    type: 'addrs',
    lists: true,
    placeholder: '192.168.1.0/24, a name or @list',
  },
  {
    key: 'dst_addrs',
    label: 'Destination addresses',
    type: 'addrs',
    lists: true,
    placeholder: '192.168.1.10, a name or @list',
    hint: 'Addresses, CIDRs, hosts/prefixes or IP lists (@name). With IPv4 and IPv6 entries, or an IP list, the rule applies to both.',
  },
  { key: 'action', label: 'Action', type: 'select', items: opt(['accept', 'drop', 'reject']) },
  {
    key: 'rate_limit',
    label: 'Rate limit',
    type: 'select',
    nullable: true,
    text: true,
    items: () =>
      limits.value.map((l) => ({
        label: `${l.name} (${l.shape ? 'shape' : 'police'} ${l.rate} ${l.unit === 'mbit' ? 'Mbit' : l.unit === 'kbit' ? 'kbit' : l.unit || 'packets'}/s)`,
        value: l.name,
      })),
    show: (f) => !f.match,
    hint: 'When the rule matches, its traffic goes through the rate limit. Police drops what is over the rate; Shape (accept rules only) queues it. Rate limits are defined on the Rate limits page.',
  },
  {
    key: 'log',
    label: 'Log matches',
    type: 'switch',
    hint: "Every packet the rule matches is shown in the log panel's Logged packets tab.",
  },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  { key: 'description', label: 'Description' },
]

// One tab per hook, in the order packets pass them; forward opens first.
// Prerouting and postrouting hold the NAT rules.
const chains = [
  {
    value: 'prerouting',
    label: 'Prerouting',
    text: 'Before routing: port forwards (DNAT) rewrite the destination. Port-forwarded connections are accepted after the forward rules, so a forward rule can drop them.',
  },
  { value: 'input', label: 'Input', text: 'Traffic to the firewall itself.' },
  { value: 'forward', label: 'Forward', text: 'Traffic through the firewall.' },
  { value: 'output', label: 'Output', text: 'Traffic from the firewall itself.' },
  {
    value: 'postrouting',
    label: 'Postrouting',
    text: 'After routing: source NAT and masquerade rewrite the source, as for Internet sharing (masquerade out of the WAN).',
  },
]
const natHook = (c) => c.value === 'prerouting' || c.value === 'postrouting'
const chainTab = ref('forward')

// Each table shows one chain; a move within it becomes a move in the full
// list (rows keep one order across chains), before or after the target row.
function moveInChain(rows, chain, moveTo, from, to) {
  const sub = rows.filter((r) => r.chain === chain)
  moveTo(rows.indexOf(sub[from]), rows.indexOf(sub[to]))
}

// insertInChain adds a rule (through the form), a comment row or a group
// heading at index `at` of one chain's table, placed at the matching spot of
// the full list.
function insertInChain(rows, chain, { openCreate, createAt }, kind, at) {
  const sub = rows.filter((r) => r.chain === chain)
  let index = rows.length
  if (at < sub.length) index = rows.indexOf(sub[at])
  else if (sub.length) index = rows.indexOf(sub[sub.length - 1]) + 1
  if (kind !== 'rule') return createAt({ chain, kind, description: '' }, index)
  openCreate({ chain }, index)
  return null
}

// copyInChain adds a disabled copy of rule r at index `at` of its chain's
// table, so the copy changes nothing until it is turned on.
function copyInChain(rows, chain, createAt, r, at) {
  const sub = rows.filter((x) => x.chain === chain)
  const index = at < sub.length ? rows.indexOf(sub[at]) : rows.indexOf(sub[sub.length - 1]) + 1
  const body = { ...r, enabled: false }
  delete body.id
  delete body.position
  return createAt(clean(body), index)
}

// ruleName names a rule as its chain's table numbers it (comment and group
// rows left out), like the server's messages: "forward rule 2 (description)".
// A group is only its heading: deleting it keeps its rules.
function ruleName(r, rows) {
  if (r.kind === 'comment') return 'comment'
  if (r.kind === 'group') return `group ${r.description || '(unnamed)'} (its rules stay)`
  const sub = rows.filter((x) => x.chain === r.chain && !x.kind)
  const name = `${r.chain} rule ${sub.findIndex((x) => x.id === r.id) + 1}`
  return r.description ? `${name} (${r.description})` : name
}

// Selects can't hold '' values; map 'any' <-> ''.
const api = {
  ...rules,
  list: async (p) => (await rules.list(p)).map(fromApi),
  create: (b) => rules.create(clean(b)),
  update: async (id, b) => fromApi(await rules.update(id, clean(b))),
}
function fromApi(r) {
  return { ...r, family: r.family || 'any' }
}
function clean(b) {
  return {
    ...b,
    family: b.family === 'any' ? '' : b.family,
  }
}
</script>

<template>
  <NeedInstance>
    <CrudPage
      ref="page"
      title="Rules"
      info="Evaluated top to bottom; the first match decides. Edit cells in place (changes save at once), drag the grip to reorder, right-click a row to insert a rule, comment or group. Prerouting and postrouting hold the NAT rules: port forwards, and source NAT and masquerade. A group heads the rows below it up to the next group; its chevron folds them away (only in the view: folded rules still apply). Established connections are allowed, and so is what the configured services (DHCP, DNS, WireGuard) need: those input rules are shown locked and follow the services' settings. In the default virtual firewall the agent's management port and SSH stay open to its allow_from addresses. Port forwards are accepted after the forward rules (the locked row above the last one), so a forward rule can drop what a port forward would let in. Invalid packets (of no known connection) and traffic to or through the firewall that no rule accepts are dropped; the locked rows at the top and bottom of each chain count them."
      :api="api"
      :params="{ instance_id: store.currentId }"
      :columns="[]"
      :fields="fields"
      :defaults="{
        chain: 'forward',
        family: 'any',
        action: 'accept',
        enabled: false,
        log: false,
        in_interfaces: [],
        out_interfaces: [],
        src_addrs: [],
        dst_addrs: [],
        services: [],
        rate_limit: '',
      }"
      new-label=""
      reorder="rules"
      :item-name="ruleName"
    >
      <template #toolbar>
        <UButton
          v-if="auth.isAdmin"
          icon="i-lucide-upload"
          label="Import nftables"
          variant="outline"
          @click="importOpen = true"
        />
        <UDropdownMenu :items="exportItems">
          <UButton icon="i-lucide-download" label="Export nftables" variant="outline" />
        </UDropdownMenu>
      </template>
      <template #field-match="{ form }">
        <UInput :model-value="form.match" class="w-full" :ui="{ base: 'font-mono' }" />
      </template>
      <template
        #table="{ rows, openCreate, openEdit, openView, remove, moveTo, saveRow, createAt }"
      >
        <UTabs v-model="chainTab" :items="chains">
          <template #content="{ item: c }">
            <NatTable v-if="natHook(c)" :key="natKey" :hook="c.value" :description="c.text" />
            <template v-else>
              <div class="mb-2 flex items-end justify-between gap-3 pt-2">
                <p class="text-sm text-muted">{{ c.text }}</p>
                <UButton
                  v-if="auth.canEdit"
                  size="sm"
                  variant="soft"
                  icon="i-lucide-plus"
                  :label="`New ${c.value} rule`"
                  @click="openCreate({ chain: c.value })"
                />
              </div>
              <RulesTable
                :rows="rows.filter((r) => r.chain === c.value)"
                :chain="c.value"
                :auto="c.value === 'input' ? autoRules : []"
                :ifaces="ifaceRefItems"
                :counters="counters"
                :drops="drops && (drops[store.current?.name]?.[c.value] ?? {})"
                :log-builtin="logBuiltin(c.value)"
                :read-only="!auth.canEdit"
                :insert="
                  (kind, at) => insertInChain(rows, c.value, { openCreate, createAt }, kind, at)
                "
                :copy="(r, at) => copyInChain(rows, c.value, createAt, r, at)"
                @save="saveRow"
                @move="(from, to) => moveInChain(rows, c.value, moveTo, from, to)"
                @edit="openEdit"
                @view="(a) => openView(lockedRow(c.value, a))"
                @remove="remove"
                @log-builtin="(kind, service, on) => setLogBuiltin(c.value, kind, service, on)"
              />
            </template>
          </template>
        </UTabs>
      </template>
    </CrudPage>
    <NftImportDialog
      v-if="store.currentId"
      v-model:open="importOpen"
      :instance-id="store.currentId"
      :ifaces="ifaceRefItems"
      @imported="imported"
    />
  </NeedInstance>
</template>
