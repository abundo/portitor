<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import RulesTable from '@/components/RulesTable.vue'
import { onMounted, onUnmounted, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api as backend, instances, rules } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceRefs } from '@/composables/useInstanceRefs'
import { useObjectStore } from '@/stores/objects'

const { store, ifaceRefItems } = useInstanceRefs()
const objects = useObjectStore()
onMounted(() => objects.load().catch(() => {}))

// Input rules for DHCP, DNS and WireGuard come from the services'
// configuration; they are shown read-only above the input rules.
const autoRules = ref([])
async function loadAutoRules() {
  if (!store.currentId) return
  autoRules.value = await backend.autoRules(store.currentId).catch(() => [])
}
watch(() => store.currentId, loadAutoRules, { immediate: true })
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
  },
  {
    key: 'services',
    label: 'Services',
    type: 'multiselect',
    items: () => objects.serviceItems,
    placeholder: 'any',
    hint: 'The traffic must match one of them; empty matches any protocol. Services are defined on the Services page.',
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
    key: 'log',
    label: 'Log matches',
    type: 'switch',
    hint: "Every packet the rule matches is shown in the log panel's Logged packets tab.",
  },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
  { key: 'description', label: 'Description' },
]

const chains = [
  { value: 'input', title: 'Input', text: 'Traffic to the firewall itself.' },
  { value: 'forward', title: 'Forward', text: 'Traffic through the firewall.' },
  { value: 'output', title: 'Output', text: 'Traffic from the firewall itself.' },
]

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
      title="Rules"
      info="Evaluated top to bottom; the first match decides. Edit cells in place (changes save at once), drag the grip to reorder, right-click a row to insert a rule, comment or group. A group heads the rows below it up to the next group; its chevron folds them away (only in the view: folded rules still apply). Established connections are allowed, and so is what the configured services (DHCP, DNS, WireGuard) need: those input rules are shown locked and follow the services' settings. In the default instance the agent's management port stays open to its allow_from addresses. Invalid packets (of no known connection) and traffic to or through the firewall that no rule accepts are dropped; the locked rows at the top and bottom of each chain count them."
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
      }"
      new-label="New rule"
      reorder="rules"
      :item-name="ruleName"
    >
      <template #table="{ rows, openCreate, openEdit, remove, moveTo, saveRow, createAt }">
        <div class="space-y-6">
          <section v-for="c in chains" :key="c.value">
            <div class="mb-2 flex items-end justify-between gap-3">
              <p>
                <span class="font-semibold">{{ c.title }}</span>
                <span class="ms-2 text-sm text-muted">{{ c.text }}</span>
              </p>
              <UButton
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
              :insert="
                (kind, at) => insertInChain(rows, c.value, { openCreate, createAt }, kind, at)
              "
              @save="saveRow"
              @move="(from, to) => moveInChain(rows, c.value, moveTo, from, to)"
              @edit="openEdit"
              @remove="remove"
              @log-builtin="(kind, service, on) => setLogBuiltin(c.value, kind, service, on)"
            />
          </section>
        </div>
      </template>
    </CrudPage>
  </NeedInstance>
</template>
