<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import RulesTable from '@/components/RulesTable.vue'
import { ref, watch } from 'vue'
import { api as backend, rules } from '@/api'
import { useInstanceRefs } from '@/composables/useInstanceRefs'

const { store, ifaceRefItems } = useInstanceRefs()

// Input rules for DHCP, DNS and WireGuard come from the services'
// configuration; they are shown read-only above the input rules.
const autoRules = ref([])
async function loadAutoRules() {
  if (!store.currentId) return
  autoRules.value = await backend.autoRules(store.currentId).catch(() => [])
}
watch(() => store.currentId, loadAutoRules, { immediate: true })
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
    key: 'protocol',
    label: 'Protocol',
    type: 'select',
    items: opt(['any', 'tcp', 'udp', 'icmp', 'icmpv6']),
  },
  {
    key: 'dst_ports',
    label: 'Destination ports',
    placeholder: '22, 80-90',
    show: (f) => f.protocol === 'tcp' || f.protocol === 'udp',
  },
  {
    key: 'src_addrs',
    label: 'Source addresses',
    type: 'addrs',
    placeholder: '192.168.1.0/24 or a name',
  },
  {
    key: 'dst_addrs',
    label: 'Destination addresses',
    type: 'addrs',
    placeholder: '192.168.1.10 or a name',
    hint: 'Addresses, CIDRs or hosts/prefixes. With IPv4 and IPv6 entries the rule applies to both.',
  },
  { key: 'action', label: 'Action', type: 'select', items: opt(['accept', 'drop', 'reject']) },
  { key: 'log', label: 'Log matches', type: 'switch' },
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

// Selects can't hold '' values; map 'any' <-> ''.
const api = {
  ...rules,
  list: async (p) => (await rules.list(p)).map(fromApi),
  create: (b) => rules.create(clean(b)),
  update: async (id, b) => fromApi(await rules.update(id, clean(b))),
}
function fromApi(r) {
  return { ...r, family: r.family || 'any', protocol: r.protocol || 'any' }
}
function clean(b) {
  return {
    ...b,
    family: b.family === 'any' ? '' : b.family,
    protocol: b.protocol === 'any' ? '' : b.protocol,
  }
}
</script>

<template>
  <NeedInstance>
    <CrudPage
      title="Rules"
      description="Evaluated top to bottom; the first match decides. Edit cells in place (changes save at once), drag the grip to reorder. Established connections are allowed, and so is what the configured services (DHCP, DNS, WireGuard) need: those input rules are shown locked and follow the services' settings. In the default instance the agent's management port stays open to its allow_from addresses. Traffic to or through the firewall that no rule accepts is dropped."
      :api="api"
      :params="{ instance_id: store.currentId }"
      :columns="[]"
      :fields="fields"
      :defaults="{
        chain: 'forward',
        family: 'any',
        protocol: 'any',
        action: 'accept',
        enabled: true,
        log: false,
        in_interfaces: [],
        out_interfaces: [],
        src_addrs: [],
        dst_addrs: [],
      }"
      new-label="New rule"
      reorder="rules"
      :item-name="(r) => `rule ${r.description || r.id}`"
    >
      <template #table="{ rows, openCreate, openEdit, remove, moveTo, saveRow }">
        <div class="space-y-6">
          <section v-for="c in chains" :key="c.value">
            <div class="mb-2 flex items-end justify-between gap-3">
              <div>
                <div class="font-semibold">{{ c.title }}</div>
                <p class="text-sm text-muted">{{ c.text }}</p>
              </div>
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
              @save="saveRow"
              @move="(from, to) => moveInChain(rows, c.value, moveTo, from, to)"
              @edit="openEdit"
              @remove="remove"
            />
          </section>
        </div>
      </template>
    </CrudPage>
  </NeedInstance>
</template>
