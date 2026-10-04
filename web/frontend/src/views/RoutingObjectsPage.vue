<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- Routing objects: the route maps, prefix lists, community lists and
     AS path lists of this virtual firewall, which BGP refers to by name. -->
<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import CrudPage from '@/components/CrudPage.vue'
import EntriesEditor from '@/components/EntriesEditor.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import RouteMapEntries from '@/components/RouteMapEntries.vue'
import { asPathLists, communityLists, prefixLists, routeMaps } from '@/api'
import { useRoutingObjects } from '@/composables/useRoutingObjects'
import { useAuthStore } from '@/stores/auth'
import { useInstanceStore } from '@/stores/instances'

const route = useRoute()
const router = useRouter()
const store = useInstanceStore()
const auth = useAuthStore()
const objects = useRoutingObjects()

const tabs = [
  { label: 'Route maps', value: 'maps', slot: 'maps', icon: 'i-lucide-map' },
  { label: 'Prefix lists', value: 'prefix', slot: 'prefix', icon: 'i-lucide-list' },
  { label: 'Community lists', value: 'community', slot: 'community', icon: 'i-lucide-tags' },
  { label: 'AS path lists', value: 'aspath', slot: 'aspath', icon: 'i-lucide-route' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'maps'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'maps' ? undefined : v } }),
})

const actions = ['permit', 'deny'].map((a) => ({ label: a, value: a }))
const entriesCount = (r) => (r.entries?.length ? String(r.entries.length) : 'none')
const params = computed(() => ({ instance_id: store.currentId }))

// Prefix lists.
const prefixColumns = [
  { key: 'name', label: 'Name', class: 'font-mono' },
  { key: 'family', label: 'IP version', format: (r) => (r.family === 'ipv6' ? 'IPv6' : 'IPv4') },
  {
    key: 'entries',
    label: 'Entries',
    format: (r) =>
      r.entries
        .map(
          (e) => `${e.action} ${e.prefix}${e.ge ? ` ge ${e.ge}` : ''}${e.le ? ` le ${e.le}` : ''}`,
        )
        .join(', ') || 'none',
    class: 'font-mono text-xs',
  },
  { key: 'description', label: 'Description' },
]
const prefixFields = [
  { key: 'name', label: 'Name', required: true, placeholder: 'customer-a' },
  {
    key: 'family',
    label: 'IP version',
    type: 'select',
    items: [
      { label: 'IPv4', value: 'ipv4' },
      { label: 'IPv6', value: 'ipv6' },
    ],
  },
  { key: 'description', label: 'Description' },
  {
    key: 'entries',
    label: 'Entries',
    type: 'custom',
    hint: 'Tried in sequence order; a prefix matches with its length, or with ge/le the prefixes inside it of those lengths. any matches every prefix. What no entry permits is denied.',
  },
]
const prefixEntryColumns = [
  { key: 'seq', label: 'Seq', type: 'number', class: 'w-16', placeholder: 'auto' },
  { key: 'action', label: 'Action', type: 'select', items: actions, class: 'w-24' },
  { key: 'prefix', label: 'Prefix', placeholder: '10.0.0.0/8 or any' },
  { key: 'ge', label: 'ge', type: 'number', class: 'w-16' },
  { key: 'le', label: 'le', type: 'number', class: 'w-16' },
]

// AS path lists.
const asPathColumns = [
  { key: 'name', label: 'Name', class: 'font-mono' },
  {
    key: 'entries',
    label: 'Entries',
    format: (r) => r.entries.map((e) => `${e.action} ${e.regex}`).join(', ') || 'none',
    class: 'font-mono text-xs',
  },
  { key: 'description', label: 'Description' },
]
const asPathFields = [
  { key: 'name', label: 'Name', required: true },
  { key: 'description', label: 'Description' },
  {
    key: 'entries',
    label: 'Entries',
    type: 'custom',
    hint: 'Regular expressions over the AS path, tried in order: _ matches a space or the start or end, ^65000_ a path from AS 65000, _65000$ a path that started in it, ^$ a route of this AS.',
  },
]
const asPathEntryColumns = [
  { key: 'action', label: 'Action', type: 'select', items: actions, class: 'w-28' },
  { key: 'regex', label: 'Regular expression', placeholder: '^65000_' },
]

// Community lists.
const communityKinds = [
  { label: 'Standard', value: 'standard', description: 'communities AS:NN' },
  { label: 'Expanded', value: 'expanded', description: 'a regular expression' },
  { label: 'Large standard', value: 'large-standard', description: 'large communities A:B:C' },
  { label: 'Large expanded', value: 'large-expanded', description: 'a regular expression' },
]
const communityColumns = [
  { key: 'name', label: 'Name', class: 'font-mono' },
  {
    key: 'kind',
    label: 'Kind',
    format: (r) => communityKinds.find((k) => k.value === r.kind)?.label ?? r.kind,
  },
  {
    key: 'entries',
    label: 'Entries',
    format: (r) => r.entries.map((e) => `${e.action} ${e.value}`).join(', ') || 'none',
    class: 'font-mono text-xs',
  },
  { key: 'description', label: 'Description' },
]
const communityFields = [
  { key: 'name', label: 'Name', required: true },
  { key: 'kind', label: 'Kind', type: 'select', items: communityKinds },
  { key: 'description', label: 'Description' },
  {
    key: 'entries',
    label: 'Entries',
    type: 'custom',
    hint: "Tried in order. A standard entry matches a route with all its communities (AS:NN, or no-export, no-advertise, local-AS, blackhole, graceful-shutdown, ...); an expanded one matches the route's communities as text.",
  },
]
const communityEntryColumns = [
  { key: 'action', label: 'Action', type: 'select', items: actions, class: 'w-28' },
  { key: 'value', label: 'Communities or expression', placeholder: '65000:100 no-export' },
]

// Route maps.
const mapColumns = [
  { key: 'name', label: 'Name', class: 'font-mono' },
  { key: 'entries', label: 'Entries', format: entriesCount },
  { key: 'description', label: 'Description' },
]
const mapFields = [
  { key: 'name', label: 'Name', required: true, placeholder: 'from-upstream' },
  { key: 'description', label: 'Description' },
  {
    key: 'entries',
    label: 'Entries',
    type: 'custom',
    hint: 'Tried in sequence order: the first entry whose matches all match permits the route (and sets what it sets) or denies it. A route no entry matches is denied.',
  },
]

const readOnly = computed(() => !auth.canEdit)
</script>

<template>
  <NeedInstance>
    <UTabs v-model="tab" :items="tabs">
      <template #prefix>
        <CrudPage
          title="Prefix lists"
          description="IPv4 and IPv6 prefix lists, for BGP neighbour filters and route maps."
          :api="prefixLists"
          wide
          :params="params"
          :columns="prefixColumns"
          :fields="prefixFields"
          :defaults="{ family: 'ipv4', entries: [] }"
          new-label="New prefix list"
          @changed="objects.reload"
        >
          <template #field-entries="{ form }">
            <EntriesEditor
              v-model="form.entries"
              :columns="prefixEntryColumns"
              :new-entry="() => ({ seq: 0, action: 'permit', prefix: '', ge: 0, le: 0 })"
              ordered
              seq-key="seq"
              :disabled="readOnly"
            />
          </template>
        </CrudPage>
      </template>
      <template #aspath>
        <CrudPage
          title="AS path lists"
          description="Regular expressions over a route's AS path, for route maps."
          :api="asPathLists"
          wide
          :params="params"
          :columns="asPathColumns"
          :fields="asPathFields"
          :defaults="{ entries: [] }"
          noun="AS path list"
          new-label="New AS path list"
          @changed="objects.reload"
        >
          <template #field-entries="{ form }">
            <EntriesEditor
              v-model="form.entries"
              :columns="asPathEntryColumns"
              :new-entry="() => ({ action: 'permit', regex: '' })"
              ordered
              :disabled="readOnly"
            />
          </template>
        </CrudPage>
      </template>
      <template #community>
        <CrudPage
          title="Community lists"
          description="BGP communities and large communities, for route maps."
          :api="communityLists"
          wide
          :params="params"
          :columns="communityColumns"
          :fields="communityFields"
          :defaults="{ kind: 'standard', entries: [] }"
          new-label="New community list"
          @changed="objects.reload"
        >
          <template #field-entries="{ form }">
            <EntriesEditor
              v-model="form.entries"
              :columns="communityEntryColumns"
              :new-entry="() => ({ action: 'permit', value: '' })"
              ordered
              :disabled="readOnly"
            />
          </template>
        </CrudPage>
      </template>
      <template #maps>
        <CrudPage
          title="Route maps"
          description="Match routes by prefix, AS path, community and more, and permit, deny or change them. BGP uses them on neighbours, networks and redistribution."
          :api="routeMaps"
          wide
          :params="params"
          :columns="mapColumns"
          :fields="mapFields"
          :defaults="{ entries: [] }"
          new-label="New route map"
          @changed="objects.reload"
        >
          <template #field-entries="{ form }">
            <RouteMapEntries
              v-model="form.entries"
              :disabled="readOnly"
              :prefix-list-items="objects.prefixListItems()"
              :as-path-items="objects.asPathItems.value"
              :community-items="objects.communityItems.value"
            />
          </template>
        </CrudPage>
      </template>
    </UTabs>
  </NeedInstance>
</template>
