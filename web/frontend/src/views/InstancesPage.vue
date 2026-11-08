<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import { treeApi } from '@/api/config'
import { useInstanceStore } from '@/stores/instances'

const store = useInstanceStore()
// The virtual firewalls in the configuration tree, without their contents.
const instances = treeApi(() => 'instance', ['name'], { shallow: true })
const firewallItems = () => store.firewalls.map((f) => ({ label: f.name, value: f.name }))

const columns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'firewall', label: 'Firewall' },
  { key: 'description', label: 'Description' },
]

const fields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'guest',
    hint: 'Lowercase letters and digits, max 12.',
  },
  {
    key: 'firewall',
    label: 'Firewall',
    type: 'select',
    items: firewallItems,
    show: () => store.firewalls.length > 1,
    hint: 'The host it runs on. One with links stays on its firewall.',
  },
  { key: 'description', label: 'Description' },
]
</script>

<template>
  <CrudPage
    title="Virtual firewalls"
    description="Virtual firewalls, each with its own interfaces, routing table, firewall, DNS and DHCP server. Connect virtual firewalls with links."
    :api="instances"
    shared
    :columns="columns"
    :fields="fields"
    :row-filter="(i) => !i.is_default"
    :defaults="() => ({ firewall: store.firewalls[0]?.name })"
    new-label="New virtual firewall"
    @changed="store.load()"
  />
</template>
