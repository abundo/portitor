<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import { instances } from '@/api'
import { useInstanceStore } from '@/stores/instances'

const store = useInstanceStore()

const columns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'description', label: 'Description' },
]

const fields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'guest',
    hint: 'Lowercase letters and digits, max 12. Runs in network namespace fw-<name>.',
  },
  { key: 'description', label: 'Description' },
]
</script>

<template>
  <CrudPage
    title="Virtual firewalls"
    description="Virtual routers, each in its own network namespace, with its own interfaces, routing table, firewall, DNS and DHCP server. The default virtual firewall is the host itself and is not listed. Connect virtual firewalls with links."
    :api="instances"
    shared
    :columns="columns"
    :fields="fields"
    :row-filter="(i) => !i.is_default"
    new-label="New virtual firewall"
    @changed="store.load()"
  />
</template>
