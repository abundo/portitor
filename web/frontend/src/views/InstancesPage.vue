<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import { instances } from '@/api'
import { useInstanceStore } from '@/stores/instances'

const store = useInstanceStore()

const columns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'is_default', label: 'Default' },
  { key: 'description', label: 'Description' },
]

const fields = [
  {
    key: 'name',
    label: 'Name',
    required: true,
    placeholder: 'main',
    hint: 'Lowercase letters and digits, max 12. Non-default instances run in network namespace fw-<name>.',
  },
  { key: 'description', label: 'Description' },
  {
    key: 'is_default',
    label: 'Default instance',
    type: 'switch',
    hint: 'The default instance is the host itself (root network namespace). Exactly one.',
  },
]
</script>

<template>
  <CrudPage
    title="Instances"
    description="Virtual routers. Each has its own interfaces, routing table, firewall, DNS and DHCP server. Connect instances with links."
    :api="instances"
    :columns="columns"
    :fields="fields"
    new-label="New instance"
    @changed="store.load()"
  />
</template>
