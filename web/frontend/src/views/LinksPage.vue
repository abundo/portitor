<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { onMounted } from 'vue'
import CrudPage from '@/components/CrudPage.vue'
import { links } from '@/api'
import { useInstanceStore } from '@/stores/instances'

const store = useInstanceStore()
onMounted(() => store.load())

const side = (r, s) =>
  `${store.nameOf(r[`instance_${s}_id`])} · ${r[`interface_${s}`]} ${r[`addresses_${s}`]?.join(', ') ?? ''}`

const columns = [
  { key: 'name', label: 'Link', class: 'font-medium' },
  { key: 'a', label: 'Side A', format: (r) => side(r, 'a') },
  { key: 'b', label: 'Side B', format: (r) => side(r, 'b') },
  { key: 'description', label: 'Description' },
]
const fields = [
  { key: 'name', label: 'Name', required: true, placeholder: 'guestup' },
  { key: 'description', label: 'Description' },
  {
    key: 'instance_a_id',
    label: 'Side A virtual firewall',
    type: 'select',
    items: () => store.items,
  },
  { key: 'interface_a', label: 'Side A interface name', placeholder: 'lk-guest', required: true },
  { key: 'addresses_a', label: 'Side A addresses', type: 'tags', placeholder: '10.255.0.1/30' },
  {
    key: 'instance_b_id',
    label: 'Side B virtual firewall',
    type: 'select',
    items: () => store.items,
  },
  { key: 'interface_b', label: 'Side B interface name', placeholder: 'lk-main', required: true },
  { key: 'addresses_b', label: 'Side B addresses', type: 'tags', placeholder: '10.255.0.2/30' },
]
</script>

<template>
  <CrudPage
    title="Links"
    description="Internal point-to-point links between virtual firewalls (a veth pair). Add a route in each virtual firewall through the other side's address, and firewall rules for the link's interfaces (each end is an interface of its virtual firewall)."
    :api="links"
    shared
    :columns="columns"
    :fields="fields"
    :defaults="
      () => ({
        addresses_a: [],
        addresses_b: [],
        instance_a_id: store.list[0]?.id,
        instance_b_id: store.list[1]?.id,
      })
    "
    new-label="New link"
    :blocked-reason="
      store.list.length < 2
        ? 'Links connect two virtual firewalls; create a second virtual firewall first.'
        : ''
    "
  />
</template>
