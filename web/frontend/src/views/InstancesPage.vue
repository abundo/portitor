<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import CrudPage from '@/components/CrudPage.vue'
import { instances } from '@/api'
import { useInstanceStore } from '@/stores/instances'

const store = useInstanceStore()

const forwardModes = [
  { label: 'Forwarders first, then the root servers', value: 'first' },
  { label: 'Forwarders only', value: 'only' },
  { label: 'Root servers only (no forwarders)', value: 'off' },
]

const columns = [
  { key: 'name', label: 'Name', class: 'font-medium' },
  { key: 'is_default', label: 'Default' },
  { key: 'description', label: 'Description' },
  { key: 'dns_enabled', label: 'DNS server' },
  { key: 'dhcp_enabled', label: 'DHCP server' },
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
  { key: 'dns_enabled', label: 'DNS server (BIND)', type: 'switch' },
  {
    key: 'dns_forward_mode',
    label: 'Upstream DNS',
    type: 'select',
    items: forwardModes,
    show: (f) => f.dns_enabled,
  },
  {
    key: 'dns_forwarders',
    label: 'Upstream DNS servers',
    type: 'addrs',
    placeholder: '9.9.9.9',
    show: (f) => f.dns_enabled && f.dns_forward_mode !== 'off',
    hint: 'Empty: resolve from the root servers.',
  },
  {
    key: 'dns_forward_from_dhcp',
    label: 'Also use DNS servers from the WAN DHCP lease',
    type: 'switch',
    show: (f) => f.dns_enabled && f.dns_forward_mode !== 'off',
  },
  {
    key: 'dns_allow_recursion',
    label: 'Allow recursion from',
    type: 'addrs',
    placeholder: '192.168.0.0/16',
    show: (f) => f.dns_enabled,
    hint: 'Empty: the networks of the interfaces DNS listens on.',
  },
  {
    key: 'dhcp_enabled',
    label: 'DHCP server (Kea)',
    type: 'switch',
    hint: 'DHCPv4 and DHCPv6 scopes are set per prefix under Hosts & prefixes.',
  },
  {
    key: 'dhcp_domain_name',
    label: 'DHCP domain name',
    placeholder: 'home.arpa',
    show: (f) => f.dhcp_enabled,
  },
  {
    key: 'dhcp_lease_time',
    label: 'Lease time (seconds)',
    type: 'number',
    show: (f) => f.dhcp_enabled,
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
    :defaults="{
      dns_forward_mode: 'first',
      dns_forwarders: [],
      dns_allow_recursion: [],
      dhcp_lease_time: 86400,
    }"
    new-label="New instance"
    @changed="store.load()"
  />
</template>
