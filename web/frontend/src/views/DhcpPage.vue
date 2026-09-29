<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, ref } from 'vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { api, ipamPrefixes } from '@/api'
import { errMsg } from '@/api/http'
import { useInstanceStore } from '@/stores/instances'
import { datetime } from '@/utils/time'

const store = useInstanceStore()
const prefixes = ref([])
const leases = ref(null)
const leaseError = ref('')

onMounted(async () => {
  prefixes.value = (await ipamPrefixes.list({ instance_id: store.currentId })).filter(
    (p) => p.dhcp_enabled,
  )
  try {
    leases.value = await api.agentLeases()
  } catch (err) {
    leaseError.value = errMsg(err)
  }
})

const serverLeases = computed(() => leases.value?.server?.[store.current?.name] ?? [])
const clientLeases = computed(() =>
  (leases.value?.client ?? []).filter((l) => l.instance === store.current?.name),
)
</script>

<template>
  <NeedInstance>
    <div class="space-y-4">
      <div class="card">
        <div class="mb-2 text-lg font-semibold">DHCP scopes</div>
        <p class="mb-3 text-sm text-muted">
          Scopes are prefixes with DHCP turned on, under
          <RouterLink to="/ipam" class="text-primary">IP addresses</RouterLink>, served on the
          interface with an address in the prefix; several on one interface form a shared network.
          Fixed leases are IPAM addresses with a MAC and a DNS name.
        </p>
        <UAlert
          v-if="store.current && !store.current.dhcp_enabled"
          color="warning"
          variant="subtle"
          title="The DHCP server is off for this instance (Instances)."
          class="mb-3"
        />
        <UTable
          :data="prefixes"
          :columns="[
            { accessorKey: 'prefix', header: 'Prefix' },
            { id: 'range', header: 'Range' },
            { accessorKey: 'dhcp_gateway', header: 'Gateway' },
            { id: 'dns', header: 'DNS servers' },
          ]"
        >
          <template #range-cell="{ row }"
            >{{ row.original.dhcp_range_start }} – {{ row.original.dhcp_range_end }}</template
          >
          <template #dns-cell="{ row }">{{ row.original.dhcp_dns_servers?.join(', ') }}</template>
          <template #dhcp_gateway-cell="{ row }">{{
            row.original.dhcp_gateway || 'firewall'
          }}</template>
        </UTable>
      </div>

      <div class="card">
        <div class="mb-2 text-lg font-semibold">Active leases</div>
        <UAlert v-if="leaseError" color="error" variant="subtle" :title="leaseError" />
        <UTable
          v-else
          :data="serverLeases"
          :columns="[
            { accessorKey: 'address', header: 'Address' },
            { accessorKey: 'mac', header: 'MAC' },
            { accessorKey: 'hostname', header: 'Host name' },
            { id: 'expires', header: 'Expires' },
          ]"
        >
          <template #expires-cell="{ row }">{{ datetime(row.original.expires) }}</template>
          <template #empty
            ><div class="py-4 text-center text-muted">No active leases.</div></template
          >
        </UTable>
      </div>

      <div v-if="clientLeases.length" class="card">
        <div class="mb-2 text-lg font-semibold">Upstream (DHCP client)</div>
        <UTable
          :data="clientLeases"
          :columns="[
            { accessorKey: 'interface', header: 'Interface' },
            { accessorKey: 'state', header: 'State' },
            { accessorKey: 'address', header: 'Address' },
            { accessorKey: 'router', header: 'Gateway' },
            { id: 'dns', header: 'DNS' },
            { id: 'expires', header: 'Expires' },
          ]"
        >
          <template #dns-cell="{ row }">{{ row.original.dns?.join(', ') }}</template>
          <template #expires-cell="{ row }">{{ datetime(row.original.expires) }}</template>
        </UTable>
      </div>
    </div>
  </NeedInstance>
</template>
