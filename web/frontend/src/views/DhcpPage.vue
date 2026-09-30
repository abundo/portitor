<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import NeedInstance from '@/components/NeedInstance.vue'
import { api, instances, ipamPrefixes } from '@/api'
import { errMsg } from '@/api/http'
import { usePageForm } from '@/composables/useFormGuard'
import { useAuthStore } from '@/stores/auth'
import { useInstanceStore } from '@/stores/instances'
import { inlineField } from '@/utils/form'
import { datetime } from '@/utils/time'

const toast = useToast()
const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const store = useInstanceStore()
const readOnly = computed(() => !auth.isAdmin)
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

// The DHCP server: the instance's dhcp_* fields.
const server = reactive({
  dhcp_enabled: false,
  dhcp_domain_name: '',
  dhcp_lease_time: 86400,
})
const serverForm = usePageForm(server)
const saving = ref(false)

async function load() {
  const id = store.currentId
  if (!id) return
  const inst = await instances.get(id)
  Object.assign(server, {
    dhcp_enabled: inst.dhcp_enabled,
    dhcp_domain_name: inst.dhcp_domain_name ?? '',
    dhcp_lease_time: inst.dhcp_lease_time,
  })
  serverForm.mark()
}
watch(() => store.currentId, load, { immediate: true })

async function save() {
  saving.value = true
  try {
    await instances.update(store.currentId, server)
    toast.add({ title: 'DHCP server saved', color: 'success' })
    await Promise.all([load(), store.load()])
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    saving.value = false
  }
}

const tabs = [
  { label: 'DHCP info', value: 'info', slot: 'info', icon: 'i-lucide-info' },
  { label: 'DHCP server', value: 'server', slot: 'server', icon: 'i-lucide-server' },
]
// The tab is in the URL (?tab=server), so links can open one.
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'info'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'info' ? undefined : v } }),
})
</script>

<template>
  <NeedInstance>
    <UTabs v-model="tab" :items="tabs" :unmount-on-hide="false">
      <template #info>
        <div class="space-y-4 pt-2">
          <div class="card">
            <div class="mb-2 text-lg font-semibold">DHCP scopes</div>
            <p class="mb-3 text-sm text-muted">
              Scopes are prefixes with DHCP turned on, under
              <RouterLink to="/objects" class="text-primary">Hosts & prefixes</RouterLink>, served
              on the interface with an address in the prefix; several on one interface form a shared
              network. Fixed leases are IPAM addresses with a MAC and a DNS name.
            </p>
            <UAlert
              v-if="store.current && !store.current.dhcp_enabled"
              color="warning"
              variant="subtle"
              title="The DHCP server is off for this instance (DHCP server tab)."
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
              <template #dns-cell="{ row }">{{
                row.original.dhcp_dns_servers?.join(', ')
              }}</template>
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
            <div class="mb-2 text-lg font-semibold">DHCP client</div>
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
      </template>

      <template #server>
        <div class="pt-2">
          <div class="card">
            <div class="mb-1 text-lg font-semibold">DHCP server</div>
            <p class="mb-4 text-sm text-muted">
              Kea, for the clients on this instance's interfaces. DHCPv4 and DHCPv6 scopes are set
              per prefix under
              <RouterLink to="/objects" class="text-primary">Hosts & prefixes</RouterLink>.
            </p>
            <form @submit.prevent="save">
              <fieldset :disabled="readOnly" class="space-y-3">
                <UFormField label="DHCP server (Kea)" :ui="inlineField">
                  <USwitch v-model="server.dhcp_enabled" />
                </UFormField>
                <template v-if="server.dhcp_enabled">
                  <UFormField label="DHCP domain name" :ui="inlineField">
                    <UInput
                      v-model="server.dhcp_domain_name"
                      placeholder="home.arpa"
                      class="w-full sm:w-96"
                    />
                  </UFormField>
                  <UFormField label="Lease time (seconds)" :ui="inlineField">
                    <UInput
                      v-model.number="server.dhcp_lease_time"
                      type="number"
                      min="300"
                      class="w-full sm:w-48"
                    />
                  </UFormField>
                </template>
              </fieldset>
              <div v-if="!readOnly" class="mt-4">
                <UButton type="submit" :loading="saving">Save</UButton>
              </div>
            </form>
          </div>
        </div>
      </template>
    </UTabs>
  </NeedInstance>
</template>
