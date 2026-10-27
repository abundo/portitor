<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- OpenVPN: the virtual firewall's OpenVPN server (an interface of kind
     openvpn), its connected clients, and client configs. Users log in with
     their password, as to the GUI: the directory's (Admin → Directory). -->
<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { useRoute, useRouter } from 'vue-router'
import AutoRefreshButton from '@/components/AutoRefreshButton.vue'
import FormHeader from '@/components/FormHeader.vue'
import NameSelect from '@/components/NameSelect.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import SearchInput from '@/components/SearchInput.vue'
import TagsInput from '@/components/TagsInput.vue'
import { api, certificates, interfaces } from '@/api'
import { errMsg } from '@/api/http'
import { withLabel } from '@/composables/useInstanceRefs'
import { useAutoRefresh } from '@/composables/useAutoRefresh'
import { usePageForm } from '@/composables/useFormGuard'
import { useAuthStore } from '@/stores/auth'
import { useInstanceStore } from '@/stores/instances'
import { bytes } from '@/utils/bytes'
import { inlineField } from '@/utils/form'
import { useSearch, valuesText } from '@/utils/search'
import { ago, datetime } from '@/utils/time'

const toast = useToast()
const auth = useAuthStore()
const store = useInstanceStore()
const route = useRoute()
const router = useRouter()
const readOnly = computed(() => !auth.canEdit)

const tabs = [
  { label: 'OpenVPN info', value: 'info', slot: 'info', icon: 'i-lucide-info' },
  { label: 'OpenVPN config', value: 'config', slot: 'config', icon: 'i-lucide-settings' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'info'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'info' ? undefined : v } }),
})

// ----- The server: the instance's interface of kind openvpn.
const server = ref(null)
const ifaceRows = ref([])
const certs = ref([])
const roles = ref([])
const keys = [
  'label',
  'description',
  'enabled',
  'addresses',
  'ovpn_tcp_addresses',
  'mtu',
  'ovpn_mode',
  'ovpn_port',
  'ovpn_listen',
  'ovpn_certificate_id',
  'ovpn_host',
  'ovpn_role_id',
  'ovpn_routes',
  'ovpn_redirect_gateway',
  'ovpn_dns',
  'ovpn_dns_domain',
  'ovpn_client_to_client',
]
const form = reactive({})
const pageForm = usePageForm(form)
const saving = ref(false)
const NONE = 0 // no certificate or role, null in the database

async function load() {
  const id = store.currentId
  if (!id) return
  const [ifs, cs] = await Promise.all([
    interfaces.list({ instance_id: id }),
    certificates.list({ instance_id: id }),
  ])
  ifaceRows.value = ifs
  certs.value = cs.filter((c) => !c.is_ca)
  // The roles are a global admin's to see.
  roles.value = auth.isAdmin ? await api.roles().catch(() => []) : []
  server.value = ifs.find((i) => i.kind === 'openvpn') ?? null
  for (const k of keys) delete form[k]
  if (server.value) {
    for (const k of keys) form[k] = JSON.parse(JSON.stringify(server.value[k] ?? null))
    form.addresses ??= []
    form.ovpn_tcp_addresses ??= []
    form.ovpn_routes ??= []
    form.ovpn_dns ??= []
    form.ovpn_certificate_id ??= NONE
    form.ovpn_role_id ??= NONE
  }
  pageForm.mark()
}
watch(() => store.currentId, load, { immediate: true })

const modeItems = [
  { label: 'Adaptive: UDP, and TCP where UDP is blocked', value: 'adaptive' },
  { label: 'UDP only', value: 'udp' },
  { label: 'TCP only', value: 'tcp' },
]
// Adaptive: a UDP and a TCP process, each with its own tunnel addresses.
const adaptive = computed(() => form.ovpn_mode === 'adaptive')
const certItems = computed(() => [
  { label: '—', value: NONE },
  ...certs.value.map((c) => ({
    label: c.name,
    value: c.id,
    description: (c.domains ?? []).join(', '),
  })),
])
const roleItems = computed(() => [
  { label: 'Any user of the directory', value: NONE },
  ...roles.value.map((r) => ({ label: r.name, value: r.id, description: r.description })),
])
const listenItems = computed(() =>
  ifaceRows.value
    .filter((i) => i.kind !== 'openvpn')
    .map((i) => ({ label: withLabel(i.label, i.name), value: i.name })),
)

async function create() {
  saving.value = true
  try {
    await interfaces.create({
      instance_id: store.currentId,
      name: 'ovpn0',
      kind: 'openvpn',
      enabled: false,
      ipv4_mode: 'static',
      addresses: ['10.8.0.1/24'],
      ovpn_tcp_addresses: ['10.9.0.1/24'],
      ovpn_mode: 'adaptive',
      ovpn_port: 1194,
    })
    toast.add({
      title: 'OpenVPN interface ovpn0 added; choose its certificate and enable it.',
      color: 'success',
    })
    await load()
    tab.value = 'config'
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    saving.value = false
  }
}

async function save() {
  saving.value = true
  try {
    const body = { ...form }
    if (body.ovpn_certificate_id === NONE) body.ovpn_certificate_id = null
    if (body.ovpn_role_id === NONE) body.ovpn_role_id = null
    server.value = await interfaces.update(server.value.id, body)
    toast.add({ title: 'OpenVPN saved; commit to apply it.', color: 'success' })
    await load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    saving.value = false
  }
}

// ----- Info: the processes and their clients, every 10 s.
const status = ref({ servers: [] })
const statusLoading = ref(false)
async function loadStatus() {
  statusLoading.value = true
  try {
    status.value = await api.agentOpenvpn()
  } catch {
    // shown as not running
  } finally {
    statusLoading.value = false
  }
}
const auto = useAutoRefresh(loadStatus, { seconds: 10, active: () => tab.value === 'info' })

const processes = computed(() =>
  (status.value.servers ?? []).filter((s) => s.instance === store.current?.name),
)
const clients = computed(() =>
  processes.value.flatMap((p) => (p.clients ?? []).map((c) => ({ ...c, proto: p.proto }))),
)
const { search: clientSearch, filtered: shownClients } = useSearch(clients, (c) =>
  valuesText(c.user, c.real_address, c.address, c.address6, c.proto, c.source, c.cipher),
)
const certName = computed(
  () => certs.value.find((c) => c.id === server.value?.ovpn_certificate_id)?.name ?? '',
)
const infoRows = computed(() => {
  const s = server.value
  if (!s) return []
  const login = s.ovpn_role_id
    ? `members of role ${roles.value.find((r) => r.id === s.ovpn_role_id)?.name ?? s.ovpn_role_id}, and of its groups`
    : s.ovpn_require_role
      ? 'no one: its required role is gone'
      : 'any user of the directory'
  return [
    ['Interface', withLabel(s.label, s.name)],
    ['Enabled', s.enabled ? 'yes' : 'no'],
    ['Mode', modeItems.find((m) => m.value === s.ovpn_mode)?.label ?? s.ovpn_mode],
    ['Port', String(s.ovpn_port)],
    ['Listens on', s.ovpn_listen || 'any interface'],
    ['Certificate', certName.value || '— (none chosen)'],
    ...(s.ovpn_mode === 'adaptive'
      ? [
          ['UDP tunnel addresses', (s.addresses ?? []).join(', ') || '—'],
          ['TCP tunnel addresses', (s.ovpn_tcp_addresses ?? []).join(', ') || '—'],
        ]
      : [['Addresses', (s.addresses ?? []).join(', ') || '—']]),
    ['Logins', login],
    ...processes.value.map((p) => [
      `Process (${p.proto.toUpperCase()})`,
      p.connected
        ? `running on ${p.device}, ${p.clients.length} client${p.clients.length === 1 ? '' : 's'}`
        : p.error || 'not running',
    ]),
  ]
})

// ----- The client config.
const cfgOpen = ref(false)
const cfg = ref({ config: '', filename: '', warnings: [] })
async function showConfig() {
  try {
    cfg.value = await api.openvpnClientConfig(server.value.id)
    cfgOpen.value = true
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
function copy(text) {
  navigator.clipboard?.writeText(text)
  toast.add({ title: 'Copied', color: 'success' })
}
function downloadConfig() {
  const url = URL.createObjectURL(
    new Blob([cfg.value.config], { type: 'application/x-openvpn-profile' }),
  )
  const a = document.createElement('a')
  a.href = url
  a.download = cfg.value.filename
  a.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <NeedInstance>
    <UTabs v-model="tab" :items="tabs" :unmount-on-hide="false">
      <template #info>
        <div class="space-y-4 pt-2">
          <div v-if="!server" class="card">
            <UAlert
              icon="i-lucide-shield-check"
              title="No OpenVPN server in this virtual firewall"
              description="Add one on the OpenVPN config tab."
            />
          </div>
          <template v-else>
            <div class="card space-y-3">
              <div class="flex flex-wrap items-center justify-between gap-3">
                <div class="text-lg font-semibold">OpenVPN server</div>
                <div class="flex gap-2">
                  <UButton
                    v-if="auth.canEdit"
                    color="neutral"
                    variant="outline"
                    icon="i-lucide-file-down"
                    label="Client config"
                    @click="showConfig"
                  />
                  <AutoRefreshButton :auto="auto" :loading="statusLoading" />
                </div>
              </div>
              <table class="text-sm">
                <tbody>
                  <tr v-for="[k, v] in infoRows" :key="k">
                    <td class="py-1 pr-6 align-top text-muted">{{ k }}</td>
                    <td class="py-1">{{ v }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div class="card">
              <div class="mb-2 text-lg font-semibold">Connected clients</div>
              <SearchInput v-model="clientSearch" class="mb-2" />
              <div class="overflow-x-auto">
                <table class="w-full text-sm">
                  <thead>
                    <tr class="text-left text-muted">
                      <th class="py-1 pr-3">User</th>
                      <th class="py-1 pr-3">From</th>
                      <th class="py-1 pr-3">Tunnel addresses</th>
                      <th class="py-1 pr-3">Protocol</th>
                      <th class="py-1 pr-3">Connected</th>
                      <th class="py-1 pr-3">Received</th>
                      <th class="py-1 pr-3">Sent</th>
                      <th class="py-1 pr-3">Checked by</th>
                      <th class="py-1 pr-3">Cipher</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="c in shownClients"
                      :key="`${c.proto}-${c.id}`"
                      class="border-t border-default align-top"
                    >
                      <td class="py-1 pr-3 font-medium">{{ c.user }}</td>
                      <td class="py-1 pr-3 font-mono text-xs">{{ c.real_address }}</td>
                      <td class="py-1 pr-3 font-mono text-xs">
                        <div v-if="c.address">{{ c.address }}</div>
                        <div v-if="c.address6">{{ c.address6 }}</div>
                      </td>
                      <td class="py-1 pr-3 text-xs">{{ c.proto.toUpperCase() }}</td>
                      <td class="py-1 pr-3 text-xs" :title="datetime(c.since)">
                        {{ ago(c.since) }}
                      </td>
                      <td class="py-1 pr-3 text-xs">{{ bytes(c.rx_bytes) }}</td>
                      <td class="py-1 pr-3 text-xs">{{ bytes(c.tx_bytes) }}</td>
                      <td class="py-1 pr-3 text-xs">{{ c.source || '—' }}</td>
                      <td class="py-1 pr-3 text-xs">{{ c.cipher || '—' }}</td>
                    </tr>
                    <tr v-if="!shownClients.length">
                      <td colspan="9" class="py-2 text-muted">No clients.</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </template>
        </div>
      </template>

      <template #config>
        <div class="pt-2">
          <div v-if="!server" class="card space-y-3">
            <UAlert
              icon="i-lucide-shield-check"
              title="No OpenVPN server in this virtual firewall"
              description="Add one: an interface ovpn0 with the tunnel's addresses (adaptive: one prefix for the UDP clients, another for the TCP clients). Its clients get the other addresses of their prefixes. Choose its certificate (under Certificates) and enable it; allow its traffic with firewall rules on ovpn0."
            />
            <UButton
              v-if="auth.canEdit"
              icon="i-lucide-plus"
              label="Add OpenVPN server"
              :loading="saving"
              @click="create"
            />
          </div>
          <div v-else class="card">
            <form @submit.prevent="save">
              <FormHeader :title="`OpenVPN server ${withLabel(server.label, server.name)}`">
                <UButton
                  v-if="!readOnly"
                  type="submit"
                  :loading="saving"
                  :disabled="!pageForm.dirty()"
                  >Save</UButton
                >
              </FormHeader>
              <p class="mb-4 text-sm text-muted">
                Remote users log in with their user name and password, over IPv4 or IPv6. The
                firewall opens the port automatically; what clients reach is up to the firewall
                rules on {{ server.name }}.
              </p>
              <fieldset :disabled="readOnly" class="space-y-3">
                <UFormField label="Enabled" :ui="inlineField">
                  <USwitch v-model="form.enabled" />
                </UFormField>
                <UFormField label="Label" :ui="inlineField">
                  <UInput v-model="form.label" class="w-full" placeholder="VPN" />
                </UFormField>
                <UFormField label="Description" :ui="inlineField">
                  <UInput v-model="form.description" class="w-full" />
                </UFormField>
                <UFormField label="Mode" :ui="inlineField">
                  <USelect v-model="form.ovpn_mode" :items="modeItems" class="w-full" />
                </UFormField>
                <UFormField
                  :label="adaptive ? 'UDP tunnel addresses' : 'Tunnel addresses'"
                  :help="`The firewall's address in the ${adaptive ? 'UDP clients’ ' : ''}tunnel, one IPv4 and/or one IPv6, with the prefix length: 10.8.0.1/24, fd00:8::1/64. Clients get the other addresses of the prefixes. IPv4 /16 to /30, IPv6 /64 is usual.`"
                  :ui="inlineField"
                >
                  <TagsInput
                    v-model="form.addresses"
                    class="w-full font-mono"
                    placeholder="10.8.0.1/24"
                    :disabled="readOnly"
                  />
                </UFormField>
                <UFormField
                  v-if="adaptive"
                  label="TCP tunnel addresses"
                  help="The firewall's address in the TCP clients' tunnel, as for UDP, in other prefixes: 10.9.0.1/24, fd00:9::1/64. Each side's clients get a route to the other's."
                  :ui="inlineField"
                >
                  <TagsInput
                    v-model="form.ovpn_tcp_addresses"
                    class="w-full font-mono"
                    placeholder="10.9.0.1/24"
                    :disabled="readOnly"
                  />
                </UFormField>
                <UFormField
                  label="Port"
                  help="UDP and TCP; opened automatically on the listen interface."
                  :ui="inlineField"
                >
                  <UInput v-model.number="form.ovpn_port" type="number" class="w-40" />
                </UFormField>
                <UFormField
                  label="Listen interface"
                  help="Where clients come in, the WAN; —: any interface."
                  :ui="inlineField"
                >
                  <NameSelect
                    v-model="form.ovpn_listen"
                    :items="listenItems"
                    :disabled="readOnly"
                  />
                </UFormField>
                <UFormField
                  label="Certificate"
                  help="The server's, from Certificates (an ACME certificate is renewed and OpenVPN restarted). Clients check it by its common name."
                  :ui="inlineField"
                >
                  <USelect v-model="form.ovpn_certificate_id" :items="certItems" class="w-full" />
                </UFormField>
                <UFormField
                  label="Public host"
                  help="The name or address clients connect to, in their config; empty: the certificate's name."
                  :ui="inlineField"
                >
                  <UInput
                    v-model="form.ovpn_host"
                    class="w-full font-mono"
                    placeholder="vpn.example.com"
                  />
                </UFormField>
              </fieldset>

              <h2 class="border-b border-default pb-1 mt-8 mb-2 text-xl font-semibold">Logins</h2>
              <fieldset :disabled="readOnly" class="space-y-3">
                <p class="text-sm text-muted">
                  Users log in with their name and password, as to the GUI: a local user's is
                  checked here, a directory user's at the directory's servers (Admin → Directory),
                  which also let in, and copy to the users, a user the firewall doesn't have yet. No
                  two-factor code is asked for.
                </p>
                <UFormField
                  v-if="auth.isAdmin"
                  label="Required role"
                  help="Only the role's members may log in, and the directory users in a group mapped to it (Admin → Directory → Authorization)."
                  :ui="inlineField"
                >
                  <USelect v-model="form.ovpn_role_id" :items="roleItems" class="w-full" />
                </UFormField>
                <p v-else class="text-xs text-muted">
                  Only the members of this virtual firewall's role log in.
                </p>
              </fieldset>

              <h2 class="border-b border-default pb-1 mt-8 mb-2 text-xl font-semibold">Clients</h2>
              <fieldset :disabled="readOnly" class="space-y-3">
                <UFormField
                  label="Routes"
                  help="Networks the clients reach through the tunnel: 192.168.1.0/24, fd00:1::/64."
                  :ui="inlineField"
                >
                  <TagsInput
                    v-model="form.ovpn_routes"
                    class="w-full font-mono"
                    placeholder="192.168.1.0/24"
                    :disabled="readOnly"
                  />
                </UFormField>
                <UFormField
                  label="All traffic through the tunnel"
                  help="The clients' default route (and IPv6's, or IPv6 blocked without an IPv6 address here). Masquerade it with a NAT rule out of the WAN."
                  :ui="inlineField"
                >
                  <USwitch v-model="form.ovpn_redirect_gateway" />
                </UFormField>
                <UFormField
                  label="DNS servers"
                  help="Empty: this interface's addresses when the DNS server answers on it."
                  :ui="inlineField"
                >
                  <TagsInput
                    v-model="form.ovpn_dns"
                    class="w-full font-mono"
                    placeholder="10.8.0.1"
                    :disabled="readOnly"
                  />
                </UFormField>
                <UFormField label="DNS domain" :ui="inlineField">
                  <UInput v-model="form.ovpn_dns_domain" class="w-full" placeholder="home.arpa" />
                </UFormField>
                <UFormField
                  label="Client to client"
                  help="Clients reach each other inside OpenVPN, past the firewall rules."
                  :ui="inlineField"
                >
                  <USwitch v-model="form.ovpn_client_to_client" />
                </UFormField>
                <UFormField label="MTU" help="0 keeps the default." :ui="inlineField">
                  <UInput v-model.number="form.mtu" type="number" class="w-40" />
                </UFormField>
              </fieldset>
              <p class="mt-4 text-xs text-muted">
                The name is changed, and the interface deleted, under
                <ULink to="/interfaces" class="underline">Interfaces</ULink>.
              </p>
            </form>
          </div>
        </div>
      </template>
    </UTabs>

    <UModal
      v-model:open="cfgOpen"
      :title="`Client config: ${cfg.filename}`"
      :ui="{ content: 'max-w-2xl' }"
      :dismissible="false"
    >
      <template #body>
        <div class="space-y-3">
          <UAlert v-for="w in cfg.warnings" :key="w" color="warning" variant="subtle" :title="w" />
          <pre class="max-h-[60vh] overflow-auto rounded bg-elevated p-3 text-xs">{{
            cfg.config
          }}</pre>
          <p class="text-xs text-muted">
            For the OpenVPN apps (OpenVPN Connect, the OpenVPN GUI, NetworkManager): the same file
            for every user, who logs in with their own name and password. It holds the server's
            tls-crypt key: hand it out to your users only.
          </p>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton
            color="neutral"
            variant="outline"
            icon="i-lucide-copy"
            label="Copy"
            @click="copy(cfg.config)"
          />
          <UButton
            color="neutral"
            variant="outline"
            icon="i-lucide-download"
            label="Download"
            @click="downloadConfig"
          />
          <UButton label="Close" @click="cfgOpen = false" />
        </div>
      </template>
    </UModal>
  </NeedInstance>
</template>
