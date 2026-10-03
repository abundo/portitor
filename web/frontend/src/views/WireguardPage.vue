<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { useConfirm } from '@/composables/useConfirm'
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import QRCode from 'qrcode'
import CrudPage from '@/components/CrudPage.vue'
import NeedInstance from '@/components/NeedInstance.vue'
import { api, interfaces, wgPeers } from '@/api'
import { withLabel } from '@/composables/useInstanceRefs'
import { errMsg } from '@/api/http'
import { useInstanceStore } from '@/stores/instances'
import { useDeployStore } from '@/stores/deploy'
import { useAuthStore } from '@/stores/auth'
import { useFormGuard, usePageForm } from '@/composables/useFormGuard'
import TagsInput from '@/components/TagsInput.vue'
import { inlineField, wideModal } from '@/utils/form'

const { ask } = useConfirm()

const auth = useAuthStore()
const store = useInstanceStore()
const deploy = useDeployStore()
const toast = useToast()
const tunnels = ref([])
const selectedId = ref(null)

async function load() {
  tunnels.value = (await interfaces.list({ instance_id: store.currentId })).filter(
    (i) => i.kind === 'wireguard',
  )
  if (!tunnels.value.some((t) => t.id === selectedId.value))
    selectedId.value = tunnels.value[0]?.id ?? null
}
onMounted(load)

// The public endpoint host (a global setting, for global admins): the
// client configs' endpoint when an interface has none of its own.
const endpoint = ref({ wg_endpoint_host: '' })
const endpointForm = usePageForm(endpoint)
async function loadEndpoint() {
  if (!auth.isAdmin) return
  endpoint.value.wg_endpoint_host = (await api.settings()).wg_endpoint_host
  endpointForm.mark()
}
onMounted(loadEndpoint)
async function saveEndpoint() {
  try {
    const s = await api.saveSettings({ wg_endpoint_host: endpoint.value.wg_endpoint_host })
    endpoint.value.wg_endpoint_host = s.wg_endpoint_host
    endpointForm.mark()
    toast.add({ title: 'Saved', color: 'success' })
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

const selected = computed(() => tunnels.value.find((t) => t.id === selectedId.value))

// Suggested tunnel addresses for the next new peer, one free address per
// address family of the interface.
const freeAddrs = ref([])
const freeWarnings = ref([])
async function loadFree() {
  freeAddrs.value = []
  freeWarnings.value = []
  if (!selectedId.value) return
  try {
    const r = await api.wgNextFree(selectedId.value)
    freeAddrs.value = r.addresses
    freeWarnings.value = r.warnings ?? []
  } catch {
    // no suggestion; the field stays empty
  }
}
watch(selectedId, loadFree)
function peerDefaults() {
  return {
    enabled: true,
    allowed_ips: [...freeAddrs.value],
    networks: [],
    keepalive: 0,
    public_key: '',
  }
}
const tunnelItems = computed(() =>
  tunnels.value.map((t) => ({
    label: withLabel(t.label, t.name) + (t.enabled ? '' : ' (disabled)'),
    value: t.id,
  })),
)

// Enables or disables the selected tunnel (its interface); takes effect on
// the next deploy.
async function setEnabled(enabled) {
  const t = selected.value
  try {
    Object.assign(t, await interfaces.update(t.id, { enabled }))
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
    await load()
  }
}

// ----- edit the selected tunnel (its interface) -----
// The name, kind and virtual firewall are changed under Interfaces.
const editKeys = [
  'label',
  'description',
  'enabled',
  'addresses',
  'wg_listen_port',
  'wg_endpoint',
  'wg_keepalive',
  'mtu',
]
const editOpen = ref(false)
const editSaving = ref(false)
const editForm = reactive({})
const editGuard = useFormGuard(editForm, editOpen)
function editTunnel() {
  const t = selected.value
  for (const k of editKeys) editForm[k] = structuredClone(t[k] ?? null)
  editForm.addresses ??= []
  editOpen.value = true
}
async function saveTunnel() {
  editSaving.value = true
  try {
    const t = selected.value
    Object.assign(t, await interfaces.update(t.id, { ...editForm }))
    editOpen.value = false
    await loadFree()
  } catch (err) {
    toast.add({ title: errMsg(err, 'Save failed'), color: 'error' })
  } finally {
    editSaving.value = false
  }
}

// Handshakes from the agent status, by peer public key.
const handshakes = computed(() => {
  const m = {}
  for (const inst of deploy.status?.instances ?? []) {
    for (const wg of inst.wireguard ?? []) {
      for (const p of wg.peers) m[p.public_key] = p
    }
  }
  return m
})
function ago(t) {
  if (!t) return 'never'
  const s = Math.round((Date.now() - new Date(t).getTime()) / 1000)
  if (s < 120) return `${s}s ago`
  if (s < 7200) return `${Math.round(s / 60)}m ago`
  return `${Math.round(s / 3600)}h ago`
}

async function rekey() {
  if (
    !(await ask({
      title: 'New key',
      message: `Generate a new key for ${withLabel(selected.value.label, selected.value.name)}? Every peer needs the new public key.`,
    }))
  )
    return
  try {
    await api.wgRekey(selected.value.id)
    await load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

const columns = [
  { key: 'name', label: 'Peer', class: 'font-medium' },
  { key: 'allowed_ips', label: 'Tunnel addresses', class: 'font-mono text-xs' },
  { key: 'networks', label: 'Networks', class: 'font-mono text-xs' },
  { key: 'endpoint', label: 'Endpoint', class: 'font-mono text-xs' },
  { key: 'handshake', label: 'Last handshake' },
  { key: 'enabled', label: 'Enabled' },
]
// What the generated client config uses when the peer leaves endpoint and
// keepalive empty: the interface's client defaults.
const clientEndpoint = computed(() => {
  const t = selected.value
  if (!t) return ''
  if (t.wg_endpoint) return t.wg_endpoint
  return t.wg_listen_port ? `the public endpoint host, port ${t.wg_listen_port}` : 'none set'
})
const clientKeepalive = computed(() =>
  selected.value?.wg_keepalive ? `${selected.value.wg_keepalive}s` : 'off',
)
const fields = computed(() => [
  { key: 'name', label: 'Name', required: true, placeholder: 'phone' },
  { key: 'description', label: 'Description' },
  {
    key: 'public_key',
    label: "Peer's public key",
    placeholder: 'leave empty to generate a key pair here',
    hint: 'Empty: a key pair and preshared key are generated, and a ready client config can be downloaded.',
  },
  {
    key: 'allowed_ips',
    label: 'Allowed IPs',
    type: 'addrs',
    placeholder: '10.99.0.2/32',
    hint: "The peer's tunnel address. New peers get the next free addresses of the interface's prefixes.",
  },
  {
    key: 'networks',
    label: 'Networks',
    type: 'addrs',
    placeholder: '192.168.50.0/24',
    hint: 'Site-to-site: the networks behind the peer. They are allowed through the tunnel and routed to it. Empty for phones and laptops.',
  },
  {
    key: 'endpoint',
    label: 'Endpoint',
    placeholder: 'host:port (only for peers the firewall dials)',
    hint: `Empty: the firewall waits for the peer to connect. The client config uses the interface default (${clientEndpoint.value}).`,
  },
  {
    key: 'keepalive',
    label: 'Keepalive (seconds)',
    type: 'number',
    hint: `0: the firewall sends no keepalives. The client config uses the interface default (${clientKeepalive.value}).`,
  },
  { key: 'enabled', label: 'Enabled', type: 'switch' },
])

// ----- import a wg-quick config file -----
// The interface is named after the file (wg0.conf → wg0).
const importInput = ref(null)
async function importFile(ev) {
  const file = ev.target.files?.[0]
  ev.target.value = ''
  if (!file) return
  const name = file.name.replace(/\.conf$/i, '')
  try {
    const config = await file.text()
    const existing = (await interfaces.list({ instance_id: store.currentId })).find(
      (i) => i.name === name,
    )
    if (existing && existing.kind !== 'wireguard') {
      toast.add({ title: `${name} exists and is not a WireGuard interface`, color: 'error' })
      return
    }
    const ok = await ask(
      existing
        ? {
            title: 'Overwrite interface',
            message: `WireGuard interface ${withLabel(existing.label, name)} exists. Overwrite its key, listen port, addresses and peers with ${file.name}?`,
          }
        : {
            title: 'Create interface',
            message: `WireGuard interface ${name} does not exist. Create it from ${file.name}?`,
          },
    )
    if (!ok) return
    const r = await api.wgImport({
      instance_id: store.currentId,
      name,
      config,
      overwrite: !!existing,
    })
    await load()
    selectedId.value = r.interface.id
    await loadFree()
    toast.add({
      title: `Imported ${name} with ${r.peers} peer${r.peers === 1 ? '' : 's'}`,
      description: r.warnings.join('; ') || undefined,
      color: r.warnings.length ? 'warning' : 'success',
    })
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

// ----- client config -----
const cfgOpen = ref(false)
const cfg = ref({ config: '', warnings: [] })
const qr = ref('')
const split = ref(false)
const cfgPeer = ref(null)
async function showConfig(peer) {
  cfgPeer.value = peer
  await loadConfig()
  cfgOpen.value = true
}
async function loadConfig() {
  try {
    cfg.value = await api.wgClientConfig(cfgPeer.value.id, split.value)
    qr.value = cfg.value.site
      ? ''
      : await QRCode.toDataURL(cfg.value.config, { margin: 1, width: 280 })
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
function copy(text) {
  navigator.clipboard?.writeText(text)
  toast.add({ title: 'Copied', color: 'success' })
}
</script>

<template>
  <NeedInstance>
    <input ref="importInput" type="file" accept=".conf,text/plain" hidden @change="importFile" />
    <form v-if="auth.isAdmin" class="card mb-4 space-y-3" @submit.prevent="saveEndpoint">
      <UFormField
        label="Public endpoint host"
        help="Name or address clients connect to, in every virtual firewall; used in generated client configs when the interface has no client endpoint of its own."
      >
        <div class="flex flex-wrap gap-2">
          <UInput
            v-model="endpoint.wg_endpoint_host"
            class="w-full max-w-md font-mono"
            placeholder="home.example.org"
          />
          <UButton type="submit">Save</UButton>
        </div>
      </UFormField>
    </form>
    <div v-if="!tunnels.length" class="card space-y-3">
      <UAlert
        icon="i-lucide-key-round"
        title="No WireGuard interface in this virtual firewall"
        description="Add an interface of kind WireGuard (e.g. wg0, listen port 51820), give it an address (e.g. 10.99.0.1/24), and allow its traffic with firewall rules."
        :actions="[{ label: 'Interfaces', to: '/interfaces' }]"
      />
      <UButton
        v-if="auth.canEdit"
        color="neutral"
        variant="outline"
        icon="i-lucide-file-up"
        label="Import config"
        @click="importInput.click()"
      />
    </div>
    <div v-else class="space-y-4">
      <div class="card flex flex-wrap items-center gap-4">
        <USelect v-model="selectedId" :items="tunnelItems" class="w-40" />
        <USwitch
          v-if="selected"
          :model-value="selected.enabled"
          :disabled="!auth.canEdit"
          label="Enabled"
          @update:model-value="setEnabled"
        />
        <div v-if="selected?.description" class="min-w-0 text-sm">
          <div class="text-muted">Description</div>
          <div>{{ selected.description }}</div>
        </div>
        <div v-if="selected" class="min-w-0 text-sm">
          <div class="text-muted">Public key</div>
          <div class="flex items-center gap-1 font-mono break-all">
            {{ selected.wg_public_key }}
            <UButton
              size="xs"
              color="neutral"
              variant="ghost"
              icon="i-lucide-copy"
              @click="copy(selected.wg_public_key)"
            />
          </div>
        </div>
        <div v-if="selected" class="text-sm">
          <div class="text-muted">Listen port</div>
          <div class="font-mono">{{ selected.wg_listen_port || '—' }}</div>
        </div>
        <div v-if="selected" class="text-sm">
          <div class="text-muted">Client endpoint</div>
          <div class="font-mono">{{ selected.wg_endpoint || '—' }}</div>
        </div>
        <div v-if="selected" class="text-sm">
          <div class="text-muted">Client keepalive</div>
          <div class="font-mono">
            {{ selected.wg_keepalive ? `${selected.wg_keepalive}s` : 'off' }}
          </div>
        </div>
        <UButton
          v-if="selected"
          class="ml-auto"
          color="neutral"
          variant="outline"
          :icon="auth.canEdit ? 'i-lucide-pencil' : 'i-lucide-eye'"
          :label="auth.canEdit ? 'Edit' : 'Details'"
          @click="editTunnel"
        />
        <UButton
          v-if="auth.canEdit"
          color="neutral"
          variant="outline"
          icon="i-lucide-file-up"
          label="Import config"
          @click="importInput.click()"
        />
        <UButton
          v-if="auth.canEdit"
          color="neutral"
          variant="outline"
          icon="i-lucide-refresh-cw"
          label="New key"
          @click="rekey"
        />
      </div>
      <UAlert
        v-for="w in freeWarnings"
        :key="w"
        color="warning"
        variant="subtle"
        icon="i-lucide-triangle-alert"
        :title="w"
      />
      <CrudPage
        v-if="selected"
        :key="selected.id"
        :title="`Peers of ${withLabel(selected.label, selected.name)}`"
        noun="peer"
        description="Remote devices and sites. Changes take effect on the next commit."
        :api="wgPeers"
        :params="{ interface_id: selected.id }"
        :columns="columns"
        :fields="fields"
        :defaults="peerDefaults"
        new-label="New peer"
        @changed="loadFree"
      >
        <template #cell-handshake="{ row }">
          <span class="text-xs">{{ ago(handshakes[row.public_key]?.latest_handshake) }}</span>
        </template>
        <template #row-actions="{ row }">
          <UButton
            v-if="auth.canEdit"
            size="xs"
            color="neutral"
            variant="ghost"
            icon="i-lucide-qr-code"
            :title="row.networks?.length ? 'Site config' : 'Client config'"
            @click="showConfig(row)"
          />
        </template>
      </CrudPage>
    </div>

    <UModal
      :open="editOpen"
      :title="`${auth.canEdit ? 'Edit' : 'Interface'} ${selected ? withLabel(selected.label, selected.name) : ''}`"
      :ui="wideModal"
      :dismissible="false"
      @update:open="editGuard.onUpdateOpen"
    >
      <template #body>
        <form id="wg-tunnel-form" @submit.prevent="saveTunnel">
          <fieldset :disabled="!auth.canEdit" class="space-y-3">
            <UFormField
              :ui="inlineField"
              label="Label"
              help="A short name shown before the interface name: VPN (wg0)."
            >
              <UInput v-model="editForm.label" class="w-full" placeholder="VPN" />
            </UFormField>
            <UFormField :ui="inlineField" label="Description">
              <UInput v-model="editForm.description" class="w-full" />
            </UFormField>
            <UFormField :ui="inlineField" label="Enabled">
              <USwitch v-model="editForm.enabled" />
            </UFormField>
            <UFormField
              :ui="inlineField"
              label="IP addresses"
              help="The firewall's tunnel addresses with their prefix length: 10.99.0.1/24, fd00:99::1/64. New peers get free addresses of these prefixes."
            >
              <TagsInput
                v-model="editForm.addresses"
                class="w-full font-mono"
                placeholder="10.99.0.1/24"
                :disabled="!auth.canEdit"
              />
            </UFormField>
            <UFormField
              :ui="inlineField"
              label="Listen port"
              help="Opened automatically in the firewall. 0 for outgoing-only tunnels."
            >
              <UInput v-model.number="editForm.wg_listen_port" type="number" class="w-40" />
            </UFormField>
            <UFormField
              :ui="inlineField"
              label="Public endpoint for clients"
              help="host:port written into generated client configs. Empty: the public endpoint host and the listen port."
            >
              <UInput
                v-model="editForm.wg_endpoint"
                class="w-full font-mono"
                placeholder="vpn.example.org:51820"
              />
            </UFormField>
            <UFormField
              :ui="inlineField"
              label="Client keepalive (seconds)"
              help="PersistentKeepalive in generated client configs; 0 disables it."
            >
              <UInput v-model.number="editForm.wg_keepalive" type="number" class="w-40" />
            </UFormField>
            <UFormField :ui="inlineField" label="MTU" help="0 keeps the default.">
              <UInput v-model.number="editForm.mtu" type="number" class="w-40" />
            </UFormField>
            <p class="text-xs text-muted">
              The name is changed, and the interface deleted, under
              <ULink to="/interfaces" class="underline">Interfaces</ULink>.
            </p>
          </fieldset>
        </form>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton color="neutral" variant="ghost" @click="editGuard.close">{{
            auth.canEdit ? 'Cancel' : 'Close'
          }}</UButton>
          <UButton v-if="auth.canEdit" type="submit" form="wg-tunnel-form" :loading="editSaving"
            >Save</UButton
          >
        </div>
      </template>
    </UModal>

    <UModal
      v-model:open="cfgOpen"
      :title="`${cfg.site ? 'Site' : 'Client'} config: ${cfgPeer?.name}`"
      :ui="{ content: 'max-w-2xl' }"
      :dismissible="false"
    >
      <template #body>
        <div class="space-y-3">
          <UAlert v-for="w in cfg.warnings" :key="w" color="warning" variant="subtle" :title="w" />
          <USwitch
            v-if="!cfg.site"
            v-model="split"
            label="Split tunnel (only this virtual firewall's networks)"
            @update:model-value="loadConfig"
          />
          <div class="flex flex-wrap gap-4">
            <img
              v-if="qr"
              :src="qr"
              alt="QR code of the client config"
              class="rounded bg-white p-2"
              width="280"
              height="280"
            />
            <pre class="min-w-0 flex-1 overflow-x-auto rounded bg-elevated p-3 text-xs">{{
              cfg.config
            }}</pre>
          </div>
          <p v-if="cfg.site" class="text-xs text-muted">
            A wg-quick config for the router at the other site: it routes this virtual firewall's
            networks through the tunnel. On another Portitor, enter the same values instead: a
            WireGuard interface with the address above, and this firewall as a peer with the public
            key and endpoint above and this instance's networks (AllowedIPs) as its networks.
          </p>
          <p v-else class="text-xs text-muted">
            The config contains the client's private key. Scan it with the WireGuard app, or copy it
            into a .conf file.
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
          <UButton label="Close" @click="cfgOpen = false" />
        </div>
      </template>
    </UModal>
  </NeedInstance>
</template>
