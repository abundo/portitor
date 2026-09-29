<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
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
  tunnels.value.map((t) => ({ label: withLabel(t.label, t.name), value: t.id })),
)

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
    !window.confirm(
      `Generate a new key for ${withLabel(selected.value.label, selected.value.name)}? Every peer needs the new public key.`,
    )
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
  return t.wg_listen_port
    ? `the endpoint host under Settings, port ${t.wg_listen_port}`
    : 'none set'
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
    <div v-if="!tunnels.length" class="card">
      <UAlert
        icon="i-lucide-key-round"
        title="No WireGuard interface in this instance"
        description="Add an interface of kind WireGuard (e.g. wg0, listen port 51820), give it an address under IP addresses, and allow its traffic with firewall rules."
        :actions="[{ label: 'Interfaces', to: '/interfaces' }]"
      />
    </div>
    <div v-else class="space-y-4">
      <div class="card flex flex-wrap items-center gap-4">
        <USelect v-model="selectedId" :items="tunnelItems" class="w-40" />
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
          v-if="auth.isAdmin"
          class="ml-auto"
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
        description="Remote devices and sites. Changes take effect on the next deploy."
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
            v-if="auth.isAdmin"
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
      v-model:open="cfgOpen"
      :title="`${cfg.site ? 'Site' : 'Client'} config: ${cfgPeer?.name}`"
      :ui="{ content: 'max-w-2xl' }"
    >
      <template #body>
        <div class="space-y-3">
          <UAlert v-for="w in cfg.warnings" :key="w" color="warning" variant="subtle" :title="w" />
          <USwitch
            v-if="!cfg.site"
            v-model="split"
            label="Split tunnel (only this instance's networks)"
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
            A wg-quick config for the router at the other site: it routes this instance's networks
            through the tunnel. On another Portitor, enter the same values instead: a WireGuard
            interface with the address above, and this firewall as a peer with the public key and
            endpoint above and this instance's networks (AllowedIPs) as its networks.
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
