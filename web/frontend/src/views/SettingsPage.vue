<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api, certificates } from '@/api'
import { errMsg } from '@/api/http'
import { useDeployStore } from '@/stores/deploy'
import { useInstanceStore } from '@/stores/instances'
import { useAuthStore } from '@/stores/auth'
import { usePageForm } from '@/composables/useFormGuard'

const toast = useToast()
const deploy = useDeployStore()
const instStore = useInstanceStore()
const auth = useAuthStore()
const settings = reactive({
  agent_url: '',
  agent_token: '',
  agent_fingerprint: '',
  confirm_timeout: 120,
  capture_rate_kbps: 1000,
  web_certificate_id: 0,
  virtual_firewalls: false,
})
const settingsForm = usePageForm(settings)
const hasToken = ref(false)
const webTLS = ref(false)
const version = ref(null)

// Every instance's certificates, for the one portitor-web serves.
const certs = ref([])
const certItems = computed(() => [
  { label: 'None (tls_cert from web.yaml)', value: 0 },
  ...certs.value.map((c) => ({
    label: `${instStore.nameOf(c.instance_id)}/${c.name} (${c.domains.join(', ')})`,
    value: c.id,
  })),
])

async function load() {
  const s = await api.settings()
  Object.assign(settings, s, { agent_token: '', web_certificate_id: s.web_certificate_id ?? 0 })
  hasToken.value = s.has_agent_token
  webTLS.value = s.web_tls
  settingsForm.mark()
  version.value = await api.version()
  certs.value = await certificates.list()
}
onMounted(load)

async function saveSettings() {
  try {
    const s = await api.saveSettings({
      ...settings,
      confirm_timeout: Number(settings.confirm_timeout),
      capture_rate_kbps: Number(settings.capture_rate_kbps),
    })
    hasToken.value = s.has_agent_token
    settings.agent_token = ''
    settings.web_certificate_id = s.web_certificate_id ?? 0
    settings.virtual_firewalls = s.virtual_firewalls
    if (auth.user) auth.user.virtual_firewalls = s.virtual_firewalls
    settingsForm.mark()
    toast.add({ title: 'Settings saved', color: 'success' })
    deploy.refresh()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
</script>

<template>
  <div class="grid gap-4 xl:grid-cols-2">
    <div class="card xl:col-span-2">
      <div class="mb-1 text-lg font-semibold">Portitor web</div>
      <p class="mb-4 text-sm text-muted">
        The certificate the GUI serves HTTPS with, from Services → Certificates. portitor-web
        fetches it from the agent, and again when it is renewed; until it has it, and when none is
        chosen, it serves <code class="font-mono">tls_cert</code>. Its domain must be the name you
        browse to.
      </p>
      <form class="space-y-3" @submit.prevent="saveSettings">
        <UFormField label="Certificate">
          <USelect
            v-model="settings.web_certificate_id"
            :items="certItems"
            class="w-full max-w-xl"
            :disabled="!webTLS"
          />
        </UFormField>
        <UAlert
          v-if="!webTLS"
          color="neutral"
          variant="subtle"
          icon="i-lucide-info"
          title="portitor-web does not serve HTTPS itself"
          description="Set tls_cert and tls_key in web.yaml (the ISO's setup does) and restart it to choose a certificate here; behind a reverse proxy, give the proxy the certificate instead."
        />
        <UFormField
          label="Virtual firewalls"
          help="Several virtual firewalls, each its own namespace, connected by links. Shows the Virtual firewalls and Links pages. Can't be turned off while there is more than one virtual firewall."
        >
          <USwitch
            v-model="settings.virtual_firewalls"
            :disabled="settings.virtual_firewalls && instStore.list.length > 1"
          />
        </UFormField>
        <UButton type="submit">Save</UButton>
      </form>
    </div>

    <div class="card">
      <div class="mb-1 text-lg font-semibold">Portitor agent</div>
      <p class="mb-4 text-sm text-muted">
        Run <code class="font-mono">portitor-agent init --host &lt;address&gt;</code> on the
        firewall; it prints the token and the certificate fingerprint.
      </p>
      <form class="space-y-3" @submit.prevent="saveSettings">
        <UFormField label="Agent URL"
          ><UInput
            v-model="settings.agent_url"
            class="w-full font-mono"
            placeholder="https://192.168.1.1:8443"
        /></UFormField>
        <UFormField
          label="Token"
          :help="hasToken ? 'A token is stored. Leave empty to keep it.' : 'Not set.'"
        >
          <UInput
            v-model="settings.agent_token"
            type="password"
            class="w-full font-mono"
            autocomplete="off"
          />
        </UFormField>
        <UFormField
          label="Certificate fingerprint (SHA-256)"
          help="Pins the agent's self-signed certificate. Empty: verify against system CAs."
        >
          <UInput v-model="settings.agent_fingerprint" class="w-full font-mono text-xs" />
        </UFormField>
        <UFormField
          label="Default auto-rollback (seconds)"
          help="After an apply, the agent restores the previous configuration unless you confirm within this time. 0 disables it."
        >
          <UInput v-model="settings.confirm_timeout" type="number" class="w-40" />
        </UFormField>
        <UFormField
          label="Packet capture rate (kbit/s)"
          help="The most a packet capture sends from the agent to portitor-web. When it falls behind, the firewall drops captured packets rather than slow down. 0 is unlimited."
        >
          <UInput v-model="settings.capture_rate_kbps" type="number" min="0" class="w-40" />
        </UFormField>
        <div class="flex items-center gap-3">
          <UButton type="submit">Save</UButton>
          <UBadge v-if="deploy.error" color="error" variant="subtle" :label="deploy.error" />
          <UBadge
            v-else-if="deploy.status"
            color="success"
            variant="subtle"
            :label="`connected to ${deploy.status.hostname}`"
          />
        </div>
      </form>
    </div>

    <div class="space-y-4">
      <p v-if="version" class="text-xs text-muted">
        portitor-web {{ version.version }} ({{ version.commit.slice(0, 8) }}),
        {{ version.go_version }}
      </p>
    </div>
  </div>
</template>
