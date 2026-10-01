<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { useConfirm } from '@/composables/useConfirm'
import { onMounted, reactive, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useDeployStore } from '@/stores/deploy'
import { usePageForm } from '@/composables/useFormGuard'

const { ask } = useConfirm()

const toast = useToast()
const deploy = useDeployStore()
const settings = reactive({
  agent_url: '',
  agent_token: '',
  agent_fingerprint: '',
  confirm_timeout: 120,
  wg_endpoint_host: '',
  capture_rate_kbps: 1000,
})
// Only the settings count as unsaved changes, not the backup and restore
// fields.
const settingsForm = usePageForm(settings)
const hasToken = ref(false)
const version = ref(null)

async function load() {
  const s = await api.settings()
  Object.assign(settings, s, { agent_token: '' })
  hasToken.value = s.has_agent_token
  settingsForm.mark()
  version.value = await api.version()
}
onMounted(load)

const backupPass = ref('')
const backingUp = ref(false)
const restoreFile = ref(null)
const restorePass = ref('')
const restoring = ref(false)

// blobErrMsg reads the server's message from an error whose response was
// requested as a Blob.
async function blobErrMsg(err) {
  const data = err?.response?.data
  if (data instanceof Blob) {
    try {
      return JSON.parse(await data.text()).error ?? errMsg(err)
    } catch {
      /* not JSON */
    }
  }
  return errMsg(err)
}

async function downloadBackup() {
  backingUp.value = true
  try {
    const res = await api.backup(backupPass.value)
    const name =
      /filename="([^"]+)"/.exec(res.headers['content-disposition'] ?? '')?.[1] ?? 'portitor.db.age'
    const url = URL.createObjectURL(res.data)
    const a = document.createElement('a')
    a.href = url
    a.download = name
    a.click()
    URL.revokeObjectURL(url)
    backupPass.value = ''
  } catch (err) {
    toast.add({ title: await blobErrMsg(err), color: 'error' })
  } finally {
    backingUp.value = false
  }
}

function onRestoreFile(event) {
  restoreFile.value = event.target.files?.[0] ?? null
}

// readBase64 reads a file as base64 (without the data: URL prefix).
function readBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader()
    r.onload = () => resolve(String(r.result).replace(/^data:[^,]*,/, ''))
    r.onerror = () => reject(r.error)
    r.readAsDataURL(file)
  })
}

async function restoreBackup() {
  if (
    !(await ask({
      title: 'Restore backup',
      message: `Replace the configuration with ${restoreFile.value.name}? Changes made since the backup are lost. Nothing is deployed until you deploy.`,
    }))
  )
    return
  restoring.value = true
  try {
    const res = await api.restore(await readBase64(restoreFile.value), restorePass.value)
    toast.add({
      title: res.migrated
        ? `Backup restored (upgraded from schema ${res.schema_version})`
        : 'Backup restored',
      description: 'Review the changes and deploy.',
      color: 'success',
    })
    // Every page and store holds data from before the restore.
    setTimeout(() => window.location.reload(), 1500)
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    restoring.value = false
  }
}

async function saveSettings() {
  try {
    const s = await api.saveSettings({
      ...settings,
      confirm_timeout: Number(settings.confirm_timeout),
      capture_rate_kbps: Number(settings.capture_rate_kbps),
    })
    hasToken.value = s.has_agent_token
    settings.agent_token = ''
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
          label="Public WireGuard endpoint host"
          help="Name or address clients connect to; used in generated client configs."
        >
          <UInput
            v-model="settings.wg_endpoint_host"
            class="w-full font-mono"
            placeholder="home.example.org"
          />
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
      <div class="card">
        <div class="mb-1 text-lg font-semibold">Backup</div>
        <p class="mb-4 text-sm text-muted">
          The whole configuration database, secrets included (WireGuard keys, TSIG secrets, agent
          token), encrypted with a passphrase. Decrypt it outside Portitor with
          <code class="font-mono">age -d</code>.
        </p>
        <form class="flex flex-wrap items-end gap-3" @submit.prevent="downloadBackup">
          <UFormField label="Passphrase" class="min-w-64 flex-1">
            <UInput
              v-model="backupPass"
              type="password"
              class="w-full"
              autocomplete="new-password"
            />
          </UFormField>
          <UButton
            type="submit"
            icon="i-lucide-download"
            :loading="backingUp"
            :disabled="backupPass.length < 10"
            >Download backup</UButton
          >
        </form>
        <p class="mt-1 text-xs text-muted">At least 10 characters. It cannot be recovered.</p>
      </div>

      <div class="card">
        <div class="mb-1 text-lg font-semibold">Restore</div>
        <p class="mb-4 text-sm text-muted">
          Replaces the configuration with a backup; a backup from an older version is upgraded.
          Users, deployment history and the agent connection above stay as they are. Nothing changes
          on the firewall until you deploy.
        </p>
        <form class="space-y-3" @submit.prevent="restoreBackup">
          <UFormField label="Backup file">
            <input
              type="file"
              accept=".age,.db,.sqlite"
              class="block w-full text-sm file:mr-3 file:rounded file:border-0 file:bg-elevated file:px-3 file:py-1.5"
              @change="onRestoreFile"
            />
          </UFormField>
          <UFormField label="Passphrase" help="Not needed for an unencrypted database file.">
            <UInput v-model="restorePass" type="password" class="w-full" autocomplete="off" />
          </UFormField>
          <UButton
            type="submit"
            color="warning"
            icon="i-lucide-upload"
            :loading="restoring"
            :disabled="!restoreFile"
            >Restore</UButton
          >
        </form>
      </div>

      <p v-if="version" class="text-xs text-muted">
        portitor-web {{ version.version }} ({{ version.commit.slice(0, 8) }}),
        {{ version.go_version }}
      </p>
    </div>
  </div>
</template>
