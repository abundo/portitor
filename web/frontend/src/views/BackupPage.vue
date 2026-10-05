<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useConfirm } from '@/composables/useConfirm'

const { ask } = useConfirm()
const toast = useToast()

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
      description: 'Review the changes and commit.',
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
</script>

<template>
  <div class="max-w-3xl space-y-4">
    <div class="card">
      <div class="mb-1 text-lg font-semibold">Backup</div>
      <p class="mb-4 text-sm text-muted">
        The whole configuration database, secrets included (WireGuard keys, TSIG secrets, agent
        token), encrypted with a passphrase. Decrypt it outside Portitor with
        <code class="font-mono">age -d</code>.
      </p>
      <form class="flex flex-wrap items-end gap-3" @submit.prevent="downloadBackup">
        <UFormField label="Passphrase" class="min-w-64 flex-1">
          <UInput v-model="backupPass" type="password" class="w-full" autocomplete="new-password" />
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
        Replaces the configuration with a backup; a backup from an older version is upgraded. Users,
        deployment history and the agent connection under Settings stay as they are. Nothing changes
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
  </div>
</template>
