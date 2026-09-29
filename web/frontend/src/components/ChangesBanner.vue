<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useDeployStore } from '@/stores/deploy'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const deploy = useDeployStore()
const toast = useToast()
const busy = ref(false)
const reverting = ref(false)

const changes = computed(() => deploy.changes)
const blocked = computed(() => !!changes.value?.problems || !!deploy.pending)

// Commit applies with the configured auto-rollback, so a change that locks
// the GUI out still undoes itself.
async function commit() {
  busy.value = true
  try {
    const res = await api.deployApply()
    toast.add({
      title: `Generation ${res.deployment.generation} ${res.deployment.status}`,
      color: 'success',
    })
  } catch (err) {
    toast.add({
      title: errMsg(err, 'Commit failed'),
      description: (err.response?.data?.problems ?? []).join('\n') || undefined,
      color: 'error',
      actions: [{ label: 'Deploy page', to: '/deploy' }],
    })
  } finally {
    busy.value = false
    deploy.refresh()
  }
}

// Revert puts the database back to what the firewall runs; nothing is
// applied.
async function revert() {
  if (
    !window.confirm(
      'Revert all uncommitted changes? The configuration goes back to what is committed on the firewall.',
    )
  )
    return
  reverting.value = true
  try {
    const res = await api.deployRevert()
    toast.add({ title: `Reverted to generation ${res.generation}`, color: 'success' })
    // Every page and store holds data from before the revert.
    setTimeout(() => window.location.reload(), 1000)
  } catch (err) {
    toast.add({ title: errMsg(err, 'Revert failed'), color: 'error' })
  } finally {
    reverting.value = false
  }
}
</script>

<template>
  <div
    v-if="changes?.changed"
    class="flex flex-wrap items-center gap-3 border-b border-info/40 bg-info/10 px-4 py-2 text-sm"
  >
    <UIcon name="i-lucide-circle-alert" class="size-5 text-info" />
    <span v-if="changes.problems">
      There are uncommitted changes with {{ changes.problems }} problem(s) to fix before they can be
      committed.
    </span>
    <span v-else-if="deploy.pending">
      There are uncommitted changes. Confirm or roll back the pending generation first.
    </span>
    <span v-else-if="!changes.deployed"> Nothing has been committed to the firewall yet. </span>
    <span v-else>There are uncommitted changes that are not on the firewall yet.</span>
    <div class="ml-auto flex gap-2">
      <UButton size="sm" color="neutral" variant="outline" to="/deploy" icon="i-lucide-file-diff"
        >Review</UButton
      >
      <UButton
        v-if="changes.deployed && auth.isAdmin"
        size="sm"
        color="neutral"
        variant="outline"
        icon="i-lucide-undo-2"
        :loading="reverting"
        :disabled="busy"
        @click="revert"
        >Revert</UButton
      >
      <UButton
        v-if="auth.isAdmin"
        size="sm"
        color="info"
        icon="i-lucide-rocket"
        :loading="busy"
        :disabled="blocked || reverting"
        @click="commit"
        >Commit</UButton
      >
    </div>
  </div>
</template>
