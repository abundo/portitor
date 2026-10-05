<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { useConfirm } from '@/composables/useConfirm'
import { computed, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useDeployStore } from '@/stores/deploy'
import { useAuthStore } from '@/stores/auth'

const { ask } = useConfirm()

const auth = useAuthStore()
const deploy = useDeployStore()
const toast = useToast()
const busy = ref(false)
const reverting = ref(false)

const changes = computed(() => deploy.changes)
// The topbar shows a short label; the full sentence is its tooltip.
const label = computed(() =>
  changes.value?.problems ? `${changes.value.problems} problem(s)` : 'Uncommitted changes',
)
const detail = computed(() => {
  const c = changes.value
  if (c?.problems)
    return `There are uncommitted changes with ${c.problems} problem(s) to fix before they can be committed.`
  if (deploy.pending)
    return 'There are uncommitted changes. Confirm or roll back the pending generation first.'
  if (!c?.deployed) return 'Nothing has been committed to the firewall yet.'
  return 'There are uncommitted changes that are not on the firewall yet.'
})
const blocked = computed(() => !!changes.value?.problems || !!deploy.pending)

// Commit applies with the configured auto-rollback, so a change that locks
// the GUI out still undoes itself. With no changes it applies the deployed
// config again, which the rollback would only apply once more, so it is
// confirmed at once (timeout 0).
async function commit() {
  busy.value = true
  try {
    const res = await api.deployApply(changes.value?.changed ? undefined : 0)
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
    !(await ask({
      title: 'Revert',
      message:
        'Revert all uncommitted changes? The configuration goes back to what is committed on the firewall.',
    }))
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
  <div class="flex items-center gap-2">
    <template v-if="changes?.changed">
      <UTooltip :text="detail">
        <span
          class="flex items-center gap-1 text-sm"
          :class="changes.problems ? 'text-warning' : 'text-info'"
        >
          <UIcon name="i-lucide-circle-alert" class="size-5" />
          <span class="hidden xl:inline">{{ label }}</span>
        </span>
      </UTooltip>
      <UButton
        size="sm"
        color="neutral"
        variant="outline"
        to="/deploy"
        icon="i-lucide-file-diff"
        aria-label="Review"
        ><span class="hidden lg:inline">Review</span></UButton
      >
      <UButton
        v-if="changes.deployed && auth.isAdmin"
        size="sm"
        color="neutral"
        variant="outline"
        icon="i-lucide-undo-2"
        aria-label="Revert"
        :loading="reverting"
        :disabled="busy"
        @click="revert"
        ><span class="hidden lg:inline">Revert</span></UButton
      >
    </template>
    <!-- Always there: with no changes, a commit applies the current config again. -->
    <UButton
      v-if="auth.canDeploy"
      size="sm"
      color="info"
      icon="i-lucide-rocket"
      :loading="busy"
      :disabled="blocked || reverting"
      @click="commit"
      >Commit</UButton
    >
  </div>
</template>
