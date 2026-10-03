<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onUnmounted, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useDeployStore } from '@/stores/deploy'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const deploy = useDeployStore()
const toast = useToast()
const now = ref(Date.now())
const busy = ref(false)
const tick = setInterval(() => (now.value = Date.now()), 1000)
onUnmounted(() => clearInterval(tick))

const secondsLeft = computed(() => {
  if (!deploy.pending) return 0
  return Math.max(0, Math.round((new Date(deploy.pending.deadline).getTime() - now.value) / 1000))
})

async function confirm() {
  busy.value = true
  try {
    await api.deployConfirm()
    toast.add({ title: `Generation ${deploy.pending.generation} confirmed`, color: 'success' })
  } catch (err) {
    toast.add({ title: errMsg(err, 'Confirm failed'), color: 'error' })
  } finally {
    busy.value = false
    deploy.refresh()
  }
}

async function rollback() {
  busy.value = true
  try {
    await api.deployRollback()
    toast.add({ title: 'Previous configuration restored', color: 'warning' })
  } catch (err) {
    toast.add({ title: errMsg(err, 'Rollback failed'), color: 'error' })
  } finally {
    busy.value = false
    deploy.refresh()
  }
}
</script>

<template>
  <div v-if="deploy.pending" class="flex items-center gap-2">
    <UTooltip
      :text="`Generation ${deploy.pending.generation} is live and rolls back in ${secondsLeft}s unless you confirm it. If this page still works, the change didn't lock you out.`"
    >
      <span class="flex items-center gap-1 text-sm text-warning">
        <UIcon name="i-lucide-timer" class="size-5" />
        <span class="hidden xl:inline">Gen {{ deploy.pending.generation }} rolls back in</span>
        <b class="tabular-nums">{{ secondsLeft }}s</b>
      </span>
    </UTooltip>
    <template v-if="auth.canDeploy">
      <UButton
        size="sm"
        color="neutral"
        variant="outline"
        icon="i-lucide-undo-2"
        aria-label="Roll back now"
        :loading="busy"
        @click="rollback"
        ><span class="hidden lg:inline">Roll back</span></UButton
      >
      <UButton size="sm" color="warning" :loading="busy" icon="i-lucide-check" @click="confirm"
        >Confirm</UButton
      >
    </template>
  </div>
</template>
