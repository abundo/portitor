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
  <div
    v-if="deploy.pending"
    class="flex flex-wrap items-center gap-3 border-b border-warning/40 bg-warning/10 px-4 py-2 text-sm"
  >
    <UIcon name="i-lucide-timer" class="size-5 text-warning" />
    <span>
      Generation {{ deploy.pending.generation }} is live and rolls back in
      <b class="tabular-nums">{{ secondsLeft }}s</b> unless you confirm it. If this page still
      works, the change didn't lock you out.
    </span>
    <div v-if="auth.isAdmin" class="ml-auto flex gap-2">
      <UButton size="sm" color="neutral" variant="outline" :loading="busy" @click="rollback"
        >Roll back now</UButton
      >
      <UButton size="sm" color="warning" :loading="busy" icon="i-lucide-check" @click="confirm"
        >Confirm</UButton
      >
    </div>
  </div>
</template>
