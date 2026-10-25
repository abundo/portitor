<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// ReplicaBanner: on an HA secondary's portitor-config, whose configuration
// is a read-only copy of the primary's (web/replica.go). It names the
// primary and the last copy, and lets a global admin promote this host
// when the primary is lost (web/promote.go).
import { computed, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { useDeployStore } from '@/stores/deploy'
import { useConfirm } from '@/composables/useConfirm'
import { clock } from '@/utils/time'
import { inlineField, wideModal } from '@/utils/form'

const auth = useAuthStore()
const deploy = useDeployStore()
const toast = useToast()
const { ask } = useConfirm()

const open = ref(false)
const ha = ref(null)
const busy = ref(false)
const force = ref(false)

const label = computed(() => (ha.value?.stale ? 'Taken over' : 'HA secondary'))

async function show() {
  try {
    ha.value = await api.haStatus()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
    return
  }
  force.value = false
  open.value = true
}

async function promote() {
  const primary = ha.value?.primary || 'the primary'
  if (
    !(await ask({
      title: 'Promote',
      message: `Make ${ha.value?.local || 'this host'} the primary in place of ${primary}?`,
      detail: `Its copy of the configuration becomes the pair's and is committed here; ${primary} becomes the secondary and is caught up when it answers. Changes on ${primary} since the last copy are lost.`,
    }))
  )
    return
  busy.value = true
  try {
    const res = await api.haPromote(force.value)
    toast.add({ title: `Promoted: commit ${res.commit} ${res.status}`, color: 'success' })
    open.value = false
    await auth.fetchCurrentUser()
    deploy.refresh()
  } catch (err) {
    toast.add({ title: errMsg(err, 'Promotion failed'), color: 'error' })
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div v-if="auth.user?.replica" class="flex items-center">
    <UTooltip
      text="This host's configuration is a read-only copy of its HA primary's: change it there"
    >
      <UBadge
        color="warning"
        variant="subtle"
        icon="i-lucide-copy"
        :label="label"
        class="cursor-pointer"
        @click="show"
      />
    </UTooltip>
    <UModal v-model:open="open" title="HA secondary" :dismissible="false" :ui="wideModal">
      <template #body>
        <div v-if="ha" class="space-y-3 text-sm">
          <p v-if="ha.stale">
            This host was the primary, and its secondary was promoted while it was away. Its
            configuration is now a copy of the new primary's, until that one catches it up as its
            secondary.
          </p>
          <p v-else>
            The configuration of this HA pair is kept on its primary; this host keeps a read-only
            copy, so that it can take over the configuration if the primary is lost.
          </p>
          <UFormField label="This host" :ui="inlineField">{{ ha.local || '?' }}</UFormField>
          <UFormField label="Primary" :ui="inlineField">{{ ha.primary || '?' }}</UFormField>
          <UFormField label="Primary heard" :ui="inlineField">
            {{ ha.peer_alive ? 'yes' : 'no: its agent does not answer this host' }}
          </UFormField>
          <UFormField label="Last copy" :ui="inlineField">
            {{ ha.last_copy ? clock(ha.last_copy) : 'none yet' }}
          </UFormField>
          <UFormField v-if="ha.copy_error" label="Copy" :ui="inlineField">
            <span class="text-error">{{ ha.copy_error }}</span>
          </UFormField>
          <template v-if="auth.isAdmin && !ha.stale">
            <p class="text-muted">
              Promote this host when the primary is lost: it becomes the primary, with its copy of
              the configuration.
            </p>
            <UFormField v-if="ha.peer_alive" label="Force" :ui="inlineField">
              <UCheckbox
                v-model="force"
                label="Promote though the primary answers (both then own the configuration until it is caught up)"
              />
            </UFormField>
          </template>
        </div>
      </template>
      <template #footer>
        <div class="flex w-full justify-end gap-2">
          <UButton color="neutral" variant="outline" @click="open = false">Close</UButton>
          <UButton
            v-if="auth.isAdmin && ha && !ha.stale"
            color="warning"
            icon="i-lucide-crown"
            :loading="busy"
            :disabled="ha.peer_alive && !force"
            @click="promote"
            >Promote</UButton
          >
        </div>
      </template>
    </UModal>
  </div>
</template>
