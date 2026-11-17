<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// ReplicaBanner: on an HA secondary's portitor-config, whose configuration
// is a read-only copy of the primary's (web/replica.go). It names the
// primary and the last copy, and lets a global admin promote this host
// when the primary is lost (web/promote.go). On the primary's, it says so,
// and warns while the secondary has not copied its configuration
// (web/replication.go).
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
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
const router = useRouter()
const toast = useToast()
const { ask } = useConfirm()

const open = ref(false)
const ha = ref(null)
const busy = ref(false)
const force = ref(false)

const label = computed(() => (ha.value?.stale ? 'Taken over' : 'Cluster secondary'))

// On the primary: whether the secondary holds its configuration, asked every
// 15 s (the replica's interval).
const replication = ref(null)
const isPrimary = computed(() => auth.user?.ha_primary && !auth.user?.replica)
const unprotected = computed(() => replication.value && !replication.value.replicated)
const primaryTip = computed(() => {
  const r = replication.value
  if (!r || r.replicated)
    return (
      "This firewall is its cluster's primary: the cluster's configuration is changed here, and its secondary keeps a read-only copy" +
      (r?.copied ? ` (copied ${clock(r.copied)})` : '')
    )
  let tip =
    'The configuration runs, but the secondary has not copied it yet: losing this firewall now loses it.'
  if (r.error) tip += ` The secondary's copy failed: ${r.error}`
  else if (!r.reported)
    tip += ' The secondary has not reported a copy: it may be unreachable or need an update.'
  else tip += ` The secondary last reported ${clock(r.reported)}.`
  return tip
})
let timer = null
async function pollReplication() {
  try {
    replication.value = (await api.haStatus()).replication || null
  } catch {
    // The next poll tries again.
  }
}
watch(
  isPrimary,
  (on) => {
    clearInterval(timer)
    timer = null
    replication.value = null
    if (on) {
      pollReplication()
      timer = setInterval(pollReplication, 15000)
    }
  },
  { immediate: true },
)
onBeforeUnmount(() => clearInterval(timer))

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
      message: `Make ${ha.value?.local || 'this firewall'} the primary in place of ${primary}?`,
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
  <div v-if="isPrimary" class="flex items-center">
    <UTooltip :text="primaryTip">
      <UBadge
        :color="unprotected ? 'warning' : 'primary'"
        variant="subtle"
        :icon="unprotected ? 'i-lucide-triangle-alert' : 'i-lucide-crown'"
        :label="unprotected ? 'Cluster primary · not copied' : 'Cluster primary'"
        :class="auth.isAdmin ? 'cursor-pointer' : ''"
        @click="auth.isAdmin && router.push('/firewalls')"
      />
    </UTooltip>
  </div>
  <div v-if="auth.user?.replica" class="flex items-center">
    <UTooltip
      text="This firewall's configuration is a read-only copy of its cluster primary's: change it there"
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
    <UModal v-model:open="open" title="Cluster secondary" :dismissible="false" :ui="wideModal">
      <template #body>
        <div v-if="ha" class="space-y-3 text-sm">
          <p v-if="ha.stale">
            This host was the primary, and its secondary was promoted while it was away. Its
            configuration is now a copy of the new primary's, until that one catches it up as its
            secondary.
          </p>
          <p v-else>
            The configuration of this firewall cluster is kept on its primary; this firewall keeps a
            read-only copy, so that it can take over the configuration if the primary is lost.
          </p>
          <UFormField label="This host" :ui="inlineField">{{ ha.local || '?' }}</UFormField>
          <UFormField label="Primary" :ui="inlineField">{{ ha.primary || '?' }}</UFormField>
          <UFormField label="Primary heard" :ui="inlineField">
            {{ ha.peer_alive ? 'yes' : 'no: its agent does not answer this firewall' }}
          </UFormField>
          <UFormField label="Last copy" :ui="inlineField">
            {{ ha.last_copy ? clock(ha.last_copy) : 'none yet' }}
          </UFormField>
          <UFormField v-if="ha.copy_error" label="Copy" :ui="inlineField">
            <span class="text-error">{{ ha.copy_error }}</span>
          </UFormField>
          <template v-if="auth.isAdmin && !ha.stale">
            <p class="text-muted">
              Promote this firewall when the primary is lost: it becomes the primary, with its copy
              of the configuration.
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
