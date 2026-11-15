<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useInstanceStore } from '@/stores/instances'
import { useDeployStore } from '@/stores/deploy'
import { useLogPanel } from '@/composables/useLogPanel'
import { openConsoleWindow } from '@/composables/useConsoleWindow'
import { openCaptureWindow } from '@/composables/useCaptureWindow'
import { confirmDiscard } from '@/composables/useFormGuard'
import ConfirmBanner from '@/components/ConfirmBanner.vue'
import ChangesBanner from '@/components/ChangesBanner.vue'
import ReplicaBanner from '@/components/ReplicaBanner.vue'
import FirewallSwitcher from '@/components/FirewallSwitcher.vue'
import PortalLink from '@/components/PortalLink.vue'

const auth = useAuthStore()
const instances = useInstanceStore()
const deploy = useDeployStore()
const router = useRouter()
const { state: logPanel, toggle: toggleLog } = useLogPanel()

const current = computed({
  get: () => instances.currentName ?? undefined,
  // The page is remounted for the new instance: unsaved changes are lost.
  set: async (v) => (await confirmDiscard()) && instances.select(v),
})

const agentChip = computed(() => {
  if (deploy.error) return { color: 'error', label: 'agent unreachable', title: deploy.error }
  if (!deploy.status) return { color: 'neutral', label: 'agent …' }
  if (deploy.status.last_error)
    return {
      color: 'warning',
      label: `gen ${deploy.status.generation}`,
      title: deploy.status.last_error,
    }
  return {
    color: 'success',
    label: `gen ${deploy.status.generation}`,
    title: `applied generation ${deploy.status.generation}`,
  }
})

const userMenu = computed(() => [
  [{ label: auth.user?.full_name || auth.user?.username, type: 'label' }],
  [
    { label: 'My settings', icon: 'i-lucide-user-cog', onSelect: () => router.push('/profile') },
    {
      label: 'Change password',
      icon: 'i-lucide-key-round',
      onSelect: () => router.push('/profile/password'),
    },
  ],
  [
    {
      label: 'Log out',
      icon: 'i-lucide-log-out',
      onSelect: async () => {
        if (!(await confirmDiscard())) return
        await auth.logout()
        router.push('/login')
      },
    },
  ],
])
</script>

<template>
  <!-- The top bar's contents after AppShell's logo and version. -->
  <PortalLink />
  <FirewallSwitcher />
  <div v-if="auth.user?.virtual_firewalls" class="ml-2 flex items-center gap-2">
    <span class="hidden text-sm text-muted md:inline">VF</span>
    <USelect v-model="current" :items="instances.topItems" class="w-56" placeholder="none" />
  </div>
  <ReplicaBanner />
  <ConfirmBanner />
  <ChangesBanner v-if="!auth.replica" />
  <div class="ml-auto flex items-center gap-2">
    <UTooltip
      v-if="!auth.canEdit && !auth.replica"
      text="Your user can look at this virtual firewall but not change it"
    >
      <UBadge color="neutral" variant="outline" icon="i-lucide-eye" label="Read-only" />
    </UTooltip>
    <UTooltip v-if="deploy.status?.version_mismatch" :text="deploy.status.version_mismatch">
      <UBadge
        color="warning"
        variant="subtle"
        icon="i-lucide-triangle-alert"
        label="Version mismatch"
        class="cursor-pointer"
        @click="router.push('/updates')"
      />
    </UTooltip>
    <UTooltip :text="agentChip.title ?? ''">
      <UBadge
        :color="agentChip.color"
        variant="subtle"
        :label="agentChip.label"
        class="cursor-pointer"
        @click="router.push('/')"
      />
    </UTooltip>
    <UTooltip :text="logPanel.open ? 'Hide log panel' : 'Show agent log and logged packets'">
      <UButton
        icon="i-lucide-terminal"
        color="neutral"
        :variant="logPanel.open ? 'soft' : 'ghost'"
        aria-label="Log panel"
        @click="toggleLog"
      />
    </UTooltip>
    <UTooltip v-if="auth.isAdmin" text="Open console window">
      <UButton
        icon="i-lucide-square-terminal"
        color="neutral"
        variant="ghost"
        aria-label="Console"
        :disabled="!instances.currentName"
        @click="openConsoleWindow(instances.currentName)"
      />
    </UTooltip>
    <UTooltip v-if="auth.canEdit" text="Open packet capture window">
      <UButton
        icon="i-lucide-radio-tower"
        color="neutral"
        variant="ghost"
        aria-label="Packet capture"
        :disabled="!instances.currentName"
        @click="openCaptureWindow(instances.currentName)"
      />
    </UTooltip>
    <UTooltip text="Switch between dark and light mode">
      <UColorModeButton />
    </UTooltip>
    <UDropdownMenu :items="userMenu">
      <UButton icon="i-lucide-user" color="neutral" variant="ghost" aria-label="User menu" />
    </UDropdownMenu>
  </div>
</template>
