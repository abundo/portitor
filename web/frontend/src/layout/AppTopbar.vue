<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useInstanceStore } from '@/stores/instances'
import { useDeployStore } from '@/stores/deploy'
import { useLogPanel } from '@/composables/useLogPanel'
import { openConsoleWindow } from '@/composables/useConsoleWindow'
import { api } from '@/api'

defineEmits(['toggle-menu'])

const auth = useAuthStore()
const instances = useInstanceStore()
const deploy = useDeployStore()
const router = useRouter()
const { state: logPanel, toggle: toggleLog } = useLogPanel()

// goreleaser stamps the tag without its v (1.2.3), the Makefile `git describe`.
const build = ref(null)
const version = computed(() => {
  const v = build.value?.version
  if (!v) return ''
  return /^\d/.test(v) ? `v${v}` : v
})
onMounted(async () => {
  try {
    build.value = await api.version()
  } catch {
    // the version is cosmetic; leave it out
  }
})

const current = computed({
  get: () => instances.currentId ?? undefined,
  set: (v) => instances.select(v),
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
        await auth.logout()
        router.push('/login')
      },
    },
  ],
])
</script>

<template>
  <header class="flex h-14 shrink-0 items-center gap-3 border-b border-default px-3 md:px-4">
    <UButton
      class="lg:hidden"
      icon="i-lucide-menu"
      color="neutral"
      variant="ghost"
      @click="$emit('toggle-menu')"
    />
    <RouterLink to="/" class="flex items-center gap-2 font-semibold">
      <UIcon name="i-lucide-shield" class="size-6 text-primary" />
      <span class="hidden sm:inline">Portitor</span>
    </RouterLink>
    <UTooltip v-if="version" :text="`commit ${build.commit.slice(0, 12)}, ${build.date}`">
      <span class="hidden font-mono text-xs text-muted sm:inline">{{ version }}</span>
    </UTooltip>
    <div class="ml-2 flex items-center gap-2">
      <span class="hidden text-sm text-muted md:inline">Instance</span>
      <USelect v-model="current" :items="instances.items" class="w-40" placeholder="none" />
    </div>
    <div class="ml-auto flex items-center gap-2">
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
      <UTooltip text="Open console window">
        <UButton
          icon="i-lucide-square-terminal"
          color="neutral"
          variant="ghost"
          aria-label="Console"
          @click="openConsoleWindow"
        />
      </UTooltip>
      <UDropdownMenu :items="userMenu">
        <UButton icon="i-lucide-user" color="neutral" variant="ghost" aria-label="User menu" />
      </UDropdownMenu>
    </div>
  </header>
</template>
