<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useInstanceStore } from '@/stores/instances'
import { useDeployStore } from '@/stores/deploy'

defineEmits(['toggle-menu'])

const auth = useAuthStore()
const instances = useInstanceStore()
const deploy = useDeployStore()
const router = useRouter()

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
  [{ label: auth.user?.username, type: 'label' }],
  [
    { label: 'Settings', icon: 'i-lucide-settings', onSelect: () => router.push('/settings') },
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
      <UDropdownMenu :items="userMenu">
        <UButton icon="i-lucide-user" color="neutral" variant="ghost" />
      </UDropdownMenu>
    </div>
  </header>
</template>
