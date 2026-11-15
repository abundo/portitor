<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// The portal's frame: AppShell, as the firewall GUI's, with the portal's
// menu and user menu. A firewall opens as its own page (/fw/<name>/), whose
// top bar leads back here.
import { onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import AppShell from '@/layout/AppShell.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import { confirmDiscard } from '@/composables/useFormGuard'
import { portal, session } from './api'

const router = useRouter()
const toast = useToast()
const build = ref(null)
onMounted(async () => {
  try {
    build.value = await portal.version()
  } catch {
    // cosmetic
  }
})

// The session also ends while the page sits idle: look every minute.
const timer = setInterval(
  () => portal.session().then(() => session.user || router.push('/login')),
  60000,
)
watch(
  () => session.user,
  (u) => u || clearInterval(timer),
)

const menu = [
  { label: 'Firewalls', icon: 'i-lucide-shield', to: '/' },
  { label: 'HA witness', icon: 'i-lucide-scale', to: '/witness' },
]

const userMenu = [
  [{ label: session.user, type: 'label' }],
  [
    {
      label: 'Log out',
      icon: 'i-lucide-log-out',
      onSelect: async () => {
        if (!(await confirmDiscard())) return
        await portal.logout()
        toast.clear?.()
        router.push('/login')
      },
    },
  ],
]
</script>

<template>
  <AppShell :build="build">
    <template #topbar>
      <UBadge color="neutral" variant="subtle" label="portitor-web" class="hidden sm:inline-flex" />
      <div class="ml-auto flex items-center gap-2">
        <UTooltip text="Switch between dark and light mode">
          <UColorModeButton />
        </UTooltip>
        <UDropdownMenu :items="userMenu">
          <UButton icon="i-lucide-user" color="neutral" variant="ghost" aria-label="User menu" />
        </UDropdownMenu>
      </div>
    </template>
    <template #menu>
      <UNavigationMenu :items="menu" orientation="vertical" class="w-full" />
    </template>
    <router-view />
  </AppShell>
  <ConfirmDialog />
</template>
