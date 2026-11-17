<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// The portal's frame: AppShell, as the firewall GUI's, with the portal's
// menu and user menu. Above it a tab per firewall opened: its GUI
// (/fw/<name>/) in an iframe, kept loaded while another tab shows.
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from '@nuxt/ui/composables'
import AppShell from '@/layout/AppShell.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import { confirmDiscard } from '@/composables/useFormGuard'
import { portal, session } from './api'
import { closeAll, closeTab, frames, tabs } from './tabs'

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

// A tab's GUI found the portal's session gone: the portal's login.
function onMessage(e) {
  if (e.origin === window.location.origin && e.data?.portitor === 'portal-login')
    router.push('/login')
}
window.addEventListener('message', onMessage)
onBeforeUnmount(() => window.removeEventListener('message', onMessage))

function setFrame(name, el) {
  if (el) frames.set(name, el)
  else frames.delete(name)
}

const menu = [
  { label: 'Firewalls', icon: 'i-lucide-shield', to: '/', exact: true },
  { label: 'Cluster witness', icon: 'i-lucide-scale', to: '/witness' },
]

const userMenu = [
  [{ label: session.user, type: 'label' }],
  [
    {
      label: 'Log out',
      icon: 'i-lucide-log-out',
      onSelect: async () => {
        if (!(await confirmDiscard()) || !(await closeAll())) return
        await portal.logout()
        toast.clear?.()
        router.push('/login')
      },
    },
  ],
]
</script>

<template>
  <div class="flex h-screen flex-col overflow-hidden">
    <nav
      v-if="tabs.open.length"
      class="flex h-9 shrink-0 items-end gap-1 overflow-x-auto border-b border-default bg-elevated px-2"
      aria-label="Firewalls opened"
    >
      <button
        type="button"
        class="tab"
        :class="{ active: tabs.active === '' }"
        @click="tabs.active = ''"
      >
        <UIcon name="i-lucide-layout-grid" class="size-4" />
        portitor-manager
      </button>
      <div
        v-for="t in tabs.open"
        :key="t.name"
        class="tab"
        :class="{ active: tabs.active === t.name }"
        role="button"
        tabindex="0"
        @click="tabs.active = t.name"
        @keydown.enter="tabs.active = t.name"
        @auxclick.middle="closeTab(t.name)"
      >
        <UIcon name="i-lucide-shield" class="size-4" />
        {{ t.name }}
        <UButton
          icon="i-lucide-x"
          size="xs"
          color="neutral"
          variant="ghost"
          :aria-label="`Close ${t.name}`"
          @click.stop="closeTab(t.name)"
        />
      </div>
    </nav>
    <div class="relative min-h-0 flex-1">
      <div v-show="tabs.active === ''" class="h-full">
        <AppShell fill :build="build">
          <template #topbar>
            <UBadge
              color="neutral"
              variant="subtle"
              label="portitor-manager"
              class="hidden sm:inline-flex"
            />
            <div class="ml-auto flex items-center gap-2">
              <UTooltip text="Switch between dark and light mode">
                <UColorModeButton />
              </UTooltip>
              <UDropdownMenu :items="userMenu">
                <UButton
                  icon="i-lucide-user"
                  color="neutral"
                  variant="ghost"
                  aria-label="User menu"
                />
              </UDropdownMenu>
            </div>
          </template>
          <template #menu>
            <UNavigationMenu :items="menu" orientation="vertical" class="w-full" />
          </template>
          <router-view />
        </AppShell>
      </div>
      <iframe
        v-for="t in tabs.open"
        v-show="tabs.active === t.name"
        :key="t.name"
        :ref="(el) => setFrame(t.name, el)"
        :src="t.path"
        :title="`${t.name}'s GUI`"
        class="absolute inset-0 size-full border-0"
      />
    </div>
  </div>
  <ConfirmDialog />
</template>

<style scoped>
.tab {
  display: inline-flex;
  align-items: center;
  gap: 0.375rem;
  height: 2rem;
  padding: 0 0.5rem 0 0.75rem;
  border: 1px solid transparent;
  border-bottom: none;
  border-radius: 0.375rem 0.375rem 0 0;
  font-size: 0.875rem;
  white-space: nowrap;
  cursor: pointer;
  color: var(--ui-text-muted);
}
.tab:first-child {
  padding-right: 0.75rem;
}
.tab.active {
  background: var(--ui-bg);
  border-color: var(--ui-border);
  color: var(--ui-text);
  margin-bottom: -1px;
}
</style>
