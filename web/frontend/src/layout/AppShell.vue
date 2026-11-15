<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// AppShell: the frame of a Portitor GUI, the firewall's (AppLayout) and the
// portal's (portal/PortalLayout): the top bar with the menu button, the logo
// and the version, then the `topbar` slot; the menu (`menu` slot) as a
// sidebar on a wide screen, which the button hides and shows and the browser
// remembers, or a slideover on a narrow one; the page (default slot) and the
// `bottom` slot under both. It knows no store, so both GUIs share it.
import { computed, ref, watch } from 'vue'
import { useRoute } from 'vue-router'

// build is /api/version's answer (version, commit, date), or null.
const props = defineProps({
  build: { type: Object, default: null },
  home: { type: String, default: '/' },
  title: { type: String, default: 'Portitor' },
})

// goreleaser stamps the tag without its v (1.2.3), the Makefile `git describe`.
const version = computed(() => {
  const v = props.build?.version
  if (!v) return ''
  return /^\d/.test(v) ? `v${v}` : v
})

const mobileMenu = ref(false)
const MENU_KEY = 'menu.open'
const wide = window.matchMedia('(min-width: 1024px)')
const sidebar = ref(readSidebar())

function readSidebar() {
  try {
    return localStorage.getItem(MENU_KEY) !== 'false'
  } catch {
    return true
  }
}

function toggleMenu() {
  if (!wide.matches) {
    mobileMenu.value = !mobileMenu.value
    return
  }
  sidebar.value = !sidebar.value
  try {
    localStorage.setItem(MENU_KEY, String(sidebar.value))
  } catch {
    // Not remembered; the toggle works without it.
  }
}

const route = useRoute()
watch(
  () => route.path,
  () => (mobileMenu.value = false),
)
</script>

<template>
  <div class="flex h-screen flex-col overflow-hidden">
    <header class="flex h-14 shrink-0 items-center gap-3 border-b border-default px-3 md:px-4">
      <UTooltip text="Show or hide the menu">
        <UButton
          icon="i-lucide-menu"
          color="neutral"
          variant="ghost"
          aria-label="Menu"
          @click="toggleMenu"
        />
      </UTooltip>
      <RouterLink :to="home" class="flex items-center gap-2 font-semibold">
        <UIcon name="i-lucide-shield" class="size-6 text-primary" />
        <span class="hidden sm:inline">{{ title }}</span>
      </RouterLink>
      <UTooltip
        v-if="version"
        :text="`commit ${(build.commit ?? '').slice(0, 12)}, ${build.date ?? ''}`"
      >
        <span class="hidden font-mono text-xs text-muted sm:inline">{{ version }}</span>
      </UTooltip>
      <slot name="topbar" />
    </header>
    <div class="flex min-h-0 flex-1">
      <aside
        v-if="sidebar"
        class="hidden w-60 shrink-0 overflow-y-auto border-r border-default p-3 lg:block"
      >
        <slot name="menu" />
      </aside>
      <main class="min-w-0 flex-1 overflow-auto p-4 md:p-6">
        <slot />
      </main>
    </div>
    <slot name="bottom" />
  </div>
  <USlideover v-model:open="mobileMenu" side="left" title="Menu">
    <template #body>
      <slot name="menu" />
    </template>
  </USlideover>
</template>
