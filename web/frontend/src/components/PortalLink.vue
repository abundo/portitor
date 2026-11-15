<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// PortalLink: behind portitor-web (the GUI served at /fw/<name>/), a way
// back to the portal's own pages, its list of firewalls. A full page load:
// the portal is another application. In the portal's tab (framed) its
// own tab strip leads back.
import { framed, portal } from '@/utils/base'
import { confirmDiscard } from '@/composables/useFormGuard'

async function go() {
  if (await confirmDiscard()) window.location.assign('/')
}
</script>

<template>
  <UTooltip v-if="portal && !framed" text="Back to portitor-web's firewalls">
    <UButton
      icon="i-lucide-layout-grid"
      color="neutral"
      variant="ghost"
      label="Portal"
      class="hidden md:inline-flex"
      @click="go"
    />
  </UTooltip>
</template>
