<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import ConsoleTerminal from '@/components/ConsoleTerminal.vue'
import { openConsoleWindow } from '@/composables/useConsoleWindow'
</script>

<template>
  <div class="card flex h-full min-h-[24rem] flex-col gap-3">
    <div>
      <div class="text-lg font-semibold">Console</div>
      <p class="text-sm text-muted">
        A shell on the firewall, as portitor-agent's console user. It ends when you leave this page.
      </p>
    </div>
    <ConsoleTerminal class="min-h-0 flex-1">
      <template #actions>
        <UButton
          icon="i-lucide-external-link"
          size="sm"
          color="neutral"
          variant="ghost"
          label="Open in window"
          @click="openConsoleWindow"
        />
      </template>
    </ConsoleTerminal>
  </div>
</template>
