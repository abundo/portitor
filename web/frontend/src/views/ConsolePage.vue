<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import ConsoleTerminal from '@/components/ConsoleTerminal.vue'
import { openConsoleWindow } from '@/composables/useConsoleWindow'
import { useInstanceStore } from '@/stores/instances'

const instances = useInstanceStore()
</script>

<template>
  <div class="card flex h-full min-h-[24rem] flex-col gap-3">
    <div>
      <div class="text-lg font-semibold">Console</div>
      <p class="text-sm text-muted">
        A shell on the firewall, as portitor-agent's console user, in the network namespace of
        instance <span class="font-semibold">{{ instances.current?.name }}</span
        >. It ends when you leave this page.
      </p>
    </div>
    <ConsoleTerminal
      v-if="instances.current"
      :instance="instances.current.name"
      class="min-h-0 flex-1"
    >
      <template #actions>
        <UButton
          icon="i-lucide-external-link"
          size="sm"
          color="neutral"
          variant="ghost"
          label="Open in window"
          @click="openConsoleWindow(instances.currentId)"
        />
      </template>
    </ConsoleTerminal>
  </div>
</template>
