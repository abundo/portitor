<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { onMounted } from 'vue'
import ConsoleTerminal from '@/components/ConsoleTerminal.vue'

// The console alone in a popup window (no menu or top bar).
onMounted(() => (document.title = 'Console · Portitor'))
</script>

<template>
  <div class="h-screen bg-default p-2">
    <ConsoleTerminal />
  </div>
</template>
