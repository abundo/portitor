<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// VrfSelect chooses the VRF a page shows (useVrfChoice); hidden while the
// virtual firewall has no VRFs. Another VRF's forms replace the shown
// ones, so unsaved changes are asked about first, as for another virtual
// firewall.
import { confirmDiscard } from '@/composables/useFormGuard'

defineProps({
  items: { type: Array, required: true },
})
const model = defineModel({ type: Number, required: true })

async function choose(v) {
  if (v !== model.value && (await confirmDiscard())) model.value = v
}
</script>

<template>
  <USelect
    v-if="items.some((i) => i.value > 0)"
    :model-value="model"
    :items="items"
    class="w-64"
    aria-label="VRF"
    icon="i-lucide-split"
    @update:model-value="choose"
  />
</template>
