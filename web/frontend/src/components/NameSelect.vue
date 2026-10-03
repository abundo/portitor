<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// NameSelect: picks a name from items ({ label, value, description }), or
// none ('' in the model, "—" in the menu: Reka's select can't hold ''). A
// name the items lack stays visible, so a stale reference shows.
import { computed } from 'vue'

const model = defineModel({ type: String, default: '' })
const props = defineProps({
  items: { type: Array, default: () => [] },
  disabled: { type: Boolean, default: false },
  placeholder: { type: String, default: '—' },
})

const NONE = '\u0000'
const all = computed(() => {
  const list = [{ label: '—', value: NONE }, ...props.items]
  if (model.value && !props.items.some((it) => it.value === model.value))
    list.push({ label: model.value, value: model.value, description: 'does not exist' })
  return list
})
const value = computed({
  get: () => model.value || NONE,
  set: (v) => (model.value = v === NONE ? '' : v),
})
const selected = computed(() => all.value.find((it) => it.value === value.value))
</script>

<template>
  <USelect
    v-model="value"
    :items="all"
    class="w-full"
    :disabled="disabled"
    :placeholder="placeholder"
  >
    <template v-if="selected" #default>
      <span class="truncate">
        {{ selected.label }}
        <span v-if="selected.description" class="text-muted"> — {{ selected.description }}</span>
      </span>
    </template>
  </USelect>
</template>
