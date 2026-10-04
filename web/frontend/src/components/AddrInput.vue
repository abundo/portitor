<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// AddrInput: addresses/CIDRs, with the names of hosts/prefixes and address
// lists suggested, and with `lists` IP lists ("@name") too. With `multiple`
// the model is an array of entries, otherwise a string.
import { computed, onMounted } from 'vue'
import { useObjectStore } from '@/stores/objects'

const props = defineProps({
  multiple: { type: Boolean, default: false },
  placeholder: { type: String, default: '' },
  disabled: { type: Boolean, default: false },
  lists: { type: Boolean, default: false },
})
const model = defineModel({ type: [Array, String], default: undefined })
const objects = useObjectStore()
onMounted(() => objects.load().catch(() => {}))

// Items must include the current entries, or they would not render as tags.
const items = computed(() => {
  const current = props.multiple ? (model.value ?? []) : []
  return [...new Set([...objects.names, ...(props.lists ? objects.listRefs : []), ...current])]
})

function onCreate(item) {
  const v = item.trim()
  if (v && !model.value.includes(v)) model.value = [...model.value, v]
}
</script>

<template>
  <UInputMenu
    v-if="multiple"
    v-model="model"
    multiple
    create-item
    :items="items"
    :placeholder="placeholder"
    :disabled="disabled"
    class="w-full"
    @create="onCreate"
  />
  <UInputMenu
    v-else
    v-model="model"
    mode="autocomplete"
    :items="items"
    :placeholder="placeholder"
    :disabled="disabled"
    class="w-full font-mono"
  />
</template>
