<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// TagsInput: a list of values as tags (UInputTags) where a click on a tag
// edits it: the tag leaves the list and its text goes into the input, and
// Enter (or leaving the field) puts it back in its place.
import { ref } from 'vue'

const model = defineModel({ type: Array, default: () => [] })
defineProps({
  placeholder: { type: String, default: '' },
  disabled: { type: Boolean, default: false },
})

const tags = ref(null)
// Where the tag being edited came from, so it goes back there.
let editIndex = null

function input() {
  return tags.value?.inputRef
}

function edit(index) {
  const el = input()
  // Text being typed is not overwritten.
  if (!el || el.value) return
  editIndex = index
  el.value = model.value[index]
  model.value = model.value.filter((_, i) => i !== index)
  el.focus()
}

function onUpdate(v) {
  if (editIndex !== null && v.length === model.value.length + 1) {
    const next = v.slice(0, -1)
    next.splice(Math.min(editIndex, next.length), 0, v[v.length - 1])
    v = next
  }
  editIndex = null
  model.value = v
}

function onBlur() {
  // Leaving the field adds what it holds (add-on-blur) before this runs.
  editIndex = null
}
</script>

<template>
  <UInputTags
    ref="tags"
    :model-value="model"
    class="w-full"
    :placeholder="placeholder"
    :disabled="disabled"
    add-on-blur
    add-on-paste
    @update:model-value="onUpdate"
    @blur="onBlur"
  >
    <template #item-text="{ item, index }">
      <span
        :class="disabled ? '' : 'cursor-text'"
        title="Click to edit"
        @click.stop="!disabled && edit(index)"
        >{{ item }}</span
      >
    </template>
  </UInputTags>
</template>
