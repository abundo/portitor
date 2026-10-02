<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// PacketTree: a packet's protocol tree, folded like Wireshark's. Clicking
// a line selects it (its bytes light up in the hex dump). Which lines are
// unfolded lives in `open` (a reactive Set the page owns), keyed by the path
// of field names, so the next packet unfolds the same lines, as in Wireshark.
defineOptions({ name: 'PacketTree' })
const props = defineProps({
  nodes: { type: Array, required: true },
  selected: { type: Object, default: null },
  open: { type: Set, required: true },
  path: { type: String, default: '' },
  depth: { type: Number, default: 0 },
})
const emit = defineEmits(['select'])
function key(n) {
  return `${props.path}/${n.filter || n.label}`
}
function toggle(n) {
  const k = key(n)
  if (props.open.has(k)) props.open.delete(k)
  else props.open.add(k)
}
</script>

<template>
  <ul class="font-mono text-xs">
    <li v-for="(n, i) in nodes" :key="i">
      <div
        class="flex cursor-default items-start gap-1 rounded px-1 hover:bg-elevated"
        :class="n === selected ? 'bg-primary/20' : ''"
        :style="{ paddingLeft: `${depth * 1}rem` }"
        @click="emit('select', n)"
        @dblclick="n.children.length && toggle(n)"
      >
        <button
          v-if="n.children.length"
          type="button"
          class="w-3 shrink-0 text-muted"
          :aria-label="open.has(key(n)) ? 'Fold' : 'Unfold'"
          @click.stop="toggle(n)"
        >
          {{ open.has(key(n)) ? '▾' : '▸' }}
        </button>
        <span v-else class="w-3 shrink-0" />
        <span class="break-all">{{ n.label }}</span>
      </div>
      <PacketTree
        v-if="n.children.length && open.has(key(n))"
        :nodes="n.children"
        :selected="selected"
        :open="open"
        :path="key(n)"
        :depth="depth + 1"
        @select="emit('select', $event)"
      />
    </li>
  </ul>
</template>
