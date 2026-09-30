<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { ref } from 'vue'

// PacketTree: a packet's protocol tree, folded like Wireshark's. Clicking
// a line selects it (its bytes light up in the hex dump).
defineOptions({ name: 'PacketTree' })
defineProps({
  nodes: { type: Array, required: true },
  selected: { type: Object, default: null },
  depth: { type: Number, default: 0 },
})
const emit = defineEmits(['select'])
const open = ref(new Set())
function toggle(i) {
  const s = new Set(open.value)
  if (s.has(i)) s.delete(i)
  else s.add(i)
  open.value = s
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
        @dblclick="n.children.length && toggle(i)"
      >
        <button
          v-if="n.children.length"
          type="button"
          class="w-3 shrink-0 text-muted"
          :aria-label="open.has(i) ? 'Fold' : 'Unfold'"
          @click.stop="toggle(i)"
        >
          {{ open.has(i) ? '▾' : '▸' }}
        </button>
        <span v-else class="w-3 shrink-0" />
        <span class="break-all">{{ n.label }}</span>
      </div>
      <PacketTree
        v-if="n.children.length && open.has(i)"
        :nodes="n.children"
        :selected="selected"
        :depth="depth + 1"
        @select="emit('select', $event)"
      />
    </li>
  </ul>
</template>
