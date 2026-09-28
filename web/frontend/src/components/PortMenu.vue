<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// PortMenu: the port names and ports of usePortMenu, each on one line.
// It goes right after the input: under a `relative` wrapper around it, or
// with `fixed` in viewport coordinates, clear of an overflow that would clip
// it (the rules grid's cells).
import { nextTick, ref, watch } from 'vue'

const props = defineProps({
  menu: { type: Object, default: null },
  fixed: { type: Boolean, default: false },
})
const emit = defineEmits(['pick'])

const list = ref(null)
watch(
  () => props.menu?.active,
  async (n) => {
    await nextTick()
    list.value?.children[n]?.scrollIntoView({ block: 'nearest' })
  },
)
</script>

<template>
  <ul
    v-if="menu"
    ref="list"
    class="port-menu"
    :class="{ 'is-fixed': fixed }"
    role="listbox"
    :style="
      fixed
        ? { top: `${menu.top}px`, left: `${menu.left}px`, minWidth: `${menu.width}px` }
        : undefined
    "
  >
    <li
      v-for="(it, n) in menu.items"
      :key="it.name"
      role="option"
      :aria-selected="n === menu.active"
      :class="{ active: n === menu.active }"
      @pointerdown.prevent="emit('pick', it)"
    >
      <span>{{ it.name }}</span>
      <span class="port">{{ it.port }}</span>
    </li>
  </ul>
</template>

<style>
.port-menu {
  position: absolute;
  top: 100%;
  left: 0;
  min-width: 100%;
  z-index: 50;
  max-height: 16rem;
  overflow-y: auto;
  padding-block: 0.25rem;
  font-family: var(--font-mono);
  font-size: 0.75rem;
  white-space: nowrap;
  background: var(--ui-bg);
  border: 1px solid var(--ui-border-accented);
  border-radius: 0.375rem;
  box-shadow: 0 4px 12px rgb(0 0 0 / 0.15);
}
.port-menu.is-fixed {
  position: fixed;
}
.port-menu li {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.125rem 0.5rem;
  line-height: 1.25rem;
  cursor: pointer;
}
.port-menu li:hover,
.port-menu li.active {
  background: var(--ui-bg-elevated);
}
.port-menu .port {
  color: var(--ui-text-muted);
  font-variant-numeric: tabular-nums;
}
</style>
