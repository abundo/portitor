<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// PortMenu: the service names and ports of usePortMenu, each on one line,
// and last an entry that creates a custom service (`create`).
// It goes right after the input: under a `relative` wrapper around it, or
// with `fixed` in viewport coordinates, clear of an overflow that would clip
// it (the rules grid's cells).
import { nextTick, ref, watch } from 'vue'

const props = defineProps({
  menu: { type: Object, default: null },
  fixed: { type: Boolean, default: false },
})
const emit = defineEmits(['pick', 'create'])

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
    <li
      role="option"
      class="create"
      :aria-selected="menu.active === menu.items.length"
      :class="{ active: menu.active === menu.items.length }"
      @pointerdown.prevent="emit('create')"
    >
      <span>
        <UIcon name="i-lucide-plus" class="size-3 align-middle" />
        New service{{ menu.newName ? ` ${menu.newName}` : '' }}…
      </span>
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
.port-menu li.create {
  margin-block-start: 0.25rem;
  padding-block-start: 0.25rem;
  border-block-start: 1px solid var(--ui-border);
  color: var(--ui-primary);
  font-family: var(--font-sans);
}
.port-menu .port {
  color: var(--ui-text-muted);
  font-variant-numeric: tabular-nums;
}
</style>
