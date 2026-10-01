<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// A Wunderbaum treegrid (Hosts & prefixes). The page builds the nodes:
// { key, title, icon (HTML), expanded, children, cells: { <column id>: HTML } }.
// A click on a row opens it (open), a right click asks for its menu (menu),
// and folding a node reports it (toggle) so the page can keep it folded.
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { Wunderbaum } from 'wunderbaum'
import 'wunderbaum/dist/wunderbaum.css'
import '@/assets/wunderbaum-theme.css'

const props = defineProps({
  source: { type: Array, required: true },
  // [{ id, title, width }]; the first is the tree column ('*').
  columns: { type: Array, required: true },
})
const emit = defineEmits(['open', 'menu', 'toggle'])

const el = ref(null)
let tree

function render(e) {
  const cells = e.node.data.cells ?? {}
  for (const col of Object.values(e.renderColInfosById ?? {}))
    col.elem.innerHTML = cells[col.id] ?? ''
}

function onContextMenu(ev) {
  const node = Wunderbaum.getNode(ev)
  if (node) node.setActive()
  emit('menu', ev, node?.data ?? null, node?.key)
}

onMounted(() => {
  tree = new Wunderbaum({
    element: el.value,
    header: true,
    debugLevel: 0,
    rowHeightPx: 30,
    navigationModeOption: 'row',
    iconMap: {
      ...Wunderbaum.iconMaps?.bootstrap,
      expanderExpanded: '<i class="wb-expander">−</i>',
      expanderCollapsed: '<i class="wb-expander">+</i>',
      expanderLazy: '<i class="wb-expander">+</i>',
    },
    source: props.source,
    columns: props.columns,
    columnsResizable: true,
    render,
    click: (e) => {
      if (!e.node || e.info?.region === 'expander') return
      emit('open', e.node.data, e.node.key)
    },
    expand: (e) => emit('toggle', e.node.key, e.node.expanded),
  })
  el.value.addEventListener('contextmenu', onContextMenu)
})

watch(
  () => props.source,
  (source) => tree?.load(source),
)

onBeforeUnmount(() => {
  el.value?.removeEventListener('contextmenu', onContextMenu)
  // destroy() replaces the element (outerHTML); only stop the observer.
  tree?.resizeObserver?.disconnect()
  tree = null
})
</script>

<template>
  <div ref="el" class="object-tree" />
</template>
