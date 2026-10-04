<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, nextTick, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Marked } from 'marked'
import { docs } from '@/docs'

const route = useRoute()
const router = useRouter()

const REPO = 'https://github.com/abundo/portitor/blob/main/'
const slugs = new Set(docs.map((d) => d.slug))
const esc = (s) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')

// slug makes a heading's id the way GitHub does, so links to #sections
// work here as there.
const slug = (text) =>
  text
    .toLowerCase()
    .trim()
    .replace(/[^\p{L}\p{N}\s_-]/gu, '')
    .replace(/\s/g, '-')

// Links between the docs stay in the GUI, with their #section; links to
// other files of the repository (README.md, ...) go to GitHub, the rest
// open in a new tab.
let seen = new Map() // heading ids of the doc being rendered
const marked = new Marked({
  renderer: {
    heading({ tokens, depth }) {
      const text = this.parser.parseInline(tokens)
      let id = slug(this.parser.parseInline(tokens, this.parser.textRenderer))
      const n = seen.get(id) ?? 0
      seen.set(id, n + 1)
      if (n) id += `-${n}`
      return `<h${depth} id="${esc(id)}">${text}</h${depth}>\n`
    },
    link({ href, tokens }) {
      const text = this.parser.parseInline(tokens)
      const doc = href.match(/^(?:\.\/)?(?:\.\.\/docs\/)?([\w-]+)\.md(?:#(.*))?$/)
      const local = href.match(/^#(.*)$/)
      if ((doc && slugs.has(doc[1])) || local) {
        const target = doc ? doc[1] : current.value.slug
        const hash = (doc ? doc[2] : local[1]) ?? ''
        return `<a href="/help/${target}${hash ? '#' + esc(hash) : ''}" data-help="${target}" data-hash="${esc(hash)}">${text}</a>`
      }
      if (!/^[a-z]+:/i.test(href)) {
        href =
          REPO + new URL(href, 'http://x/docs/').pathname.slice(1) + (href.match(/#.*/)?.[0] ?? '')
      }
      return `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${text}</a>`
    },
  },
})

const current = computed(() => docs.find((d) => d.slug === route.params.doc) ?? docs[0])
const html = computed(() => {
  if (!current.value) return ''
  seen = new Map()
  return marked.parse(current.value.markdown)
})
// TOPICS groups the docs as the main menu (AppMenu.vue) groups the pages;
// a doc not listed here goes under Other.
const TOPICS = [
  { label: 'General', children: ['portitor-web', 'appliance'] },
  { label: 'Network', children: ['nat64'] },
  { label: 'Routing', children: ['bfd', 'vrrp', 'ospf', 'bgp'] },
  { label: 'Firewall', children: ['rules', 'shaping', 'crowdsec'] },
  { label: 'Services', children: ['ntp', 'snmp'] },
]

const items = computed(() => {
  const bySlug = new Map(docs.map((d) => [d.slug, d]))
  const used = new Set()
  const build = (node) => {
    if (typeof node === 'string') {
      const d = bySlug.get(node)
      if (!d) return null
      used.add(node)
      return { label: d.title, to: `/help/${d.slug}`, active: d === current.value }
    }
    const children = node.children.map(build).filter(Boolean)
    return children.length ? { label: node.label, defaultOpen: true, children } : null
  }
  const tree = TOPICS.map(build).filter(Boolean)
  const rest = docs.filter((d) => !used.has(d.slug)).map((d) => d.slug)
  if (rest.length) tree.push(build({ label: 'Other', children: rest }))
  return tree
})

function onClick(e) {
  const a = e.target.closest('a[data-help]')
  if (!a) return
  e.preventDefault()
  const hash = a.dataset.hash ? `#${a.dataset.hash}` : ''
  router.push(`/help/${a.dataset.help}${hash}`)
}

// Scroll to the #section of the URL once the doc is rendered, or to the top
// of the page when there is none.
watch(
  () => [route.params.doc, route.hash],
  async () => {
    await nextTick()
    const id = decodeURIComponent(route.hash.slice(1))
    const el = id && document.getElementById(id)
    if (el) el.scrollIntoView()
    else document.querySelector('main')?.scrollTo(0, 0)
  },
  { immediate: true },
)
</script>

<template>
  <div class="flex flex-col gap-4 lg:flex-row lg:items-start">
    <nav class="card shrink-0 !p-3 lg:sticky lg:top-0 lg:w-56">
      <div class="mb-2 px-2.5 text-sm font-semibold">Topic</div>
      <UNavigationMenu :items="items" orientation="vertical" class="w-full" />
    </nav>
    <!-- v-html: our own docs, bundled at build time -->
    <article
      v-if="current"
      class="card doc min-w-0 max-w-4xl flex-1"
      @click="onClick"
      v-html="html"
    />
    <div v-else class="card text-muted">No documentation in this build.</div>
  </div>
</template>

<style scoped>
.doc {
  line-height: 1.65;
}
.doc :deep(h1) {
  font-size: 1.5rem;
  font-weight: 600;
  margin-bottom: 1rem;
}
.doc :deep(h2) {
  font-size: 1.2rem;
  font-weight: 600;
  margin: 2rem 0 0.75rem;
  padding-bottom: 0.25rem;
  border-bottom: 1px solid var(--ui-border);
}
.doc :deep(h3) {
  font-weight: 600;
  margin: 1.5rem 0 0.5rem;
}
.doc :deep(p),
.doc :deep(ul),
.doc :deep(ol),
.doc :deep(pre),
.doc :deep(table) {
  margin-bottom: 0.9rem;
}
.doc :deep(ul) {
  list-style: disc;
  padding-left: 1.5rem;
}
.doc :deep(ol) {
  list-style: decimal;
  padding-left: 1.5rem;
}
.doc :deep(li) {
  margin-bottom: 0.25rem;
}
.doc :deep(li > p) {
  margin-bottom: 0.4rem;
}
.doc :deep(a) {
  color: var(--ui-primary);
}
.doc :deep(a:hover) {
  text-decoration: underline;
}
.doc :deep(code) {
  font-family: var(--font-mono);
  font-size: 0.875em;
  padding: 0.1rem 0.3rem;
  border-radius: 0.25rem;
  background: var(--ui-bg-elevated);
}
.doc :deep(pre) {
  overflow-x: auto;
  padding: 0.75rem 1rem;
  border-radius: 0.375rem;
  background: var(--ui-bg-elevated);
  font-size: 0.8rem;
  line-height: 1.5;
}
.doc :deep(pre code) {
  padding: 0;
  background: none;
  font-size: inherit;
}
.doc :deep(table) {
  display: block;
  overflow-x: auto;
  border-collapse: collapse;
  font-size: 0.875rem;
}
.doc :deep(th),
.doc :deep(td) {
  padding: 0.35rem 0.75rem;
  border: 1px solid var(--ui-border);
  text-align: left;
  vertical-align: top;
}
.doc :deep(th) {
  background: var(--ui-bg-elevated);
  font-weight: 600;
}
</style>
