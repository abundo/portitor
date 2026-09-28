<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Marked } from 'marked'
import { docs } from '@/docs'

const route = useRoute()
const router = useRouter()

const REPO = 'https://github.com/abundo/portitor/blob/main/'
const slugs = new Set(docs.map((d) => d.slug))
const esc = (s) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')

// Links between the docs stay in the GUI; links to other files of the
// repository (README.md, ...) go to GitHub, the rest open in a new tab.
const marked = new Marked({
  renderer: {
    link({ href, tokens }) {
      const text = this.parser.parseInline(tokens)
      const doc = href.match(/^(?:\.\/)?(?:\.\.\/docs\/)?([\w-]+)\.md(#.*)?$/)
      if (doc && slugs.has(doc[1])) {
        return `<a href="/help/${doc[1]}" data-help="${doc[1]}">${text}</a>`
      }
      if (!/^[a-z]+:/i.test(href) && !href.startsWith('#')) {
        href =
          REPO + new URL(href, 'http://x/docs/').pathname.slice(1) + (href.match(/#.*/)?.[0] ?? '')
      }
      return `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${text}</a>`
    },
  },
})

const current = computed(() => docs.find((d) => d.slug === route.params.doc) ?? docs[0])
const html = computed(() => (current.value ? marked.parse(current.value.markdown) : ''))
const items = computed(() =>
  docs.map((d) => ({ label: d.title, to: `/help/${d.slug}`, active: d === current.value })),
)

function onClick(e) {
  const a = e.target.closest('a[data-help]')
  if (!a) return
  e.preventDefault()
  router.push(`/help/${a.dataset.help}`)
}
</script>

<template>
  <div class="flex flex-col gap-4 lg:flex-row lg:items-start">
    <nav class="card shrink-0 !p-3 lg:sticky lg:top-0 lg:w-56">
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
