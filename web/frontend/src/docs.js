// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// The user documentation in docs/*.md, bundled at build time for the Help
// page. Each document is shown under /help/<file name without .md>.

const files = import.meta.glob('../../../docs/*.md', {
  query: '?raw',
  import: 'default',
  eager: true,
})

// The portitor-web guide first, then by title.
const FIRST = 'portitor-web'

export const docs = Object.entries(files)
  .map(([path, markdown]) => {
    const slug = path.split('/').pop().replace(/\.md$/, '')
    const title = markdown.match(/^# (.+)$/m)?.[1] ?? slug
    return { slug, title, markdown }
  })
  .sort((a, b) => (a.slug === FIRST ? -1 : b.slug === FIRST ? 1 : a.title.localeCompare(b.title)))
