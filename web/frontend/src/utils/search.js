// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Table search (AGENTS.md, GUI design rules): a row matches when its text
// holds every word typed, in any case.
import { computed, ref, toValue } from 'vue'

// searchWords splits a search text into lower-case words.
export function searchWords(q) {
  return (q ?? '').toLowerCase().split(/\s+/).filter(Boolean)
}

// valuesText joins the strings and numbers in values (arrays and objects
// included) into one text.
export function valuesText(...values) {
  const out = []
  const walk = (v) => {
    if (v == null || typeof v === 'boolean') return
    if (Array.isArray(v)) v.forEach(walk)
    else if (typeof v === 'object') Object.values(v).forEach(walk)
    else out.push(String(v))
  }
  values.forEach(walk)
  return out.join(' ')
}

// matchesWords reports whether text holds every word (from searchWords).
export function matchesWords(text, words) {
  const t = text.toLowerCase()
  return words.every((w) => t.includes(w))
}

// useSearch filters rows (a ref or getter) by the search text; text(row)
// is what a row is searched in, by default all its values.
export function useSearch(rows, text = (row) => valuesText(row)) {
  const search = ref('')
  const words = computed(() => searchWords(search.value))
  const filtered = computed(() => {
    const list = toValue(rows) ?? []
    return words.value.length ? list.filter((r) => matchesWords(text(r), words.value)) : list
  })
  return { search, words, filtered }
}
