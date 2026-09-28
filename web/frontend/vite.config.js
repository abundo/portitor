// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import ui from '@nuxt/ui/vite'

export default defineConfig({
  base: '/',
  plugins: [
    vue(),
    ui({
      // Bundle every icon used in src/ at build time; main.js disables
      // Iconify's network API, so nothing is fetched at runtime.
      icon: { clientBundle: { scan: true } },
      ui: { colors: { primary: 'emerald', neutral: 'zinc' } },
    }),
  ],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  build: {
    // Straight into the directory portitor-web serves (and embeds).
    outDir: '../static',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': { target: 'http://127.0.0.1:8080', changeOrigin: true, ws: true },
    },
  },
})
