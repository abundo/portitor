// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createReadStream, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import ui from '@nuxt/ui/vite'

// Wiregasm (Wireshark in WebAssembly, GPL-2.0-or-later, for the packet
// capture page) is copied as it is from the npm package into the build's
// wiregasm/, with its LICENSE and a SOURCE note; the dev server serves the
// package's copy at the same path. The capture worker loads it from there.
const wiregasmPkg = fileURLToPath(new URL('./node_modules/@goodtools/wiregasm', import.meta.url))
const wiregasmFiles = ['wiregasm.js', 'wiregasm.wasm.gz', 'wiregasm.data.gz']
function wiregasm() {
  return {
    name: 'portitor-wiregasm',
    configureServer(server) {
      server.middlewares.use('/wiregasm/', (req, res, next) => {
        const name = req.url.replace(/^\//, '').split('?')[0]
        if (!wiregasmFiles.includes(name)) return next()
        res.setHeader(
          'Content-Type',
          name.endsWith('.js') ? 'text/javascript' : 'application/octet-stream',
        )
        createReadStream(join(wiregasmPkg, 'dist', name)).pipe(res)
      })
    },
    generateBundle() {
      const { version, license } = JSON.parse(readFileSync(join(wiregasmPkg, 'package.json')))
      for (const name of wiregasmFiles) {
        this.emitFile({
          type: 'asset',
          fileName: `wiregasm/${name}`,
          source: readFileSync(join(wiregasmPkg, 'dist', name)),
        })
      }
      this.emitFile({
        type: 'asset',
        fileName: 'wiregasm/LICENSE',
        source: readFileSync(join(wiregasmPkg, 'LICENSE')),
      })
      this.emitFile({
        type: 'asset',
        fileName: 'wiregasm/SOURCE',
        source:
          `Wiregasm ${version}, Wireshark compiled to WebAssembly, licensed under\n` +
          `${license} (LICENSE). Source: https://github.com/good-tools/wiregasm\n` +
          `(tag v${version}).\n`,
      })
    },
  }
}

export default defineConfig({
  // Relative, under index.html's <base> (BASE in utils/base.js).
  base: './',
  plugins: [
    vue(),
    wiregasm(),
    ui({
      // Bundle every icon used in src/ at build time; main.js disables
      // Iconify's network API, so nothing is fetched at runtime.
      icon: { clientBundle: { scan: true } },
      ui: {
        colors: { primary: 'emerald', neutral: 'zinc' },
        // Compact tables, so more rows fit on the screen (AGENTS.md).
        table: { slots: { th: 'px-2 py-1.5', td: 'px-2 py-1' } },
      },
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
    // The Help page bundles ../../docs (src/docs.js).
    fs: { allow: ['.', '../../docs'] },
    proxy: {
      '/api': { target: 'http://127.0.0.1:8080', changeOrigin: true, ws: true },
    },
  },
})
