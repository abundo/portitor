// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { createReadStream } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import ui from '@nuxt/ui/vite'

// Wiregasm (Wireshark in WebAssembly, for the packet capture page) is a
// separate program: it is never bundled or copied into the build.
// portitor-web serves it from wiregasm_dir (web.yaml), where install.py
// puts it; the dev server serves the npm package's copy at the same path.
const wiregasmDir = fileURLToPath(
  new URL('./node_modules/@goodtools/wiregasm/dist', import.meta.url),
)
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
        createReadStream(join(wiregasmDir, name)).pipe(res)
      })
    },
  }
}

export default defineConfig({
  base: '/',
  plugins: [
    vue(),
    wiregasm(),
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
    // The Help page bundles ../../docs (src/docs.js).
    fs: { allow: ['.', '../../docs'] },
    proxy: {
      '/api': { target: 'http://127.0.0.1:8080', changeOrigin: true, ws: true },
    },
  },
})
