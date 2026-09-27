// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { defineConfig, globalIgnores } from 'eslint/config'
import globals from 'globals'
import js from '@eslint/js'
import pluginVue from 'eslint-plugin-vue'
import pluginOxlint from 'eslint-plugin-oxlint'
import skipFormatting from 'eslint-config-prettier/flat'

export default defineConfig([
  { name: 'app/files-to-lint', files: ['**/*.{vue,js,mjs}'] },
  globalIgnores(['**/dist/**', '**/coverage/**']),
  { languageOptions: { globals: { ...globals.browser } } },
  js.configs.recommended,
  ...pluginVue.configs['flat/essential'],
  ...pluginOxlint.buildFromOxlintConfigFile('.oxlintrc.json'),
  skipFormatting,
])
