// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import axios from 'axios'
import { BASE } from '@/utils/base'

// Every mutating request is JSON: the server refuses anything else, which
// (with the SameSite=Strict cookie) is the CSRF defence.
const http = axios.create({
  baseURL: `${BASE}api`,
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
})

let onUnauthorized = () => {}
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn
}

// onMutation runs after every successful write, so the "uncommitted
// changes" banner follows edits without polling.
let onMutation = () => {}
export function setMutationHandler(fn) {
  onMutation = fn
}

// onWarnings shows what a save leaves for the commit to refuse (problems
// that were there before it): the CRUD's answer has them in a header,
// /api/config's in its body.
let onWarnings = () => {}
export function setWarningsHandler(fn) {
  onWarnings = fn
}

http.interceptors.response.use(
  (res) => {
    if (res.config.method !== 'get' && !/\/(login|logout)$/.test(res.config.url ?? '')) onMutation()
    const warnings = res.headers?.['x-portitor-warnings'] || res.data?.warnings?.join('; ')
    if (warnings && res.config.method !== 'get') onWarnings(warnings)
    return res
  },
  (err) => {
    if (err.response?.status === 401 && !err.config.url?.endsWith('/login')) {
      onUnauthorized()
    }
    return Promise.reject(err)
  },
)

// errMsg extracts the server's message from an axios error.
// A refusal of the configuration's checks lists its problems, each named
// by its path.
export function errMsg(err, fallback = 'Request failed') {
  const data = err?.response?.data
  if (data?.problems?.length) return data.problems.join('\n')
  if (data?.error && data?.path) return `${data.error} (${data.path})`
  return data?.error ?? err?.message ?? fallback
}

export default http
