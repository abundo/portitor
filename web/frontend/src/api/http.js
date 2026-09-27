// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import axios from 'axios'

// Every mutating request is JSON: the server refuses anything else, which
// (with the SameSite=Strict cookie) is the CSRF defence.
const http = axios.create({
  baseURL: '/api',
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
})

let onUnauthorized = () => {}
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn
}

http.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401 && !err.config.url?.endsWith('/login')) {
      onUnauthorized()
    }
    return Promise.reject(err)
  },
)

// errMsg extracts the server's message from an axios error.
export function errMsg(err, fallback = 'Request failed') {
  return err?.response?.data?.error ?? err?.message ?? fallback
}

export default http
