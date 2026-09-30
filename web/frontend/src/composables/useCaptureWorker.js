// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import { onScopeDispose, ref } from 'vue'

// useCaptureWorker runs the packet capture worker (workers/capture.worker.js)
// for as long as the calling component lives, and wraps its messages:
// state as refs, questions as promises.
export function useCaptureWorker() {
  const worker = new Worker(new URL('../workers/capture.worker.js', import.meta.url))
  const ready = ref(false)
  const fatal = ref('')
  const columns = ref([])
  const running = ref(false)
  const bytes = ref(0)
  const packets = ref(0)
  // generation counts the dissections, so views know to refresh.
  const generation = ref(0)
  let onEnded = () => {}

  let nextId = 1
  const pending = new Map()

  worker.onmessage = (e) => {
    const m = e.data
    switch (m.type) {
      case 'ready':
        columns.value = m.columns
        ready.value = true
        break
      case 'fatal':
        fatal.value = m.error
        break
      case 'progress':
        bytes.value = m.bytes
        packets.value = m.packets
        running.value = m.running
        generation.value++
        break
      case 'ended':
        running.value = false
        onEnded(m.error)
        break
      case 'reply': {
        const p = pending.get(m.id)
        pending.delete(m.id)
        if (m.error) p?.reject(new Error(m.error))
        else p?.resolve(m.result)
        break
      }
    }
  }
  worker.onerror = (e) => {
    fatal.value = e.message || 'the capture worker failed to start'
  }

  function ask(type, args = {}) {
    const id = nextId++
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject })
      worker.postMessage({ type, id, ...args })
    })
  }

  onScopeDispose(() => worker.terminate())

  return {
    ready,
    fatal,
    columns,
    running,
    bytes,
    packets,
    generation,
    start: (body) => {
      running.value = true
      worker.postMessage({ type: 'start', body })
    },
    stop: () => worker.postMessage({ type: 'stop' }),
    onEnded: (fn) => (onEnded = fn),
    frames: (filter, skip, limit) => ask('frames', { filter, skip, limit }),
    frame: (number) => ask('frame', { number }),
    checkFilter: (filter) => ask('check', { filter }),
    pcap: () => ask('pcap'),
  }
}
