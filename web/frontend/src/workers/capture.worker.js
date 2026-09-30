// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

/* global importScripts, loadWiregasm */

// The packet capture worker: it streams a capture from portitor-web
// (/api/agent/capture) into Wiregasm, Wireshark compiled to WebAssembly,
// and answers the page's questions about it (packet list, one packet's
// tree and bytes, display filter checks). Wiregasm dissects a whole file at
// a time, so a live capture is dissected again as it grows, no more often
// than every second or twice as long as the last dissection took.
//
// Messages in:  {type: 'start', body}, {type: 'stop'},
//               {type: 'frames', id, filter, skip, limit},
//               {type: 'frame', id, number}, {type: 'check', id, filter},
//               {type: 'pcap', id}
// Messages out: {type: 'ready', columns} or {type: 'fatal', error},
//               {type: 'progress', bytes, packets, running},
//               {type: 'ended', error}, {type: 'reply', id, result, error}

let lib = null
let session = null
let chunks = []
let size = 0
// complete is where the last whole pcap record ends: the stream arrives in
// pieces that can split a packet, and Wiregasm refuses a truncated file.
let complete = 0
let recHdr = [] // bytes of the file or record header being read
let recSkip = 0 // packet data still to pass over
let recLE = true
let controller = null
let dirty = false // data arrived since the last dissection
let busy = false
let lastLoadMs = 0
let timer = null
let packets = 0
let running = false

const toArray = (vec) => Array.from({ length: vec.size() }, (_, i) => vec.get(i))

// fetchOk fetches a Wiregasm file; portitor-web answers 404 with why
// (Wiregasm is installed separately, by install.py).
async function fetchOk(url) {
  const res = await fetch(url)
  if (!res.ok) throw new Error((await res.text()).trim() || `${url}: ${res.status}`)
  return res
}

async function gunzip(url) {
  const res = await fetchOk(url)
  return new Response(res.body.pipeThrough(new DecompressionStream('gzip'))).arrayBuffer()
}

async function init() {
  await fetchOk('/wiregasm/wiregasm.js') // a clear error before importScripts' vague one
  importScripts('/wiregasm/wiregasm.js')
  const [wasmBinary, data] = await Promise.all([
    gunzip('/wiregasm/wiregasm.wasm.gz'),
    gunzip('/wiregasm/wiregasm.data.gz'),
  ])
  lib = await loadWiregasm({
    wasmBinary,
    getPreloadedPackage: () => data,
    print: () => {},
    printErr: () => {},
    handleStatus: () => {},
  })
  if (!lib.init()) throw new Error('Wiregasm failed to initialize')
  postMessage({ type: 'ready', columns: toArray(lib.getColumns()) })
}

// scan follows the pcap records through a new piece of the stream and
// moves complete to the end of the last whole one.
function scan(chunk) {
  const base = size - chunk.length
  for (let i = 0; i < chunk.length; ) {
    if (recSkip > 0) {
      const n = Math.min(recSkip, chunk.length - i)
      recSkip -= n
      i += n
      if (recSkip === 0) complete = base + i
      continue
    }
    const want = complete === 0 && base + i < 24 ? 24 : 16
    while (recHdr.length < want && i < chunk.length) recHdr.push(chunk[i++])
    if (recHdr.length < want) break
    const dv = new DataView(Uint8Array.from(recHdr).buffer)
    recHdr = []
    if (want === 24) {
      const magic = dv.getUint32(0, true)
      recLE = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d
      complete = base + i
    } else {
      recSkip = dv.getUint32(8, recLE)
      if (recSkip === 0) complete = base + i
    }
  }
}

// dissect loads the capture so far into a new session.
function dissect() {
  timer = null
  if (!dirty || busy || !lib) return
  busy = true
  dirty = false
  const t0 = performance.now()
  try {
    const buf = new Uint8Array(size)
    let off = 0
    for (const c of chunks) {
      buf.set(c, off)
      off += c.length
    }
    chunks = [buf] // keep one piece; later chunks append to it
    const path = lib.getUploadDirectory() + '/capture.pcap'
    lib.FS.writeFile(path, buf.subarray(0, complete))
    const next = new lib.DissectSession(path)
    const res = next.load()
    if (res.code === 0) {
      session?.delete()
      session = next
      packets = res.summary.packet_count
    } else {
      next.delete()
    }
  } finally {
    busy = false
    lastLoadMs = performance.now() - t0
  }
  postMessage({ type: 'progress', bytes: size, packets, running })
  schedule()
}

function schedule() {
  if (dirty && !timer) timer = setTimeout(dissect, Math.max(1000, 2 * lastLoadMs))
}

async function start(body) {
  stop()
  session?.delete()
  session = null
  chunks = []
  size = 0
  complete = 0
  recHdr = []
  recSkip = 0
  packets = 0
  dirty = false
  controller = new AbortController()
  running = true
  postMessage({ type: 'progress', bytes: 0, packets: 0, running })
  let error = null
  try {
    const res = await fetch('/api/agent/capture', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    })
    if (!res.ok) {
      let msg = res.statusText
      try {
        msg = (await res.json()).error ?? msg
      } catch {
        /* not JSON */
      }
      throw new Error(msg)
    }
    const reader = res.body.getReader()
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      chunks.push(value)
      size += value.length
      scan(value)
      dirty = true
      schedule()
    }
  } catch (err) {
    if (err.name !== 'AbortError') error = err.message
  } finally {
    running = false
    controller = null
  }
  // The last packets, without waiting for the timer.
  clearTimeout(timer)
  timer = null
  dirty = dirty || size > 0
  dissect()
  postMessage({ type: 'ended', error })
}

function stop() {
  controller?.abort()
}

// treeNodes converts a protocol tree to plain objects.
function treeNodes(vec) {
  return toArray(vec).map((n) => ({
    label: n.label,
    filter: n.filter,
    start: n.start,
    length: n.length,
    source: n.data_source_idx,
    children: treeNodes(n.tree),
  }))
}

const handlers = {
  frames({ filter, skip, limit }) {
    if (!session) return { frames: [], matched: 0 }
    const res = session.getFrames(filter, skip, limit)
    return {
      matched: res.matched,
      frames: toArray(res.frames).map((f) => ({
        number: f.number,
        bg: f.bg,
        fg: f.fg,
        columns: toArray(f.columns),
      })),
    }
  },
  frame({ number }) {
    if (!session) return null
    const f = session.getFrame(number)
    return {
      number: f.number,
      tree: treeNodes(f.tree),
      sources: toArray(f.data_sources).map((d) => ({ name: d.name, data: d.data })),
    }
  },
  check({ filter }) {
    if (!lib) return { ok: true }
    const r = lib.checkFilter(filter)
    return { ok: r.ok, error: r.error }
  },
  pcap() {
    return new Blob(chunks, { type: 'application/vnd.tcpdump.pcap' })
  },
}

onmessage = (e) => {
  const m = e.data
  if (m.type === 'start') start(m.body)
  else if (m.type === 'stop') stop()
  else if (handlers[m.type]) {
    try {
      postMessage({ type: 'reply', id: m.id, result: handlers[m.type](m) })
    } catch (err) {
      postMessage({ type: 'reply', id: m.id, error: String(err?.message ?? err) })
    }
  }
}

init().catch((err) => postMessage({ type: 'fatal', error: String(err?.message ?? err) }))
