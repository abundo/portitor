<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { onMounted, onUnmounted, ref, watch } from 'vue'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'

// A shell on the firewall: portitor-agent runs it as its console user
// (portitor) and portitor-web passes the WebSocket through. Binary
// messages are terminal data both ways; the one text message is a resize.
// The shell runs in the network namespace of the named instance.
const props = defineProps({ instance: { type: String, default: '' } })
const el = ref(null)
const status = ref('connecting') // connecting, open, closed
const reason = ref('')

let term = null
let fit = null
let ws = null
let observer = null

const encoder = new TextEncoder()

function sendSize() {
  if (ws?.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ cols: term.cols, rows: term.rows }))
  }
}

function connect() {
  status.value = 'connecting'
  reason.value = ''
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  const q = props.instance ? `?instance=${encodeURIComponent(props.instance)}` : ''
  ws = new WebSocket(`${proto}//${location.host}/api/agent/console${q}`)
  ws.binaryType = 'arraybuffer'
  ws.onopen = () => {
    status.value = 'open'
    sendSize()
    term.focus()
  }
  ws.onmessage = (e) => {
    if (e.data instanceof ArrayBuffer) term.write(new Uint8Array(e.data))
  }
  ws.onclose = (e) => {
    status.value = 'closed'
    reason.value = e.reason || (e.code === 1006 ? 'connection lost' : `closed (${e.code})`)
    term.write(`\r\n\x1b[2m[${reason.value}]\x1b[0m\r\n`)
  }
}

function reconnect() {
  if (ws) {
    ws.onclose = null
    ws.close()
  }
  term.reset()
  connect()
}

onMounted(() => {
  term = new Terminal({
    cursorBlink: true,
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
    fontSize: 13,
    scrollback: 5000,
  })
  fit = new FitAddon()
  term.loadAddon(fit)
  term.open(el.value)
  fit.fit()
  term.onData((d) => {
    if (ws?.readyState === WebSocket.OPEN) ws.send(encoder.encode(d))
  })
  term.onResize(sendSize)
  observer = new ResizeObserver(() => fit.fit())
  observer.observe(el.value)
  connect()
})

onUnmounted(() => {
  observer?.disconnect()
  if (ws) {
    ws.onclose = null
    ws.close()
  }
  term?.dispose()
})

// Switching instance starts a new shell in the new namespace.
watch(
  () => props.instance,
  () => term && reconnect(),
)

defineExpose({ reconnect })
</script>

<template>
  <div class="flex h-full min-h-0 flex-col">
    <div class="flex shrink-0 items-center gap-2 pb-2 text-sm">
      <UBadge
        :color="status === 'open' ? 'success' : status === 'connecting' ? 'neutral' : 'error'"
        variant="subtle"
        size="sm"
        :label="
          status === 'open' ? 'connected' : status === 'connecting' ? 'connecting…' : 'disconnected'
        "
      />
      <span v-if="status === 'closed'" class="truncate text-muted">{{ reason }}</span>
      <div class="ml-auto flex items-center gap-1">
        <slot name="actions" />
        <UButton
          icon="i-lucide-rotate-cw"
          size="sm"
          color="neutral"
          variant="ghost"
          :label="status === 'closed' ? 'Reconnect' : 'Restart'"
          @click="reconnect"
        />
      </div>
    </div>
    <div class="min-h-0 flex-1 rounded-md bg-black p-2">
      <div ref="el" class="h-full w-full"></div>
    </div>
  </div>
</template>
