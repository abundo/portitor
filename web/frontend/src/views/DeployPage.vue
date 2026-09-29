<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { diffLines } from 'diff'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useDeployStore } from '@/stores/deploy'
import { datetime } from '@/utils/time'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const toast = useToast()
const deploy = useDeployStore()
const check = ref(null)
const preview = ref(null)
const previewError = ref(null)
const history = ref([])
const busy = ref(false)
const confirmTimeout = ref(120)
const applyResult = ref(null)
const showUnchanged = ref(false)

async function load() {
  const [c, h, s] = await Promise.all([api.deployCheck(), api.deployments(), api.settings()])
  check.value = c
  history.value = h
  confirmTimeout.value = s.confirm_timeout
}
onMounted(load)

async function runPreview() {
  busy.value = true
  previewError.value = null
  try {
    preview.value = await api.deployPreview()
  } catch (err) {
    previewError.value = { error: errMsg(err), problems: err.response?.data?.problems ?? [] }
  } finally {
    busy.value = false
  }
}

async function apply() {
  busy.value = true
  applyResult.value = null
  try {
    const res = await api.deployApply(Number(confirmTimeout.value))
    applyResult.value = { ok: true, ...res }
    toast.add({
      title: `Generation ${res.deployment.generation} ${res.deployment.status}`,
      color: 'success',
    })
    preview.value = null
  } catch (err) {
    applyResult.value = {
      ok: false,
      error: errMsg(err),
      problems: err.response?.data?.problems ?? [],
      result: err.response?.data?.result,
    }
  } finally {
    busy.value = false
    deploy.refresh()
    load()
  }
}

// Per-file diff of the preview against what the agent has applied.
const files = computed(() => {
  if (!preview.value) return []
  const current = Object.fromEntries((preview.value.current ?? []).map((f) => [f.path, f.content]))
  const out = preview.value.files.map((f) => {
    const old = current[f.path] ?? ''
    delete current[f.path]
    const status = old === f.content ? 'same' : old ? 'changed' : 'new'
    const parts = diffLines(old, f.content)
    return { path: f.path, status, parts: status === 'changed' ? collapse(parts) : parts }
  })
  for (const [path, content] of Object.entries(current)) {
    out.push({ path, status: 'removed', parts: diffLines(content, '') })
  }
  return out
})
// Long unchanged stretches are cut to a few lines of context.
const CONTEXT = 3
function collapse(parts) {
  return parts.flatMap((part, i) => {
    if (part.added || part.removed) return [part]
    const lines = part.value.split('\n')
    if (lines.at(-1) === '') lines.pop()
    const head = i === 0 ? 0 : CONTEXT
    const tail = i === parts.length - 1 ? 0 : CONTEXT
    if (lines.length <= head + tail + 2) return [part]
    const out = []
    if (head) out.push({ value: lines.slice(0, head).join('\n') + '\n' })
    out.push({ skipped: lines.length - head - tail })
    if (tail) out.push({ value: lines.slice(-tail).join('\n') + '\n' })
    return out
  })
}

const changedFiles = computed(() =>
  files.value.filter((f) => showUnchanged.value || f.status !== 'same'),
)
const statusColor = {
  applied: 'success',
  confirmed: 'success',
  pending: 'warning',
  rolled_back: 'error',
  failed: 'error',
}
const fileColor = { same: 'neutral', changed: 'warning', new: 'success', removed: 'error' }
</script>

<template>
  <div class="space-y-4">
    <div class="card space-y-3">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div class="text-lg font-semibold">Deploy</div>
          <p class="text-sm text-muted">
            Nothing changes on the firewall until you apply. Preview shows exactly what will be
            written.
          </p>
        </div>
        <div class="flex flex-wrap items-end gap-2">
          <UFormField label="Auto-rollback after (s)" help="0 = no confirmation" class="w-44">
            <UInput v-model="confirmTimeout" type="number" min="0" max="1800" />
          </UFormField>
          <UButton
            color="neutral"
            variant="outline"
            icon="i-lucide-file-diff"
            label="Preview"
            :loading="busy"
            @click="runPreview"
          />
          <UButton
            v-if="auth.isAdmin"
            icon="i-lucide-rocket"
            label="Apply"
            :loading="busy"
            :disabled="!!check?.problems?.length || !!deploy.pending"
            @click="apply"
          />
        </div>
      </div>
      <template v-if="check">
        <UAlert
          v-if="check.problems.length"
          color="error"
          variant="subtle"
          icon="i-lucide-circle-x"
          :title="`${check.problems.length} problem(s) must be fixed before deploying`"
        >
          <template #description>
            <ul class="mt-1 list-disc pl-5">
              <li v-for="p in check.problems" :key="p">{{ p }}</li>
            </ul>
          </template>
        </UAlert>
        <div v-else class="flex flex-wrap gap-2 text-sm">
          <UBadge
            color="success"
            variant="subtle"
            icon="i-lucide-check"
            label="Configuration is valid"
          />
          <UBadge
            v-for="(n, k) in check.counts"
            :key="k"
            color="neutral"
            variant="outline"
            :label="`${n} ${k}`"
          />
          <UBadge
            color="neutral"
            variant="outline"
            :label="`next generation ${check.generation + 1}`"
          />
        </div>
      </template>
    </div>

    <div v-if="applyResult" class="card space-y-2">
      <UAlert v-if="!applyResult.ok" color="error" variant="subtle" :title="applyResult.error">
        <template v-if="applyResult.problems?.length" #description>
          <ul class="list-disc pl-5">
            <li v-for="p in applyResult.problems" :key="p">{{ p }}</li>
          </ul>
        </template>
      </UAlert>
      <UAlert
        v-if="applyResult.result?.rolled_back"
        color="warning"
        variant="subtle"
        title="The agent restored the previous configuration."
      />
      <pre class="max-h-96 overflow-auto rounded bg-elevated p-3 text-xs">{{
        (applyResult.result?.log ?? []).join('\n')
      }}</pre>
    </div>

    <div v-if="previewError" class="card">
      <UAlert color="error" variant="subtle" :title="previewError.error">
        <template v-if="previewError.problems.length" #description>
          <ul class="list-disc pl-5">
            <li v-for="p in previewError.problems" :key="p">{{ p }}</li>
          </ul>
        </template>
      </UAlert>
    </div>

    <div v-if="preview" class="card space-y-3">
      <div class="flex items-center justify-between">
        <div class="font-semibold">Preview</div>
        <USwitch v-model="showUnchanged" label="Show unchanged files" />
      </div>
      <div v-if="!changedFiles.length" class="text-sm text-muted">
        No changes compared to the running configuration.
      </div>
      <details
        v-for="f in changedFiles"
        :key="f.path"
        class="rounded border border-default"
        :open="f.status !== 'same'"
      >
        <summary class="flex cursor-pointer items-center gap-2 px-3 py-2 font-mono text-sm">
          <UBadge :color="fileColor[f.status]" variant="subtle" :label="f.status" />
          {{ f.path }}
        </summary>
        <pre
          class="overflow-x-auto border-t border-default text-xs"
        ><template v-for="(part, i) in f.parts" :key="i"><span v-if="part.skipped" class="block bg-elevated px-2 text-muted italic">⋯ {{ part.skipped }} unchanged lines</span><span v-else
          :class="part.added ? 'block bg-success/15' : part.removed ? 'block bg-error/15 line-through decoration-error/40' : 'block text-muted'"
        >{{ part.value }}</span></template></pre>
      </details>
    </div>

    <div class="card">
      <div class="mb-2 font-semibold">History</div>
      <UTable
        :data="history"
        :columns="[
          { accessorKey: 'generation', header: 'Gen' },
          { id: 'when', header: 'When' },
          { accessorKey: 'username', header: 'By' },
          { id: 'status', header: 'Status' },
          { accessorKey: 'message', header: 'Message' },
        ]"
      >
        <template #when-cell="{ row }">{{ datetime(row.original.created_at) }}</template>
        <template #status-cell="{ row }">
          <UBadge
            :color="statusColor[row.original.status] ?? 'neutral'"
            variant="subtle"
            :label="row.original.status.replace('_', ' ')"
          />
        </template>
        <template #empty
          ><div class="py-4 text-center text-muted">Nothing deployed yet.</div></template
        >
      </UTable>
    </div>
  </div>
</template>
