<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// NftImportDialog: imports an nftables file into the selected virtual
// firewall. Preview asks the agent to read the file (nft, in a network
// namespace of its own) and shows what would be created and what is left
// out; Import writes it as uncommitted changes.
import { computed, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useFormGuard } from '@/composables/useFormGuard'
import { useSearch } from '@/utils/search'
import { inlineField, widerModal } from '@/utils/form'
import SearchInput from '@/components/SearchInput.vue'

const open = defineModel('open', { type: Boolean, default: false })
const props = defineProps({
  instanceId: { type: Number, required: true },
  // Interface and zone names of the virtual firewall, as select items.
  ifaces: { type: Array, default: () => [] },
})
const emit = defineEmits(['imported'])
const toast = useToast()

const form = reactive({ text: '', fileName: '', rename: {}, replace: false })
const guard = useFormGuard(form, open)
const result = ref(null)
const busy = ref(false)

watch(open, (o) => {
  if (!o) return
  Object.assign(form, { text: '', fileName: '', rename: {}, replace: false })
  result.value = null
})
// A changed file or mapping makes the preview stale.
watch(
  () => [form.text, JSON.stringify(form.rename), form.replace],
  () => (result.value = null),
)

const fileInput = ref(null)
async function pickFile(ev) {
  const file = ev.target.files?.[0]
  ev.target.value = ''
  if (!file) return
  form.text = await file.text()
  form.fileName = file.name
}

const NONE = '__none__'
const ifaceItems = computed(() => [
  { label: '(leave its rules out)', value: NONE },
  ...props.ifaces,
])
// The file's interface names, kept across previews so the mapping stays.
const foreign = ref([])
function renameOf(name) {
  return form.rename[name] || NONE
}
function setRename(name, v) {
  form.rename = { ...form.rename, [name]: v === NONE ? '' : v }
}

async function run(apply) {
  busy.value = true
  try {
    const r = await api.importNftables({
      instance_id: props.instanceId,
      text: form.text,
      rename: form.rename,
      replace: form.replace,
      apply,
    })
    if (!apply) {
      result.value = r
      foreign.value = r.interfaces
      return
    }
    toast.add({
      title: `Imported ${r.rules.length} rules and ${r.nat.length} NAT rules`,
      description: 'Review them, then commit.',
      color: 'success',
    })
    emit('imported')
    open.value = false
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    busy.value = false
  }
}

const counts = computed(() => {
  const r = result.value
  if (!r) return []
  const by = (chain) => r.rules.filter((x) => x.chain === chain && !x.kind).length
  return [
    ['Input rules', by('input')],
    ['Forward rules', by('forward')],
    ['Output rules', by('output')],
    ['Port forwards (dnat)', r.nat.filter((n) => n.kind === 'dnat').length],
    ['Source NAT, masquerade', r.nat.filter((n) => n.kind !== 'dnat').length],
  ]
})
const skipped = computed(() => result.value?.skipped ?? [])
const { search, filtered } = useSearch(skipped, (s) => `${s.where} ${s.text} ${s.reason}`)
</script>

<template>
  <UModal
    :open="open"
    title="Import nftables"
    :ui="widerModal"
    :dismissible="false"
    @update:open="guard.onUpdateOpen"
  >
    <template #body>
      <div class="space-y-4">
        <p class="text-sm text-muted">
          Rules of the input, forward and output filter chains, and dnat, snat and masquerade of the
          nat chains, become rules and NAT rules of this virtual firewall; named address sets become
          hosts/prefixes, ports and ICMP types services. What Portitor can't express is left out and
          listed with the reason. The import is an uncommitted change: review it, then commit or
          revert.
        </p>
        <UFormField :ui="inlineField" label="File">
          <div class="flex items-center gap-2">
            <input
              ref="fileInput"
              type="file"
              accept=".nft,.conf,text/plain"
              hidden
              @change="pickFile"
            />
            <UButton
              icon="i-lucide-file-up"
              variant="outline"
              label="Choose file"
              @click="fileInput.click()"
            />
            <span class="text-sm text-muted">{{ form.fileName || 'or paste it below' }}</span>
          </div>
        </UFormField>
        <UTextarea
          v-model="form.text"
          :rows="8"
          class="w-full"
          :ui="{ base: 'font-mono text-xs' }"
          placeholder="table inet filter { ... }"
        />
        <UFormField
          :ui="inlineField"
          label="Replace"
          description="Delete this virtual firewall's rules and NAT rules first"
        >
          <USwitch v-model="form.replace" />
        </UFormField>

        <template v-if="foreign.length">
          <h3 class="text-sm font-semibold">Interfaces</h3>
          <UFormField v-for="n in foreign" :key="n" :ui="inlineField" :label="n">
            <USelect
              :model-value="renameOf(n)"
              :items="ifaceItems"
              class="w-64"
              @update:model-value="(v) => setRename(n, v)"
            />
          </UFormField>
        </template>

        <template v-if="result">
          <h3 class="text-sm font-semibold">Would be created</h3>
          <table class="text-sm">
            <tbody>
              <tr v-for="[label, n] in counts" :key="label">
                <td class="py-1 pe-6 text-muted">{{ label }}</td>
                <td class="py-1">{{ n }}</td>
              </tr>
              <tr v-if="result.objects.length">
                <td class="py-1 pe-6 text-muted">New hosts/prefixes</td>
                <td class="py-1">{{ result.objects.map((o) => o.name).join(', ') }}</td>
              </tr>
              <tr v-if="result.services.length">
                <td class="py-1 pe-6 text-muted">New services</td>
                <td class="py-1">{{ result.services.map((s) => s.name).join(', ') }}</td>
              </tr>
            </tbody>
          </table>

          <template v-if="skipped.length">
            <h3 class="text-sm font-semibold">Left out ({{ skipped.length }})</h3>
            <SearchInput v-model="search" />
            <div class="max-h-80 overflow-auto">
              <table class="w-full text-sm">
                <thead>
                  <tr class="text-left text-muted">
                    <th class="py-1 pe-3">Chain</th>
                    <th class="py-1 pe-3">Rule</th>
                    <th class="py-1">Reason</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="(s, i) in filtered"
                    :key="i"
                    :class="s.builtin ? 'text-muted' : ''"
                    class="border-t border-default align-top"
                  >
                    <td class="py-1 pe-3 whitespace-nowrap">{{ s.where }}</td>
                    <td class="py-1 pe-3 font-mono text-xs">{{ s.text }}</td>
                    <td class="py-1">{{ s.reason }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </template>
        </template>
      </div>
    </template>
    <template #footer>
      <div class="flex w-full justify-end gap-2">
        <UButton variant="outline" label="Cancel" @click="guard.close" />
        <UButton
          variant="outline"
          icon="i-lucide-eye"
          label="Preview"
          :loading="busy && !result"
          :disabled="!form.text.trim()"
          @click="run(false)"
        />
        <UButton
          icon="i-lucide-file-input"
          label="Import"
          :loading="busy && !!result"
          :disabled="!result"
          @click="run(true)"
        />
      </div>
    </template>
  </UModal>
</template>
