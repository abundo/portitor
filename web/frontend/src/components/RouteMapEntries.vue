<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// RouteMapEntries: a route map's entries, a field of the route map's form.
// The list shows each entry's match and set clauses; Edit opens the entry
// in a dialog of its own, which holds its Delete.
import { computed, reactive, ref } from 'vue'
import NameSelect from '@/components/NameSelect.vue'
import { useConfirm } from '@/composables/useConfirm'
import { useFormGuard } from '@/composables/useFormGuard'
import { inlineField, wideModal } from '@/utils/form'

const model = defineModel({ type: Array, default: () => [] })
const props = defineProps({
  disabled: { type: Boolean, default: false },
  // Select items: from useRoutingObjects.
  prefixListItems: { type: Array, default: () => [] },
  asPathItems: { type: Array, default: () => [] },
  communityItems: { type: Array, default: () => [] },
})

const { confirmDelete } = useConfirm()
const sorted = computed(() =>
  model.value.map((e, i) => ({ e, i })).sort((a, b) => (a.e.seq || 0) - (b.e.seq || 0)),
)

const numberFields = [
  ['match_metric', 'metric'],
  ['match_tag', 'tag'],
  ['set_local_preference', 'local-preference'],
  ['set_metric', 'metric'],
  ['set_weight', 'weight'],
]

function matchText(e) {
  const out = []
  if (e.match_prefix_list) out.push(`prefix-list ${e.match_prefix_list}`)
  if (e.match_next_hop) out.push(`next-hop ${e.match_next_hop}`)
  if (e.match_as_path) out.push(`as-path ${e.match_as_path}`)
  if (e.match_community) out.push(`community ${e.match_community}`)
  if (e.match_metric != null) out.push(`metric ${e.match_metric}`)
  if (e.match_tag != null) out.push(`tag ${e.match_tag}`)
  return out.join(', ') || 'any'
}

function setText(e) {
  const out = []
  if (e.set_local_preference != null) out.push(`local-preference ${e.set_local_preference}`)
  if (e.set_metric != null) out.push(`metric ${e.set_metric}`)
  if (e.set_weight != null) out.push(`weight ${e.set_weight}`)
  if (e.set_as_path_prepend) out.push(`prepend ${e.set_as_path_prepend}`)
  if (e.set_community)
    out.push(`community ${e.set_community}${e.set_community_additive ? ' additive' : ''}`)
  if (e.set_large_community) out.push(`large-community ${e.set_large_community}`)
  if (e.set_next_hop) out.push(`next-hop ${e.set_next_hop}`)
  if (e.set_origin) out.push(`origin ${e.set_origin}`)
  if (e.on_match_next) out.push('on-match next')
  return out.join(', ')
}

// The entry dialog.
const open = ref(false)
const editing = ref(-1) // index in model, -1 for a new entry
const form = reactive({})
const guard = useFormGuard(form, open)
const actions = [
  { label: 'permit', value: 'permit' },
  { label: 'deny', value: 'deny' },
]
const NO_ORIGIN = '\u0000'
const origins = [
  { label: '—', value: NO_ORIGIN },
  ...['igp', 'egp', 'incomplete'].map((o) => ({ label: o, value: o })),
]
const origin = computed({
  get: () => form.set_origin || NO_ORIGIN,
  set: (v) => (form.set_origin = v === NO_ORIGIN ? '' : v),
})

function fill(e) {
  for (const k of Object.keys(form)) delete form[k]
  Object.assign(form, {
    seq: 0,
    action: 'permit',
    description: '',
    match_prefix_list: '',
    match_next_hop: '',
    match_as_path: '',
    match_community: '',
    set_as_path_prepend: '',
    set_community: '',
    set_community_additive: false,
    set_large_community: '',
    set_next_hop: '',
    set_origin: '',
    on_match_next: false,
    ...JSON.parse(JSON.stringify(e)),
  })
  for (const [k] of numberFields) form[k] = form[k] ?? ''
}

function openNew() {
  editing.value = -1
  const high = Math.max(0, ...model.value.map((e) => e.seq || 0))
  fill({ seq: high + 10 })
  open.value = true
}

function openEdit(i) {
  editing.value = i
  fill(model.value[i])
  open.value = true
}

function save() {
  const e = { ...form, seq: Number(form.seq) || 0 }
  for (const [k] of numberFields) e[k] = e[k] === '' || e[k] == null ? null : Number(e[k])
  // Unset fields stay out; a deny sets nothing.
  for (const k of Object.keys(e))
    if (
      e[k] === null ||
      e[k] === '' ||
      e[k] === false ||
      (e.action === 'deny' && /^(set_|on_match)/.test(k))
    )
      delete e[k]
  const list = [...model.value]
  if (editing.value >= 0) list[editing.value] = e
  else list.push(e)
  model.value = list
  open.value = false
}

async function remove() {
  if (!(await confirmDelete(`entry ${form.seq}`))) return
  model.value = model.value.filter((_, i) => i !== editing.value)
  open.value = false
}
</script>

<template>
  <div class="w-full">
    <table v-if="model.length" class="w-full text-sm">
      <thead>
        <tr class="text-left text-xs text-muted">
          <th class="w-px" />
          <th class="px-1 py-1 font-medium">Seq</th>
          <th class="px-1 py-1 font-medium">Action</th>
          <th class="px-1 py-1 font-medium">Match</th>
          <th class="px-1 py-1 font-medium">Set</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="{ e, i } in sorted" :key="i" class="align-top">
          <td class="py-1">
            <UButton
              size="sm"
              variant="outline"
              :icon="disabled ? 'i-lucide-eye' : 'i-lucide-pencil'"
              :aria-label="disabled ? 'View' : 'Edit'"
              @click="openEdit(i)"
            />
          </td>
          <td class="px-1 py-1 font-mono">{{ e.seq }}</td>
          <td class="px-1 py-1">
            <UBadge
              :color="e.action === 'deny' ? 'error' : 'success'"
              variant="subtle"
              :label="e.action"
            />
          </td>
          <td class="px-1 py-1 font-mono text-xs">{{ matchText(e) }}</td>
          <td class="px-1 py-1 font-mono text-xs">{{ setText(e) }}</td>
        </tr>
      </tbody>
    </table>
    <p v-else class="py-1 text-sm text-muted">No entries: the route map denies every route.</p>
    <UButton
      v-if="!disabled"
      class="mt-1"
      size="xs"
      color="neutral"
      variant="outline"
      icon="i-lucide-plus"
      label="Add entry"
      @click="openNew"
    />
  </div>

  <UModal
    :open="open"
    :title="editing >= 0 ? `Entry ${form.seq}` : 'New entry'"
    :ui="wideModal"
    :dismissible="false"
    @update:open="guard.onUpdateOpen"
  >
    <template #body>
      <form id="route-map-entry-form" class="space-y-3" @submit.prevent="save">
        <fieldset :disabled="disabled" class="space-y-3">
          <UFormField label="Sequence" required :ui="inlineField">
            <UInput v-model="form.seq" type="number" class="w-32" />
          </UFormField>
          <UFormField label="Action" :ui="inlineField">
            <USelect v-model="form.action" :items="actions" class="w-32" />
          </UFormField>
          <UFormField label="Description" :ui="inlineField">
            <UInput v-model="form.description" class="w-full" />
          </UFormField>
          <div class="border-b border-default pt-2 pb-1 text-sm font-semibold">
            Match (all of them; empty matches any route)
          </div>
          <UFormField label="Prefix list" :ui="inlineField">
            <NameSelect v-model="form.match_prefix_list" :items="props.prefixListItems" />
          </UFormField>
          <UFormField label="Next hop" help="A prefix list the next hop is in." :ui="inlineField">
            <NameSelect v-model="form.match_next_hop" :items="props.prefixListItems" />
          </UFormField>
          <UFormField label="AS path list" :ui="inlineField">
            <NameSelect v-model="form.match_as_path" :items="props.asPathItems" />
          </UFormField>
          <UFormField label="Community list" :ui="inlineField">
            <NameSelect v-model="form.match_community" :items="props.communityItems" />
          </UFormField>
          <UFormField label="Metric (MED)" :ui="inlineField">
            <UInput v-model="form.match_metric" type="number" class="w-40" />
          </UFormField>
          <UFormField label="Tag" :ui="inlineField">
            <UInput v-model="form.match_tag" type="number" class="w-40" />
          </UFormField>
          <template v-if="form.action === 'permit'">
            <div class="border-b border-default pt-2 pb-1 text-sm font-semibold">Set</div>
            <UFormField label="Local preference" :ui="inlineField">
              <UInput v-model="form.set_local_preference" type="number" class="w-40" />
            </UFormField>
            <UFormField label="Metric (MED)" :ui="inlineField">
              <UInput v-model="form.set_metric" type="number" class="w-40" />
            </UFormField>
            <UFormField label="Weight" :ui="inlineField">
              <UInput v-model="form.set_weight" type="number" class="w-40" />
            </UFormField>
            <UFormField
              label="AS path prepend"
              help="AS numbers, separated by spaces."
              :ui="inlineField"
            >
              <UInput
                v-model="form.set_as_path_prepend"
                class="w-full"
                :ui="{ base: 'font-mono' }"
                placeholder="65010 65010"
              />
            </UFormField>
            <UFormField
              label="Community"
              help="AS:NN or well-known names (no-export, ...), separated by spaces; none removes them."
              :ui="inlineField"
            >
              <UInput
                v-model="form.set_community"
                class="w-full"
                :ui="{ base: 'font-mono' }"
                placeholder="65010:100 no-export"
              />
            </UFormField>
            <UFormField label="Add to the route's" :ui="inlineField">
              <USwitch v-model="form.set_community_additive" />
            </UFormField>
            <UFormField label="Large community" :ui="inlineField">
              <UInput
                v-model="form.set_large_community"
                class="w-full"
                :ui="{ base: 'font-mono' }"
                placeholder="65010:1:2"
              />
            </UFormField>
            <UFormField label="Next hop" :ui="inlineField">
              <UInput v-model="form.set_next_hop" class="w-full" :ui="{ base: 'font-mono' }" />
            </UFormField>
            <UFormField label="Origin" :ui="inlineField">
              <USelect v-model="origin" :items="origins" class="w-40" />
            </UFormField>
            <UFormField
              label="On match next"
              help="After this entry, go on to the next one instead of leaving the route map."
              :ui="inlineField"
            >
              <USwitch v-model="form.on_match_next" />
            </UFormField>
          </template>
        </fieldset>
      </form>
    </template>
    <template #footer>
      <div class="flex w-full gap-2">
        <UButton
          v-if="editing >= 0 && !disabled"
          color="error"
          variant="ghost"
          icon="i-lucide-trash"
          label="Delete"
          @click="remove"
        />
        <UButton class="ms-auto" color="neutral" variant="ghost" @click="guard.close">
          {{ disabled ? 'Close' : 'Cancel' }}
        </UButton>
        <UButton v-if="!disabled" type="submit" form="route-map-entry-form">OK</UButton>
      </div>
    </template>
  </UModal>
</template>
