<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// ServiceOptions: the protocol options of a service (utils/services), edited
// in the service object given as v-model: its type and the fields of that
// type. TCP/UDP/SCTP holds entries of a protocol and a destination port
// range, and with "Specify source ports" a source port range each; ICMP and
// ICMP6 a type by name and a code; IP a protocol number. Empty port and
// number fields are 0 (any), an empty code null (any).
import { computed, ref, watch } from 'vue'
import { useObjectStore } from '@/stores/objects'
import { newPort, portProtocols, serviceTypes } from '@/utils/services'
import { inlineField } from '@/utils/form'

const svc = defineModel({ type: Object, required: true })
const objects = useObjectStore()

const icmpProto = computed(() => (svc.value.type === 'icmp6' ? 'icmpv6' : 'icmp'))
// A combobox item can't have an empty value, so "any" (icmp_type '') is
// 'any' in the menu.
const icmpItems = computed(() => [
  { label: 'any', value: 'any' },
  ...(objects.icmpTypes[icmpProto.value] ?? []).map((t) => ({
    label: `${t.name} (${t.type})`,
    value: t.name,
    description: t.description,
  })),
])

// Source ports show when an entry has them, or when switched on.
const withSource = ref(false)
watch(
  () => svc.value,
  (s) => (withSource.value = (s.ports ?? []).some((p) => p.src_lo)),
  { immediate: true },
)
function setWithSource(on) {
  withSource.value = on
  if (!on) for (const p of svc.value.ports ?? []) Object.assign(p, { src_lo: 0, src_hi: 0 })
}

function setType(type) {
  const s = svc.value
  s.type = type
  if (type === 'tcp/udp/sctp' && !s.ports?.length) s.ports = [newPort()]
  // Between icmp and icmp6, a type both have (echo-request) stays.
  if (s.icmp_type && !icmpItems.value.some((it) => it.value === s.icmp_type)) {
    s.icmp_type = ''
    s.icmp_code = null
  }
}

function setIcmpType(v) {
  svc.value.icmp_type = v === 'any' ? '' : v
  if (!svc.value.icmp_type) svc.value.icmp_code = null
}

function addPort() {
  const last = svc.value.ports?.at(-1)
  svc.value.ports = [...(svc.value.ports ?? []), newPort(last?.protocol)]
}
function removePort(i) {
  svc.value.ports = svc.value.ports.filter((_, j) => j !== i)
}

// num reads a number input: empty is 0 (any), or null with nullable.
function num(value, nullable = false) {
  if (value === '' || value === null || value === undefined) return nullable ? null : 0
  const n = Number(value)
  return Number.isFinite(n) ? Math.trunc(n) : nullable ? null : 0
}
const show = (n) => (n ? n : '')
</script>

<template>
  <div class="space-y-3">
    <div class="border-b border-default pb-1 text-sm font-medium text-muted">Protocol options</div>
    <UFormField :ui="inlineField" label="Protocol type" required>
      <USelect
        :model-value="svc.type"
        :items="serviceTypes"
        class="w-full"
        @update:model-value="setType"
      />
    </UFormField>

    <template v-if="svc.type === 'tcp/udp/sctp'">
      <UFormField
        :ui="inlineField"
        label="Destination ports"
        help="Low alone is one port; both empty match any port of the protocol."
      >
        <div class="space-y-2">
          <div v-for="(p, i) in svc.ports" :key="i" class="service-port space-y-1.5">
            <div class="flex items-center gap-2">
              <USelect v-model="p.protocol" :items="portProtocols" class="w-24 shrink-0" />
              <UInput
                type="number"
                :model-value="show(p.dst_lo)"
                :min="1"
                :max="65535"
                placeholder="Low"
                class="min-w-0 flex-1"
                aria-label="Destination port low"
                @update:model-value="p.dst_lo = num($event)"
              />
              <span class="text-muted">-</span>
              <UInput
                type="number"
                :model-value="show(p.dst_hi)"
                :min="1"
                :max="65535"
                placeholder="High"
                class="min-w-0 flex-1"
                aria-label="Destination port high"
                @update:model-value="p.dst_hi = num($event)"
              />
              <UButton
                icon="i-lucide-x"
                color="neutral"
                variant="ghost"
                size="sm"
                :disabled="svc.ports.length === 1"
                title="Remove"
                aria-label="Remove"
                @click="removePort(i)"
              />
            </div>
            <div v-if="withSource" class="flex items-center gap-2">
              <span class="w-24 shrink-0 text-end text-sm whitespace-nowrap text-muted">
                Source port
              </span>
              <UInput
                type="number"
                :model-value="show(p.src_lo)"
                :min="1"
                :max="65535"
                placeholder="Low"
                class="min-w-0 flex-1"
                aria-label="Source port low"
                @update:model-value="p.src_lo = num($event)"
              />
              <span class="text-muted">-</span>
              <UInput
                type="number"
                :model-value="show(p.src_hi)"
                :min="1"
                :max="65535"
                placeholder="High"
                class="min-w-0 flex-1"
                aria-label="Source port high"
                @update:model-value="p.src_hi = num($event)"
              />
              <span class="w-8 shrink-0" />
            </div>
          </div>
          <UButton
            icon="i-lucide-plus"
            color="neutral"
            variant="outline"
            block
            aria-label="Add a protocol and port range"
            title="Add a protocol and port range"
            @click="addPort"
          />
        </div>
      </UFormField>
      <UFormField :ui="inlineField" label="Specify source ports">
        <USwitch :model-value="withSource" @update:model-value="setWithSource" />
      </UFormField>
    </template>

    <template v-else-if="svc.type === 'icmp' || svc.type === 'icmp6'">
      <UFormField :ui="inlineField" label="Type" help="Empty matches any type.">
        <USelectMenu
          :model-value="svc.icmp_type || 'any'"
          :items="icmpItems"
          value-key="value"
          :filter-fields="['label', 'description']"
          class="w-full"
          @update:model-value="setIcmpType"
        />
      </UFormField>
      <UFormField :ui="inlineField" label="Code" help="Empty matches any code; needs a type.">
        <UInput
          type="number"
          :model-value="svc.icmp_code ?? ''"
          :min="0"
          :max="255"
          placeholder="any"
          class="w-full"
          :disabled="!svc.icmp_type"
          @update:model-value="svc.icmp_code = num($event, true)"
        />
      </UFormField>
    </template>

    <UFormField
      :ui="inlineField"
      v-else-if="svc.type === 'ip'"
      label="Protocol number"
      help="0 or empty matches any protocol, such as 47 for GRE or 50 for ESP."
    >
      <UInput
        type="number"
        :model-value="show(svc.ip_protocol)"
        :min="0"
        :max="255"
        placeholder="0"
        class="w-full"
        @update:model-value="svc.ip_protocol = num($event)"
      />
    </UFormField>
  </div>
</template>
