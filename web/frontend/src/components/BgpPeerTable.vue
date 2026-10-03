<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// BgpPeerTable: a CrudPage of BGP neighbours or peer groups, with the form
// fields they share that a plain field can't edit: the write-only
// password, eBGP multihop (on/off and its TTL) and each address family's
// filters in and out. Other props and events go to the CrudPage.
import { ref } from 'vue'
import BgpFilterPick from '@/components/BgpFilterPick.vue'
import CrudPage from '@/components/CrudPage.vue'

defineOptions({ inheritAttrs: false })
defineProps({
  disabled: { type: Boolean, default: false },
  // From useRoutingObjects.
  prefixListItems: { type: Function, required: true },
  routeMapItems: { type: Array, default: () => [] },
})

const page = ref(null)
defineExpose({ reload: () => page.value?.reload() })

const families = [
  { f: 'v4', family: 'ipv4' },
  { f: 'v6', family: 'ipv6' },
]
const filters = families.flatMap((x) => ['in', 'out'].map((dir) => ({ ...x, dir })))
</script>

<template>
  <CrudPage ref="page" v-bind="$attrs">
    <template #field-password="{ form }">
      <div class="flex w-full items-center gap-2">
        <UInput
          v-model="form.new_password"
          type="password"
          autocomplete="new-password"
          class="w-full"
          :disabled="form.clear_password"
          :placeholder="form.has_password ? 'set; leave empty to keep it' : 'TCP MD5, optional'"
        />
        <USwitch v-if="form.has_password" v-model="form.clear_password" label="Remove" />
      </div>
    </template>
    <template #field-ebgp_multihop="{ form }">
      <div class="flex items-center gap-2">
        <USwitch
          :model-value="form.ebgp_multihop > 0"
          @update:model-value="(on) => (form.ebgp_multihop = on ? 255 : 0)"
        />
        <template v-if="form.ebgp_multihop > 0">
          <span class="text-sm text-muted">TTL</span>
          <UInput v-model.number="form.ebgp_multihop" type="number" class="w-24" />
        </template>
      </div>
    </template>
    <template
      v-for="x in filters"
      :key="`${x.f}-${x.dir}`"
      #[`field-${x.f}_filter_${x.dir}`]="{ form }"
    >
      <BgpFilterPick
        v-model:list="form[`${x.f}_prefix_list_${x.dir}`]"
        v-model:map="form[`${x.f}_route_map_${x.dir}`]"
        :prefix-list-items="prefixListItems(x.family)"
        :route-map-items="routeMapItems"
        :disabled="disabled"
      />
    </template>
  </CrudPage>
</template>
