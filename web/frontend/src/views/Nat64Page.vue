<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { computed, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import NeedInstance from '@/components/NeedInstance.vue'
import TagsInput from '@/components/TagsInput.vue'
import { instances, interfaces } from '@/api'
import { errMsg } from '@/api/http'
import { withLabel } from '@/composables/useInstanceRefs'
import { usePageForm } from '@/composables/useFormGuard'
import { useAuthStore } from '@/stores/auth'
import { useInstanceStore } from '@/stores/instances'
import { inlineField } from '@/utils/form'

const toast = useToast()
const auth = useAuthStore()
const store = useInstanceStore()
const readOnly = computed(() => !auth.canEdit)

// The instance's nat64_* and dns64 fields.
const form = reactive({
  nat64_prefix: '64:ff9b::/96',
  nat64: false,
  nat64_pool4: [],
  dns64: false,
})
const pageForm = usePageForm(form)
const saving = ref(false)
// The interfaces with 464XLAT, set under Interfaces.
const xlatIfaces = ref([])

async function load() {
  const id = store.currentId
  if (!id) return
  const [inst, ifs] = await Promise.all([instances.get(id), interfaces.list({ instance_id: id })])
  Object.assign(form, {
    nat64_prefix: inst.nat64_prefix || '64:ff9b::/96',
    nat64: inst.nat64 ?? false,
    nat64_pool4: inst.nat64_pool4 ?? [],
    dns64: inst.dns64 ?? false,
  })
  xlatIfaces.value = ifs.filter((i) => i.xlat464).map((i) => withLabel(i.label, i.name))
  pageForm.mark()
}
watch(() => store.currentId, load, { immediate: true })

async function save() {
  saving.value = true
  try {
    await instances.update(store.currentId, { ...form })
    toast.add({ title: 'NAT64 saved', color: 'success' })
    await Promise.all([load(), store.load()])
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <NeedInstance>
    <div class="card">
      <form @submit.prevent="save">
        <h2 class="border-b border-default pb-1 mb-2 text-xl font-semibold">NAT64</h2>
        <p class="mb-4 text-sm text-muted">
          For IPv6-only clients: IPv6 packets to the NAT64 prefix are translated to IPv4, here or by
          another router (PLAT). Only packets coming in on an interface with 464XLAT are translated.
        </p>
        <fieldset :disabled="readOnly" class="space-y-3">
          <UFormField
            label="NAT64 prefix"
            help="The well-known prefix 64:ff9b::/96, or a network-specific one of length 32, 40, 48, 56, 64 or 96."
            :ui="inlineField"
          >
            <UInput v-model="form.nat64_prefix" class="w-full" placeholder="64:ff9b::/96" />
          </UFormField>
          <UFormField
            label="Translate here"
            help="Translate to IPv4 on this firewall (Jool). Off: another router is the NAT64 gateway."
            :ui="inlineField"
          >
            <USwitch v-model="form.nat64" />
          </UFormField>
          <UFormField
            v-if="form.nat64"
            label="IPv4 pool"
            help="IPv4 prefixes the translated packets leave from, routed to this firewall. Empty: the address of the interface they leave on (the WAN), ports 61001-65535."
            :ui="inlineField"
          >
            <TagsInput v-model="form.nat64_pool4" placeholder="192.0.2.0/28" />
          </UFormField>
          <UFormField
            label="DNS64"
            help="The DNS server answers a name that has only IPv4 addresses with IPv6 addresses in the NAT64 prefix."
            :ui="inlineField"
          >
            <USwitch v-model="form.dns64" />
          </UFormField>
        </fieldset>

        <h2 class="border-b border-default pb-1 mt-8 mb-2 text-xl font-semibold">464XLAT</h2>
        <p class="text-sm text-muted">
          Turned on per interface under
          <RouterLink to="/interfaces" class="text-primary">Interfaces</RouterLink>: the router
          advertisements announce the NAT64 prefix (PREF64) and DHCPv4 sends option 108 (IPv6-only
          preferred).
        </p>
        <p class="mt-2 text-sm">
          <template v-if="xlatIfaces.length">On: {{ xlatIfaces.join(', ') }}</template>
          <span v-else class="text-muted">No interface has 464XLAT.</span>
        </p>

        <div v-if="!readOnly" class="mt-4">
          <UButton type="submit" :loading="saving">Save</UButton>
        </div>
      </form>
    </div>
  </NeedInstance>
</template>
