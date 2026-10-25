<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// ServiceRateLimit: switches on the rate limit a service open to a subnet
// (DNS, DHCP, NTP) polices what comes in to it with
// (fwconfig.ServiceRateLimit). The rate limit itself is the service's own,
// set on the Rate limits page.
import { inlineField } from '@/utils/form'

const model = defineModel({ type: Boolean, default: false })
defineProps({
  service: { type: String, required: true },
})
</script>

<template>
  <UFormField
    label="Rate limit"
    :help="`Polices every packet that comes in to the ${service}, so a flood or a loop on one subnet can't take the firewall down. Its rate is on Firewall → Rate limits.`"
    :ui="inlineField"
  >
    <USwitch v-model="model" />
  </UFormField>
</template>
