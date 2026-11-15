<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// SshFields: an SSH login in a dialog form, v-model { host, port, user,
// password, private_key }; without `host`, a login to a host the portal
// knows (its address and host key are the portal's). hostKey is the key the
// host presented, shown for the administrator to compare before trusting it.
// The credentials serve one request and are never kept.
import { inlineField } from '@/utils/form'

const model = defineModel({ type: Object, required: true })
defineProps({
  host: { type: Boolean, default: true },
  hostKey: { type: String, default: '' },
  what: { type: String, default: 'the host' },
})
</script>

<template>
  <div class="space-y-3">
    <UFormField
      v-if="host"
      :ui="inlineField"
      label="Host"
      required
      help="Its management address or name."
    >
      <UInput v-model="model.host" class="w-full" placeholder="192.0.2.1 or fw.example.com" />
    </UFormField>
    <UFormField :ui="inlineField" label="SSH port">
      <UInput v-model.number="model.port" type="number" class="w-32" />
    </UFormField>
    <UFormField :ui="inlineField" label="SSH user" required>
      <UInput v-model="model.user" class="w-full" autocomplete="off" />
    </UFormField>
    <UFormField :ui="inlineField" label="Password">
      <UInput v-model="model.password" type="password" class="w-full" autocomplete="off" />
    </UFormField>
    <UFormField :ui="inlineField" label="Or a private key" help="PEM, unencrypted.">
      <UTextarea
        v-model="model.private_key"
        :rows="2"
        class="w-full font-mono"
        autocomplete="off"
      />
    </UFormField>
    <UAlert
      v-if="hostKey"
      color="warning"
      variant="subtle"
      icon="i-lucide-key-round"
      :title="`${what} presents this SSH host key`"
    >
      <template #description>
        <div class="font-mono break-all">{{ hostKey }}</div>
        <div class="mt-1">
          Compare it with the host's own (<span class="font-mono"
            >ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</span
          >) before trusting it.
        </div>
      </template>
    </UAlert>
  </div>
</template>
