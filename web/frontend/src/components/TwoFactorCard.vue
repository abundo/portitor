<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
// Two-factor login (TOTP) of the logged-in user, on My settings. Setting it
// up shows a QR code; it goes on only once a code from the app is checked,
// and then shows the recovery codes, this once.
import { onMounted, reactive, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import QRCode from 'qrcode'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { useAuthStore } from '@/stores/auth'
import { useFormGuard } from '@/composables/useFormGuard'
import { inlineField, wideModal } from '@/utils/form'

const toast = useToast()
const auth = useAuthStore()
const status = ref({ enabled: false, recovery_left: 0 })

async function load() {
  try {
    status.value = await api.totpStatus()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
onMounted(load)

// The dialog's step: 'password' (asked first, for what), 'scan' (QR code
// and the code check), 'codes' (the recovery codes).
const open = ref(false)
const busy = ref(false)
const step = ref('password')
const action = ref('setup')
const form = reactive({ password: '', code: '' })
const guard = useFormGuard(form, open)
const setup = ref({ secret: '', uri: '' })
const qr = ref('')
const codes = ref([])

const titles = {
  setup: 'Set up two-factor login',
  disable: 'Turn off two-factor login',
  codes: 'New recovery codes',
}

function start(what) {
  action.value = what
  step.value = 'password'
  Object.assign(form, { password: '', code: '' })
  codes.value = []
  open.value = true
}

async function submitPassword() {
  busy.value = true
  try {
    if (action.value === 'setup') {
      setup.value = await api.totpSetup(form.password)
      qr.value = await QRCode.toDataURL(setup.value.uri, { margin: 1, width: 220 })
      step.value = 'scan'
    } else if (action.value === 'disable') {
      await api.totpDisable(form.password)
      open.value = false
      toast.add({ title: 'Two-factor login is off', color: 'success' })
      await auth.fetchCurrentUser()
    } else {
      codes.value = (await api.recoveryCodes(form.password)).recovery_codes
      step.value = 'codes'
    }
    form.password = ''
    await load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    busy.value = false
  }
}

async function submitCode() {
  busy.value = true
  try {
    codes.value = (await api.totpEnable(form.code)).recovery_codes
    form.code = ''
    step.value = 'codes'
    toast.add({ title: 'Two-factor login is on', color: 'success' })
    await Promise.all([load(), auth.fetchCurrentUser()])
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    busy.value = false
  }
}

function copyCodes() {
  navigator.clipboard?.writeText(codes.value.join('\n'))
  toast.add({ title: 'Recovery codes copied', color: 'success' })
}

function downloadCodes() {
  const text = `Portitor recovery codes for ${auth.user?.username}\n\n${codes.value.join('\n')}\n`
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
  a.download = `portitor-recovery-codes-${auth.user?.username}.txt`
  a.click()
  URL.revokeObjectURL(a.href)
}
</script>

<template>
  <div class="card">
    <div class="mb-3 text-lg font-semibold">Two-factor login</div>
    <template v-if="status.enabled">
      <p class="mb-3 text-sm">
        On. The login asks for a code from your authenticator app.
        {{ status.recovery_left }} recovery code{{ status.recovery_left === 1 ? '' : 's' }} left.
      </p>
      <div class="flex gap-2">
        <UButton icon="i-lucide-list-restart" variant="outline" @click="start('codes')">
          New recovery codes
        </UButton>
        <UButton
          v-if="!auth.user?.totp_required"
          icon="i-lucide-shield-off"
          color="error"
          variant="ghost"
          @click="start('disable')"
        >
          Turn off
        </UButton>
      </div>
    </template>
    <template v-else>
      <p class="mb-3 text-sm text-muted">
        Off. With it on, the login asks for a code from an authenticator app (TOTP) after your
        password.
      </p>
      <UButton icon="i-lucide-shield-check" @click="start('setup')">Set up</UButton>
    </template>
  </div>

  <UModal
    :open="open"
    :title="titles[action]"
    :ui="wideModal"
    :dismissible="false"
    @update:open="guard.onUpdateOpen"
  >
    <template #body>
      <form
        v-if="step === 'password'"
        id="totp-form"
        class="space-y-3"
        @submit.prevent="submitPassword"
      >
        <UFormField :ui="inlineField" label="Your password" required>
          <UInput
            v-model="form.password"
            type="password"
            autocomplete="current-password"
            class="w-full"
            autofocus
            required
          />
        </UFormField>
      </form>
      <form
        v-else-if="step === 'scan'"
        id="totp-form"
        class="space-y-3"
        @submit.prevent="submitCode"
      >
        <p class="text-sm">
          Scan the QR code with your authenticator app, or enter the key by hand. Two-factor login
          goes on once you enter a code from the app.
        </p>
        <div class="flex flex-wrap items-center gap-4">
          <img :src="qr" alt="QR code" class="rounded bg-white p-1" width="220" height="220" />
          <div class="min-w-0 text-sm">
            <div class="text-muted">Key</div>
            <code class="break-all">{{ setup.secret }}</code>
          </div>
        </div>
        <UFormField :ui="inlineField" label="Code from the app" required>
          <UInput
            v-model="form.code"
            class="w-full"
            autocomplete="one-time-code"
            inputmode="numeric"
            required
          />
        </UFormField>
      </form>
      <div v-else class="space-y-3">
        <p class="text-sm">
          Keep these recovery codes somewhere safe. Each logs you in once in place of a code from
          the app, if you lose your phone. They are not shown again.
        </p>
        <div class="grid grid-cols-2 gap-x-6 gap-y-1 rounded bg-muted p-3 font-mono text-sm">
          <span v-for="c in codes" :key="c">{{ c }}</span>
        </div>
        <div class="flex gap-2">
          <UButton icon="i-lucide-copy" variant="outline" size="sm" @click="copyCodes">
            Copy
          </UButton>
          <UButton icon="i-lucide-download" variant="outline" size="sm" @click="downloadCodes">
            Download
          </UButton>
        </div>
      </div>
    </template>
    <template #footer>
      <div class="flex w-full gap-2">
        <template v-if="step !== 'codes'">
          <UButton class="ms-auto" color="neutral" variant="ghost" @click="guard.close">
            Cancel
          </UButton>
          <UButton
            type="submit"
            form="totp-form"
            :loading="busy"
            :color="action === 'disable' ? 'error' : 'primary'"
          >
            {{ step === 'scan' ? 'Turn on' : action === 'disable' ? 'Turn off' : 'Next' }}
          </UButton>
        </template>
        <UButton v-else class="ms-auto" @click="open = false">Done</UButton>
      </div>
    </template>
  </UModal>
</template>
