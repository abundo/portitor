<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<script setup>
import { useConfirm } from '@/composables/useConfirm'
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import SearchInput from '@/components/SearchInput.vue'
import { api } from '@/api'
import { errMsg } from '@/api/http'
import { ago, when } from '@/utils/time'
import { useSearch } from '@/utils/search'

const { ask } = useConfirm()

const toast = useToast()
const sys = ref(null)
const error = ref('')
const web = ref(null)
// Polling runs while a job runs, and after starting one until it shows up
// (a Portitor update restarts the agent and portitor-web on the way).
const expecting = ref(0)
let timer = null

const jobs = computed(() => Object.fromEntries((sys.value?.jobs ?? []).map((j) => [j.name, j])))
const running = computed(() => (sys.value?.jobs ?? []).some((j) => j.state === 'running'))
const releases = computed(() => sys.value?.releases?.releases ?? [])
const installed = computed(() => sys.value?.releases?.installed ?? {})
const shownReleases = computed(() => {
  const newer = releases.value.filter((r) => r.newer)
  const rest = releases.value.filter((r) => !r.newer).slice(0, 5)
  return [...newer, ...rest]
})
const { search: releaseSearch, filtered: foundReleases } = useSearch(
  shownReleases,
  (r) => `${r.tag} ${r.date} ${r.notes}`,
)
const { search: packageSearch, filtered: shownPackages } = useSearch(
  () => sys.value?.packages ?? [],
  (p) => `${p.name} ${p.security ? 'security' : ''} ${p.from || 'new'} ${p.to}`,
)
const security = computed(() => (sys.value?.packages ?? []).filter((p) => p.security).length)

const jobTitle = {
  check: 'Check for updates',
  upgrade: 'Debian upgrade',
  update: 'Portitor update',
}
// terminalText shows output as a terminal would: a carriage return (dpkg's
// "Reading database ... 5%" progress) starts the line over.
const terminalText = (s) =>
  s
    .split('\n')
    .map((l) => l.replace(/\r+$/, '').split('\r').pop())
    .join('\n')
const stateColor = (s) => (s === 'succeeded' ? 'success' : s === 'failed' ? 'error' : 'info')

async function load() {
  try {
    sys.value = await api.system()
    error.value = ''
  } catch (err) {
    error.value = errMsg(err)
  }
  try {
    web.value = await api.version()
  } catch {
    // portitor-web is restarting (an update); the next poll tells.
  }
  schedule()
}

function schedule() {
  clearTimeout(timer)
  if (expecting.value > 0) expecting.value--
  if (running.value || expecting.value > 0) timer = setTimeout(load, 3000)
}

onMounted(load)
onUnmounted(() => clearTimeout(timer))

async function start(job, release) {
  try {
    await api.systemJob(job, release)
    // Up to a minute of polls before the job must have shown up.
    expecting.value = 20
    toast.add({ title: `${jobTitle[job]} started`, color: 'info' })
    load()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

async function install(r) {
  const what = r.newer ? 'Install' : 'Go back to'
  if (
    !(await ask({
      title: 'Update',
      message: `${what} Portitor ${r.tag}? The agent (and portitor-web, if it runs on the firewall) restarts; the GUI is away for a moment.`,
    }))
  )
    return
  start('update', r.tag)
}

async function upgrade() {
  if (
    !(await ask({
      title: 'Upgrade',
      message: `Upgrade ${sys.value.packages.length} Debian packages on the firewall?`,
    }))
  )
    return
  start('upgrade')
}

async function reboot() {
  if (
    !(await ask({
      title: 'Reboot',
      message: 'Reboot the firewall? Traffic stops until it is back up.',
    }))
  )
    return
  try {
    await api.systemReboot()
    toast.add({ title: 'The firewall is rebooting', color: 'warning' })
    expecting.value = 60
    setTimeout(load, 10000)
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}
</script>

<template>
  <div class="space-y-4">
    <UAlert
      v-if="error"
      color="error"
      variant="subtle"
      icon="i-lucide-unplug"
      :title="expecting ? 'Waiting for the firewall…' : 'Cannot reach the firewall agent'"
      :description="error"
    />
    <UAlert
      v-if="sys?.reboot_required"
      color="warning"
      variant="subtle"
      icon="i-lucide-rotate-ccw"
      :title="
        sys.hostname ? `Reboot required: firewall ${sys.hostname}` : 'Reboot required: firewall'
      "
      description="An updated kernel or system library is installed on the firewall (where the agent runs) but not running yet."
      :actions="[{ label: 'Reboot now', color: 'warning', onClick: reboot }]"
    />

    <div class="flex flex-wrap items-center gap-3">
      <UButton
        icon="i-lucide-refresh-cw"
        :loading="jobs.check?.state === 'running'"
        :disabled="running"
        @click="start('check')"
        >Check for updates</UButton
      >
      <span v-if="jobs.check?.finished" class="text-sm text-muted"
        >last checked {{ ago(jobs.check.finished) }}</span
      >
      <span v-else-if="sys" class="text-sm text-muted">not checked since the agent started</span>
      <UButton
        class="ml-auto"
        color="neutral"
        variant="outline"
        icon="i-lucide-power"
        :disabled="running || !sys"
        @click="reboot"
        >Reboot firewall</UButton
      >
    </div>

    <div v-if="sys" class="grid gap-4 xl:grid-cols-2">
      <div class="card">
        <div class="mb-1 text-lg font-semibold">Portitor</div>
        <div class="mb-3 space-y-0.5 text-sm text-muted">
          <div v-if="web">portitor-web {{ web.version }} (this GUI)</div>
          <div v-for="(v, k) in installed" :key="k">portitor-{{ k }} {{ v }} on the firewall</div>
        </div>
        <UAlert
          v-if="!sys.installer"
          color="warning"
          variant="subtle"
          title="The firewall has no copy of install.py"
          description="Update once with install.py; from then on, updates can be installed from here."
        />
        <template v-else>
          <p v-if="sys.releases && !installed.web" class="mb-3 text-sm text-muted">
            portitor-web does not run on the firewall; this updates the agent only. Update
            portitor-web with <code class="font-mono">install.py</code> on its own host, after the
            agent (never the other way around).
          </p>
          <div v-if="sys.releases_error" class="text-sm text-error">{{ sys.releases_error }}</div>
          <div v-else-if="!sys.releases" class="text-sm text-muted">
            Check for updates to list the releases.
          </div>
          <div v-else-if="!releases.length" class="text-sm text-muted">
            No releases are published yet.
          </div>
          <template v-else>
            <div class="mb-2">
              <SearchInput v-model="releaseSearch" />
            </div>
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-default text-left text-xs text-muted">
                  <th class="py-1 pr-4 font-medium">Release</th>
                  <th class="pr-4 font-medium">Date</th>
                  <th class="pr-4 font-medium">Notes</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="r in foundReleases"
                  :key="r.tag"
                  class="border-b border-default last:border-0"
                >
                  <td class="py-1 pr-4 font-mono">{{ r.tag }}</td>
                  <td class="py-1 pr-4">{{ r.date }}</td>
                  <td class="py-1 pr-4 text-muted">{{ r.notes }}</td>
                  <td class="py-1 text-right">
                    <UButton
                      v-if="r.installable && !r.notes.includes('current')"
                      size="xs"
                      :variant="r.newer ? 'solid' : 'outline'"
                      :color="r.newer ? 'primary' : 'neutral'"
                      :disabled="running"
                      @click="install(r)"
                      >{{ r.newer ? 'Install' : 'Go back' }}</UButton
                    >
                  </td>
                </tr>
                <tr v-if="!foundReleases.length">
                  <td colspan="4" class="py-2 text-muted">No release matches.</td>
                </tr>
              </tbody>
            </table>
          </template>
        </template>
      </div>

      <div class="card">
        <div class="mb-1 text-lg font-semibold">Debian</div>
        <div class="mb-3 text-sm text-muted">
          {{ sys.os }} · kernel {{ sys.kernel }}
          <span v-if="sys.boot_time"> · up since {{ when(sys.boot_time) }}</span>
        </div>
        <div v-if="!sys.packages.length" class="text-sm text-muted">
          No package upgrades known. Check for updates to refresh the package lists.
        </div>
        <template v-else>
          <div class="mb-2 flex items-center gap-3">
            <UButton icon="i-lucide-download" :disabled="running" @click="upgrade"
              >Upgrade {{ sys.packages.length }} packages</UButton
            >
            <UBadge
              v-if="security"
              color="warning"
              variant="subtle"
              :label="`${security} security`"
            />
          </div>
          <div class="mb-2">
            <SearchInput v-model="packageSearch" />
          </div>
          <div class="max-h-80 overflow-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-default text-left text-xs text-muted">
                  <th class="py-1 pr-4 font-medium">Package</th>
                  <th class="pr-4 font-medium">Installed</th>
                  <th class="font-medium">New</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="p in shownPackages"
                  :key="p.name"
                  class="border-b border-default last:border-0"
                >
                  <td class="py-1 pr-4 font-mono text-xs">
                    {{ p.name }}
                    <UBadge
                      v-if="p.security"
                      color="warning"
                      variant="subtle"
                      size="sm"
                      label="security"
                    />
                  </td>
                  <td class="py-1 pr-4 font-mono text-xs">{{ p.from || 'new' }}</td>
                  <td class="py-1 font-mono text-xs">{{ p.to }}</td>
                </tr>
                <tr v-if="!shownPackages.length">
                  <td colspan="3" class="py-2 text-muted">No package matches.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>
      </div>
    </div>

    <div v-for="j in sys?.jobs ?? []" :key="j.name" class="card">
      <div class="mb-2 flex items-center gap-3">
        <div class="font-semibold">{{ jobTitle[j.name] ?? j.name }}</div>
        <UBadge :color="stateColor(j.state)" variant="subtle" :label="j.state" />
        <span class="text-xs text-muted">
          <template v-if="j.started">started {{ when(j.started) }}</template>
          <template v-if="j.finished"> · finished {{ when(j.finished) }}</template>
        </span>
      </div>
      <pre
        v-if="j.output"
        class="max-h-96 overflow-auto rounded bg-elevated p-3 font-mono text-xs whitespace-pre-wrap"
        >{{ terminalText(j.output) }}</pre
      >
      <p v-if="j.name === 'update' && j.state === 'succeeded'" class="mt-2 text-sm text-muted">
        Reload the page to load the new GUI.
      </p>
    </div>
  </div>
</template>
