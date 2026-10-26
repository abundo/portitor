<!-- SPDX-FileCopyrightText: 2026 The Portitor contributors -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

<!-- The directory: the users and roles, and the OpenLDAP and Active
     Directory servers every login (the GUI's, OpenVPN's) tries for a user
     the firewall doesn't have, in their order in the tree (drag to change
     it). A server's tree can be browsed, to map a group to a role
     (Authorization). -->
<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { useToast } from '@nuxt/ui/composables'
import { useRoute, useRouter } from 'vue-router'
import { Wunderbaum } from 'wunderbaum'
import 'wunderbaum/dist/wunderbaum.css'
import '@/assets/wunderbaum-theme.css'
import CrudPage from '@/components/CrudPage.vue'
import FormHeader from '@/components/FormHeader.vue'
import SearchInput from '@/components/SearchInput.vue'
import RoleForm from '@/components/RoleForm.vue'
import UserForm from '@/components/UserForm.vue'
import { api, directoryMappings, directoryServers } from '@/api'
import { errMsg } from '@/api/http'
import { useConfirm } from '@/composables/useConfirm'
import { confirmDiscard, hasUnsaved, usePageForm } from '@/composables/useFormGuard'
import { inlineField } from '@/utils/form'

const toast = useToast()
const route = useRoute()
const router = useRouter()
const { confirmDelete } = useConfirm()

const tabs = [
  { label: 'Directory', value: 'directory', slot: 'directory', icon: 'i-lucide-folder-tree' },
  { label: 'Authorization', value: 'authorization', slot: 'authorization', icon: 'i-lucide-key' },
]
const tab = computed({
  get: () => (tabs.some((t) => t.value === route.query.tab) ? route.query.tab : 'directory'),
  set: (v) => router.replace({ query: { ...route.query, tab: v === 'directory' ? undefined : v } }),
})

const users = ref([])
const roles = ref([])
const servers = ref([])
async function loadUsers() {
  users.value = await api.users()
}
async function loadRoles() {
  roles.value = await api.roles()
}
async function loadServers() {
  servers.value = await directoryServers.list()
}

// ----- The tree: Local (Users, Roles), then the servers in login order.
const el = ref(null)
let tree = null
const selected = ref(null) // the active node's data
const search = ref('')

const kindLabel = {
  local: 'Local',
  users: 'Users',
  roles: 'Roles',
  user: 'User',
  role: 'Role',
  server: 'Server',
  person: 'Person',
  group: 'Group',
  container: 'Folder',
  other: 'Entry',
}

function serverTitle(s) {
  const type = s.server_type === 'ad' ? 'Active Directory' : 'OpenLDAP'
  return `${s.name} (${type}${s.enabled ? '' : ', disabled'})`
}
function source() {
  return [
    {
      key: 'local',
      title: 'Local',
      kind: 'local',
      expanded: true,
      children: [
        {
          key: 'users',
          title: 'Users',
          kind: 'users',
          expanded: true,
          children: users.value.map((u) => ({
            key: `user-${u.id}`,
            title: u.ldap_server ? `${u.username} (${u.ldap_server})` : u.username,
            kind: 'user',
            id: u.id,
          })),
        },
        {
          key: 'roles',
          title: 'Roles',
          kind: 'roles',
          expanded: true,
          children: roles.value.map((r) => ({
            key: `role-${r.id}`,
            title: r.name,
            kind: 'role',
            id: r.id,
          })),
        },
      ],
    },
    ...servers.value.map((s) => ({
      key: `server-${s.id}`,
      title: serverTitle(s),
      kind: 'server',
      id: s.id,
      server_id: s.id,
      dn: '',
      lazy: !!(s.host && s.base_dn),
    })),
  ]
}

function render(e) {
  for (const col of Object.values(e.renderColInfosById ?? {}))
    if (col.id === 'kind') col.elem.textContent = kindLabel[e.node.data.kind] ?? ''
}

// skipGuard lets the node the user chose to discard their changes for be
// activated without asking again.
let skipGuard = false
function buildTree() {
  tree = new Wunderbaum({
    element: el.value,
    header: true,
    debugLevel: 0,
    rowHeightPx: 28,
    navigationModeOption: 'row',
    iconMap: {
      ...Wunderbaum.iconMaps?.bootstrap,
      expanderExpanded: '<i class="wb-expander">−</i>',
      expanderCollapsed: '<i class="wb-expander">+</i>',
      expanderLazy: '<i class="wb-expander">+</i>',
    },
    types: Object.fromEntries(Object.keys(kindLabel).map((k) => [k, { icon: false }])),
    columns: [
      { id: '*', title: 'Name', width: '*' },
      { id: 'kind', title: 'Kind', width: '90px' },
    ],
    source: source(),
    render,
    filter: { mode: 'hide', autoExpand: true },
    lazyLoad: (e) =>
      api.browseDirectoryServer(e.node.data.server_id, e.node.data.dn).then((rows) =>
        rows.map((r) => ({
          key: `s${e.node.data.server_id}:${r.dn}`,
          title: r.rdn,
          kind: r.kind,
          server_id: e.node.data.server_id,
          dn: r.dn,
          lazy: r.kind === 'container',
        })),
      ),
    beforeActivate: (e) => {
      if (skipGuard || !hasUnsaved()) return
      confirmDiscard().then((ok) => {
        if (!ok) return
        skipGuard = true
        try {
          e.node.setActive(true)
        } finally {
          skipGuard = false
        }
      })
      return false
    },
    activate: (e) => {
      creating.value = null
      selected.value = { ...e.node.data, key: e.node.key, title: e.node.title }
    },
    // The servers are the login order: drag one before or after another.
    dnd: {
      effectAllowed: 'move',
      dropEffectDefault: 'move',
      guessDropEffect: false,
      preventLazyParents: false,
      preventForeignNodes: true,
      preventNonNodes: true,
      dragStart: (e) => e.node.data.kind === 'server',
      dragEnter: (e) => (e.node.data.kind === 'server' ? ['before', 'after'] : false),
      drop: (e) => dropServer(e.sourceNode, e.node, e.suggestedDropMode),
    },
  })
}

async function dropServer(source, target, mode) {
  if (mode !== 'before' && mode !== 'after') return
  const ids = servers.value.map((s) => s.id).filter((id) => id !== source.data.id)
  let i = ids.indexOf(target.data.id)
  if (i < 0) return
  if (mode === 'after') i++
  ids.splice(i, 0, source.data.id)
  try {
    await api.reorderDirectoryServers(ids)
    await loadServers()
    await reload()
  } catch (err) {
    toast.add({ title: errMsg(err, 'Could not reorder the servers'), color: 'error' })
  }
}

async function reload() {
  if (!tree) return
  const active = tree.getActiveNode?.()?.key
  await tree.load(source())
  tree.update('structure', { immediate: true })
  if (active) tree.findKey(active)?.setActive(true, { noEvents: true })
  applySearch()
}

function applySearch() {
  if (!tree) return
  if (search.value.trim()) tree.filterNodes(search.value.trim(), { mode: 'hide' })
  else tree.clearFilter()
}
watch(search, applySearch)

onMounted(async () => {
  try {
    await Promise.all([loadUsers(), loadRoles(), loadServers()])
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
  await nextTick()
  buildTree()
})
onBeforeUnmount(() => {
  tree?.resizeObserver?.disconnect()
  tree = null
})

// The right pane: the selected node's form, or a new item's (creating:
// 'user', 'role', or a server's type 'generic' or 'ad').
const creating = ref(null)
const selectedUser = computed(() =>
  selected.value?.kind === 'user' ? users.value.find((u) => u.id === selected.value.id) : null,
)
const selectedRole = computed(() =>
  selected.value?.kind === 'role' ? roles.value.find((r) => r.id === selected.value.id) : null,
)
const paneKey = computed(() => (creating.value ? `new-${creating.value}` : selected.value?.key))

async function startNew(what) {
  if (!(await confirmDiscard())) return
  tree?.getActiveNode?.()?.setActive(false, { noEvents: true })
  selected.value = null
  creating.value = what
  if (what === 'generic' || what === 'ad') fillServer(blankServer(what))
}

// select reloads the tree and shows the item saved, or nothing (deleted).
async function select(key) {
  creating.value = null
  await reload()
  const node = key && tree?.findKey(key)
  if (node) {
    skipGuard = true
    try {
      node.setActive(true)
    } finally {
      skipGuard = false
    }
    selected.value = { ...node.data, key: node.key, title: node.title }
  } else {
    tree?.getActiveNode?.()?.setActive(false, { noEvents: true })
    selected.value = null
  }
}
async function userSaved(u) {
  await loadUsers()
  await select(`user-${u.id}`)
}
async function userDeleted() {
  await loadUsers()
  await loadRoles()
  await select(null)
}
async function roleSaved(r) {
  await Promise.all([loadRoles(), loadUsers()])
  await select(`role-${r.id}`)
}
async function roleDeleted() {
  await loadRoles()
  await select(null)
}

// ----- A server's form.
const serverForm = reactive({})
const serverGuard = usePageForm(serverForm)
const serverSaving = ref(false)
const testing = ref(false)
const typeItems = [
  { label: 'OpenLDAP (and other LDAP servers)', value: 'generic' },
  { label: 'Active Directory', value: 'ad' },
]
const tlsItems = [
  { label: 'LDAPS (port 636)', value: 'ldaps' },
  { label: 'StartTLS (port 389)', value: 'starttls' },
  { label: 'None (port 389)', value: 'none' },
]
function blankServer(type) {
  return {
    id: null,
    name: '',
    description: '',
    enabled: true,
    server_type: type,
    host: '',
    port: 636,
    tls_mode: 'ldaps',
    skip_tls_verify: false,
    ca_cert: '',
    bind_dn: '',
    new_bind_password: '',
    clear_bind_password: false,
    has_bind_password: false,
    base_dn: '',
    user_filter: '',
    attr_email: '',
    attr_display_name: '',
    attr_groups: '',
  }
}
function fillServer(s) {
  for (const k of Object.keys(serverForm)) delete serverForm[k]
  Object.assign(serverForm, blankServer('generic'), s ?? {}, {
    new_bind_password: '',
    clear_bind_password: false,
  })
  serverGuard.mark()
}
const creatingServer = computed(() => creating.value === 'generic' || creating.value === 'ad')
// The form is filled whatever is selected, so a hidden form never holds
// changes.
watch(selected, (n) => {
  if (n?.kind === 'server') fillServer(servers.value.find((s) => s.id === n.id))
  else if (!creatingServer.value) fillServer(null)
})
const userFilterHelp = computed(
  () =>
    `%s is the name logged in with. Empty: ${serverForm.server_type === 'ad' ? '(sAMAccountName=%s)' : '(uid=%s)'}.`,
)
watch(
  () => serverForm.tls_mode,
  (mode, old) => {
    // The usual port follows the TLS mode unless one was typed.
    const usual = (m) => (m === 'ldaps' ? 636 : 389)
    if (old && serverForm.port === usual(old)) serverForm.port = usual(mode)
  },
)

async function saveServer() {
  serverSaving.value = true
  try {
    const body = { ...serverForm }
    delete body.has_bind_password
    const saved = body.id
      ? await directoryServers.update(body.id, body)
      : await directoryServers.create(body)
    toast.add({ title: `Directory server ${saved.name} saved`, color: 'success' })
    await loadServers()
    fillServer(saved)
    await select(`server-${saved.id}`)
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    serverSaving.value = false
  }
}
async function testServer() {
  testing.value = true
  try {
    const r = await api.testDirectoryServer({ ...serverForm })
    toast.add(
      r.ok
        ? {
            title: `${serverForm.name || 'The server'}: connected, bound and searched`,
            color: 'success',
          }
        : { title: 'Test failed', description: r.error, color: 'error' },
    )
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  } finally {
    testing.value = false
  }
}
async function deleteServer() {
  if (!(await confirmDelete(`directory server ${serverForm.name}`))) return
  try {
    await directoryServers.remove(serverForm.id)
    serverGuard.mark()
    await loadServers()
    await select(null)
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

// ----- A browsed group: its mappings, and a form to map it to a role.
const mapForm = reactive({ group_dn: '', role_id: null, level: 'viewer' })
const mapGuard = usePageForm(mapForm)
const levels = [
  { label: 'Viewer', value: 'viewer' },
  { label: 'Admin', value: 'admin' },
]
const roleItems = computed(() => roles.value.map((r) => ({ label: r.name, value: r.id })))
const roleName = (id) => roles.value.find((r) => r.id === id)?.name ?? `#${id}`
const mappings = ref([])
const groupMappings = computed(() =>
  mappings.value.filter(
    (m) => m.group_dn.toLowerCase() === (selected.value?.dn ?? '').toLowerCase(),
  ),
)
watch(selected, async (n) => {
  Object.assign(mapForm, { group_dn: n?.dn ?? '', role_id: null, level: 'viewer' })
  mapGuard.mark()
  if (n?.kind !== 'group') return
  try {
    mappings.value = await directoryMappings.list()
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
})
const mappingsKey = ref(0)
async function saveMap() {
  try {
    await directoryMappings.create({ ...mapForm })
    mappings.value = await directoryMappings.list()
    mapForm.role_id = null
    mapGuard.mark()
    mappingsKey.value++
    toast.add({
      title: 'Group mapped; its members get the role at their next login',
      color: 'success',
    })
  } catch (err) {
    toast.add({ title: errMsg(err), color: 'error' })
  }
}

// ----- Authorization: group → role.
const mappingColumns = computed(() => [
  { key: 'group_dn', label: 'Group DN', class: 'font-mono text-xs' },
  {
    key: 'role_id',
    label: 'Role',
    format: (m) => roles.value.find((r) => r.id === m.role_id)?.name ?? m.role_id,
  },
  { key: 'level', label: 'Level' },
])
const mappingFields = computed(() => [
  {
    key: 'group_dn',
    label: 'Group DN',
    required: true,
    placeholder: 'CN=VPN users,CN=Users,DC=example,DC=com',
    hint: "A directory group (its DN, as the user's memberOf has it). Browse a server on the Directory tab to pick one.",
  },
  { key: 'role_id', label: 'Role', type: 'select', items: roleItems.value, required: true },
  { key: 'level', label: 'Level', type: 'select', items: levels },
])
</script>

<template>
  <UTabs v-model="tab" :items="tabs" :unmount-on-hide="false">
    <template #directory>
      <div class="grid gap-4 pt-2 xl:grid-cols-[minmax(320px,2fr)_3fr]">
        <div class="card flex min-h-[60vh] flex-col">
          <div class="mb-2 flex flex-wrap items-center gap-2">
            <div class="me-auto text-lg font-semibold">Directory</div>
            <UButton
              size="sm"
              color="neutral"
              variant="outline"
              icon="i-lucide-plus"
              label="OpenLDAP"
              @click="startNew('generic')"
            />
            <UButton
              size="sm"
              color="neutral"
              variant="outline"
              icon="i-lucide-plus"
              label="Active Directory"
              @click="startNew('ad')"
            />
          </div>
          <p class="mb-2 text-xs text-muted">
            A login (the GUI's and OpenVPN's) checks a local user here; a user the firewall doesn't
            have, or has from a server, at the servers below in this order (drag to change it). One
            that is down or refuses the password is passed over. A user a server lets in is copied
            to the users, with no global role and the roles their groups map to (Authorization).
          </p>
          <SearchInput v-model="search" class="mb-2" />
          <div ref="el" class="object-tree min-h-0 flex-1" />
        </div>

        <div class="min-w-0">
          <UserForm
            v-if="creating === 'user' || selectedUser"
            :key="paneKey"
            :user="selectedUser"
            @saved="userSaved"
            @deleted="userDeleted"
          />
          <RoleForm
            v-else-if="creating === 'role' || selectedRole"
            :key="paneKey"
            :role="selectedRole"
            :users="users"
            @saved="roleSaved"
            @deleted="roleDeleted"
          />
          <div
            v-else-if="['local', 'users', 'roles'].includes(selected?.kind)"
            class="card space-y-3"
          >
            <div class="text-lg font-semibold">{{ kindLabel[selected.kind] }}</div>
            <p class="text-sm text-muted">
              <template v-if="selected.kind === 'roles'">
                A role grants its members instances, each member as an admin (changes and deploys
                them) or a viewer. Select a role in the tree to edit it.
              </template>
              <template v-else>
                The users and roles of this firewall: local users, and the users copied from the
                directory servers at their first login. Select one in the tree to edit it.
              </template>
            </p>
            <div class="flex flex-wrap gap-2">
              <UButton
                v-if="selected.kind !== 'roles'"
                icon="i-lucide-user-plus"
                label="Add user"
                @click="startNew('user')"
              />
              <UButton
                v-if="selected.kind !== 'users'"
                icon="i-lucide-plus"
                label="Add role"
                @click="startNew('role')"
              />
            </div>
          </div>
          <div v-else-if="selected?.kind === 'server' || creatingServer" class="card">
            <form @submit.prevent="saveServer">
              <FormHeader
                :title="
                  creatingServer ? 'New directory server' : `Directory server ${serverForm.name}`
                "
              >
                <UButton
                  color="neutral"
                  variant="outline"
                  icon="i-lucide-plug-zap"
                  label="Test"
                  :loading="testing"
                  @click="testServer"
                />
                <UButton
                  v-if="!creatingServer"
                  color="error"
                  variant="ghost"
                  icon="i-lucide-trash"
                  label="Delete"
                  @click="deleteServer"
                />
                <UButton type="submit" :loading="serverSaving" :disabled="!serverGuard.dirty()"
                  >Save</UButton
                >
              </FormHeader>
              <div class="space-y-3">
                <UFormField label="Name" :ui="inlineField" required>
                  <UInput v-model="serverForm.name" class="w-full" placeholder="ad" required />
                </UFormField>
                <UFormField label="Description" :ui="inlineField">
                  <UInput v-model="serverForm.description" class="w-full" />
                </UFormField>
                <UFormField label="Enabled" :ui="inlineField" help="Disabled: logins pass it over.">
                  <USwitch v-model="serverForm.enabled" />
                </UFormField>
                <UFormField label="Type" :ui="inlineField">
                  <USelect v-model="serverForm.server_type" :items="typeItems" class="w-full" />
                </UFormField>
                <UFormField
                  label="Host"
                  :ui="inlineField"
                  help="The server's name or address, as the firewall host resolves and reaches it."
                  required
                >
                  <UInput
                    v-model="serverForm.host"
                    class="w-full font-mono"
                    placeholder="dc1.example.com"
                  />
                </UFormField>
                <UFormField label="TLS" :ui="inlineField">
                  <USelect v-model="serverForm.tls_mode" :items="tlsItems" class="w-full" />
                </UFormField>
                <UFormField label="Port" :ui="inlineField">
                  <UInput v-model.number="serverForm.port" type="number" class="w-40" />
                </UFormField>
                <UFormField
                  v-if="serverForm.tls_mode !== 'none'"
                  label="CA certificate"
                  :ui="inlineField"
                  help="PEM: the CA of the server's certificate (an Active Directory's own CA). Empty: the system's CAs."
                >
                  <UTextarea v-model="serverForm.ca_cert" class="w-full font-mono" :rows="3" />
                </UFormField>
                <UFormField
                  v-if="serverForm.tls_mode !== 'none'"
                  label="Skip certificate check"
                  :ui="inlineField"
                  help="Only to test: anyone in between can read the passwords."
                >
                  <USwitch v-model="serverForm.skip_tls_verify" />
                </UFormField>
                <UFormField
                  label="Bind DN"
                  :ui="inlineField"
                  help="The account that looks up users; empty: anonymously."
                >
                  <UInput
                    v-model="serverForm.bind_dn"
                    class="w-full font-mono"
                    placeholder="CN=svc-portitor,CN=Users,DC=example,DC=com"
                  />
                </UFormField>
                <UFormField v-if="serverForm.bind_dn" label="Bind password" :ui="inlineField">
                  <div class="flex w-full flex-wrap items-center gap-2">
                    <UInput
                      v-model="serverForm.new_bind_password"
                      type="password"
                      autocomplete="new-password"
                      class="min-w-48 flex-1"
                      :disabled="serverForm.clear_bind_password"
                      :placeholder="
                        serverForm.has_bind_password ? 'set; leave empty to keep it' : ''
                      "
                    />
                    <USwitch
                      v-if="serverForm.has_bind_password"
                      v-model="serverForm.clear_bind_password"
                      label="Remove"
                    />
                  </div>
                </UFormField>
                <UFormField
                  label="Base DN"
                  :ui="inlineField"
                  help="Where users are looked for, and below."
                  required
                >
                  <UInput
                    v-model="serverForm.base_dn"
                    class="w-full font-mono"
                    placeholder="DC=example,DC=com"
                  />
                </UFormField>
                <UFormField label="User filter" :ui="inlineField" :help="userFilterHelp">
                  <UInput
                    v-model="serverForm.user_filter"
                    class="w-full font-mono"
                    :placeholder="
                      serverForm.server_type === 'ad' ? '(sAMAccountName=%s)' : '(uid=%s)'
                    "
                  />
                </UFormField>
                <UFormField
                  label="Attributes"
                  :ui="inlineField"
                  help="Read for the local copy of a user; empty: mail, displayName, memberOf."
                >
                  <div class="grid w-full gap-2 sm:grid-cols-3">
                    <UInput v-model="serverForm.attr_email" class="font-mono" placeholder="mail" />
                    <UInput
                      v-model="serverForm.attr_display_name"
                      class="font-mono"
                      placeholder="displayName"
                    />
                    <UInput
                      v-model="serverForm.attr_groups"
                      class="font-mono"
                      placeholder="memberOf"
                    />
                  </div>
                </UFormField>
              </div>
            </form>
          </div>
          <div v-else-if="selected?.dn" class="card space-y-3">
            <div class="text-lg font-semibold">{{ selected.title }}</div>
            <table class="text-sm">
              <tbody>
                <tr>
                  <td class="py-1 pr-6 text-muted">DN</td>
                  <td class="py-1 font-mono break-all">{{ selected.dn }}</td>
                </tr>
                <tr>
                  <td class="py-1 pr-6 text-muted">Kind</td>
                  <td class="py-1">{{ kindLabel[selected.kind] }}</td>
                </tr>
              </tbody>
            </table>
            <form v-if="selected.kind === 'group'" class="space-y-3" @submit.prevent="saveMap">
              <div class="font-semibold">Roles</div>
              <p class="text-sm text-muted">
                The group's members are members of these roles, at the level given, from their next
                login on.
              </p>
              <ul v-if="groupMappings.length" class="text-sm">
                <li v-for="m in groupMappings" :key="m.id" class="py-1">
                  {{ roleName(m.role_id) }} ({{ m.level }})
                </li>
              </ul>
              <p v-else class="text-sm text-muted">Not mapped to a role.</p>
              <UFormField label="Map to role" :ui="inlineField">
                <USelect
                  v-model="mapForm.role_id"
                  :items="roleItems"
                  placeholder="Pick a role…"
                  class="w-full"
                />
              </UFormField>
              <UFormField label="Level" :ui="inlineField">
                <USelect v-model="mapForm.level" :items="levels" class="w-full" />
              </UFormField>
              <div class="flex justify-end">
                <UButton type="submit" icon="i-lucide-key" :disabled="!mapForm.role_id"
                  >Map</UButton
                >
              </div>
            </form>
            <p class="text-xs text-muted">
              The servers are read-only here; mappings are changed under Authorization.
            </p>
          </div>
          <div v-else class="card text-sm text-muted">
            Select a user, role or server in the tree, or add an OpenLDAP or Active Directory
            server.
          </div>
        </div>
      </div>
    </template>

    <template #authorization>
      <div class="pt-2">
        <CrudPage
          :key="mappingsKey"
          title="Groups to roles"
          description="A directory group's members are members of the role, at the level given, from their next login on (the GUI's or OpenVPN's). A user who leaves the group leaves the role at their next login; roles no group maps to are left as you set them."
          :api="directoryMappings"
          :columns="mappingColumns"
          :fields="mappingFields"
          :defaults="{ group_dn: '', role_id: null, level: 'viewer' }"
          noun="mapping"
          new-label="Map a group"
          :item-name="(m) => `mapping of ${m.group_dn}`"
        />
      </div>
    </template>
  </UTabs>
</template>
