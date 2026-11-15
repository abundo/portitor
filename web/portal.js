// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

'use strict'
const $ = (id) => document.getElementById(id)
const bar = $('bar'), views = $('views')
let firewalls = []
let active = 'portal'
const frames = {}

async function api(method, path, body) {
  const res = await fetch('/portal/v1/' + path, {
    method, credentials: 'same-origin',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  let data = {}
  try { data = await res.json() } catch { /* no body */ }
  if (res.status === 401 && path !== 'login') { showLogin(); throw new Error(data.error || 'log in') }
  if (!res.ok) throw new Error(data.error || 'HTTP ' + res.status)
  return data
}

function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag)
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v)
    else e[k] = v
  }
  for (const k of kids) e.append(k)
  return e
}

function showLogin() {
  bar.hidden = views.hidden = true
  $('login').hidden = false
}

$('login').addEventListener('submit', async (ev) => {
  ev.preventDefault()
  $('l-err').hidden = true
  try {
    await api('POST', 'login', { user: $('l-user').value, password: $('l-pass').value })
    $('l-pass').value = ''
    // A framed GUI whose requests the portal refuses (its session ended) says so.
window.addEventListener('message', (ev) => {
  if (ev.origin === location.origin && ev.data && ev.data.portitor === 'portal-login') expired()
})
function expired() {
  for (const f of Object.values(frames)) f.remove()
  for (const k of Object.keys(frames)) delete frames[k]
  showLogin()
}
// The session also ends while a tab sits idle: look every minute.
setInterval(() => {
  if (!bar.hidden) fetch('/portal/v1/session', { credentials: 'same-origin' }).then((r) => { if (r.status === 401) expired() }).catch(() => {})
}, 60000)

start()
  } catch (e) {
    $('l-err').textContent = e.message
    $('l-err').hidden = false
  }
})

async function start() {
  let s
  try { s = await api('GET', 'session') } catch { return }
  $('login').hidden = true
  bar.hidden = views.hidden = false
  window.portalUser = s.user
  await refresh()
  const want = (location.hash.match(/^#fw=(.+)$/) || [])[1] || localStorage.getItem('portitor_tab')
  select(want && firewalls.some((f) => f.name === decodeURIComponent(want)) ? decodeURIComponent(want) : 'portal')
}

async function refresh() {
  firewalls = await api('GET', 'firewalls')
  for (const f of firewalls) if (frames[f.name]) frames[f.name].dataset.checked = '1'
  for (const name of Object.keys(frames)) {
    if (!firewalls.some((f) => f.name === name)) { frames[name].remove(); delete frames[name] }
  }
  drawBar()
  if (active !== 'portal' && !firewalls.some((f) => f.name === active)) select('portal')
  drawPortal()
}

function drawBar() {
  bar.replaceChildren()
  bar.append(el('button', { class: 'tab' + (active === 'portal' ? ' active' : ''), role: 'tab', onclick: () => select('portal') }, 'Portal'))
  for (const f of firewalls) {
    bar.append(el('button', { class: 'tab' + (active === f.name ? ' active' : ''), role: 'tab', title: f.error || f.version || '', onclick: () => select(f.name) },
      el('span', { class: 'dot' + (f.error ? ' down' : '') }), f.name))
  }
  bar.append(el('span', { class: 'spacer' }), el('span', { class: 'who' }, window.portalUser || ''),
    el('button', { class: 'tab', onclick: logout }, 'Log out'))
}

function select(name) {
  active = name
  try { localStorage.setItem('portitor_tab', name) } catch { /* private window */ }
  history.replaceState(null, '', name === 'portal' ? '#' : '#fw=' + encodeURIComponent(name))
  for (const [n, f] of Object.entries(frames)) f.hidden = n !== name
  const page = $('portal-view')
  if (page) page.hidden = name !== 'portal'
  if (name !== 'portal' && !frames[name]) {
    const f = firewalls.find((x) => x.name === name)
    const fr = el('iframe', { src: f.path, title: name })
    frames[name] = fr
    views.append(fr)
  }
  drawBar()
}

async function logout() {
  await api('POST', 'logout', {}).catch(() => {})
  for (const f of Object.values(frames)) f.remove()
  for (const k of Object.keys(frames)) delete frames[k]
  showLogin()
}

function showError(msg) {
  const p = $('page-err')
  if (!p) return
  p.textContent = msg || ''
  p.hidden = !msg
}

function drawPortal() {
  let view = $('portal-view')
  if (!view) {
    view = el('div', { id: 'portal-view' })
    view.style.cssText = 'position:absolute;inset:0'
    view.append($('portal-page').content.cloneNode(true))
    views.prepend(view)
    $('add').onclick = openAdd
    $('refresh').onclick = () => refresh().catch((e) => showError(e.message))
    $('w-add').onclick = async () => {
      try { await api('POST', 'witness', { string: $('w-str').value }); $('w-str').value = ''; showError(''); drawWitness() } catch (e) { showError(e.message) }
    }
    drawWitness()
  }
  view.hidden = active !== 'portal'
  const rows = $('fw-rows')
  rows.replaceChildren()
  for (const f of firewalls) {
    rows.append(el('tr', {},
      el('td', {}, el('a', { onclick: () => select(f.name) }, f.name)),
      el('td', { class: f.error ? 'error' : '' }, f.error || f.version),
      el('td', { class: 'muted' }, f.description || ''),
      el('td', {}, el('button', { class: 'link', onclick: () => removeFirewall(f.name) }, 'Remove'))))
  }
  if (!firewalls.length) rows.append(el('tr', {}, el('td', { colSpan: 4, class: 'muted' }, 'No firewalls yet. Add one.')))
}

async function removeFirewall(name) {
  if (!confirm('Remove firewall ' + name + ' from the portal? The firewall is not changed.')) return
  try { await api('DELETE', 'firewalls/' + encodeURIComponent(name)); await refresh() } catch (e) { showError(e.message) }
}

async function drawWitness() {
  const rows = $('w-rows')
  if (!rows) return
  let list = []
  try { list = await api('GET', 'witness') } catch (e) { showError(e.message) }
  rows.replaceChildren()
  for (const w of list) {
    rows.append(el('tr', {}, el('td', {}, w.pair), el('td', { class: 'mono' }, (w.hosts || []).join(', ')),
      el('td', {}, el('button', { class: 'link', onclick: async () => {
        try { await api('DELETE', 'witness/' + encodeURIComponent(w.pair)); drawWitness() } catch (e) { showError(e.message) }
      } }, 'Remove'))))
  }
  if (!list.length) rows.append(el('tr', {}, el('td', { colSpan: 3, class: 'muted' }, 'None.')))
}

// The add dialog: SSH credentials -> the host key to confirm -> the
// firewall's address and fingerprint -> name -> save.
let hostKey = ''
function openAdd() {
  for (const id of ['a-host', 'a-pass', 'a-key', 'a-name', 'a-desc', 'a-url', 'a-fp']) $(id).value = ''
  hostKey = ''
  $('hostkey').hidden = $('found').hidden = $('a-save').hidden = $('a-err').hidden = true
  $('ssh-part').hidden = false
  $('a-connect').textContent = 'Connect'
  $('add-dlg').showModal()
}

function addError(msg) { $('a-err').textContent = msg || ''; $('a-err').hidden = !msg }
function showFound() { $('found').hidden = $('a-save').hidden = false }

$('a-cancel').onclick = () => $('add-dlg').close()
$('add-dlg').addEventListener('cancel', (e) => e.preventDefault())
$('a-fill').onclick = () => { $('ssh-part').hidden = true; showFound() }
$('a-connect').onclick = async () => {
  addError('')
  const btn = $('a-connect')
  btn.disabled = true
  try {
    const res = await api('POST', 'probe', {
      host: $('a-host').value.trim(), port: parseInt($('a-port').value, 10) || 22, user: $('a-user').value.trim(),
      password: $('a-pass').value, private_key: $('a-key').value, host_key: hostKey,
    })
    if (res.confirm) {
      hostKey = res.host_key
      $('hostkey-fp').textContent = hostKey
      $('hostkey').hidden = false
      btn.textContent = 'Trust this host key and connect'
      return
    }
    $('a-url').value = res.url
    $('a-fp').value = res.info.fingerprint || ''
    if (!$('a-name').value) $('a-name').value = $('a-host').value.trim().split('.')[0]
    $('ssh-part').hidden = true
    showFound()
  } catch (e) {
    addError(e.message)
  } finally {
    btn.disabled = false
  }
}
$('a-save').onclick = async () => {
  addError('')
  try {
    await api('POST', 'firewalls', {
      name: $('a-name').value.trim(), description: $('a-desc').value.trim(), url: $('a-url').value.trim(),
      fingerprint: $('a-fp').value.trim(), ssh_host_key: hostKey,
    })
    $('add-dlg').close()
    await refresh()
    select($('a-name').value.trim())
  } catch (e) {
    addError(e.message)
  }
}

start()
