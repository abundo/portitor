// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  COMMENT_TYPE,
  DOMAIN_TYPE,
  ZONE_RECORD_TYPES,
  isCommentRecord,
  isDomainRecord,
} from './zoneRecords.js'

const CLASS_RE = /^(IN|CH|HS|CS|CLASS\d+)$/i
const TTL_RE = /^(\d+)([smhdw])?$/i
const TTL_UNIT = { s: 1, m: 60, h: 3600, d: 86400, w: 604800 }

function stripBom(text) {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text
}

function ensureDot(name) {
  if (!name) return ''
  return name.endsWith('.') ? name : `${name}.`
}

function stripDot(name) {
  if (!name) return ''
  return name.endsWith('.') ? name.slice(0, -1) : name
}

export function parseTTLToken(token) {
  const m = TTL_RE.exec(token)
  if (!m) return null
  const n = Number(m[1])
  if (!Number.isFinite(n)) return null
  const unit = (m[2] || 's').toLowerCase()
  return n * TTL_UNIT[unit]
}

export function qualifyName(name, origin) {
  if (!name) return name
  if (name === '@') return origin || '@'
  if (name.endsWith('.')) return name
  if (!origin) return name
  return `${name}.${origin}`
}

export function relativeName(fqdn, origin) {
  const n = stripDot(fqdn)
  const o = stripDot(origin)
  if (!n) return '@'
  if (!o) return n
  if (n.toLowerCase() === o.toLowerCase()) return '@'
  const suffix = `.${o}`
  if (n.toLowerCase().endsWith(suffix.toLowerCase())) {
    return n.slice(0, n.length - suffix.length)
  }
  return ensureDot(n)
}

function isClass(token) {
  return CLASS_RE.test(token)
}

function unescapeQuoted(inner) {
  let out = ''
  for (let i = 0; i < inner.length; i++) {
    if (inner[i] === '\\' && i + 1 < inner.length) {
      out += inner[i + 1]
      i++
      continue
    }
    out += inner[i]
  }
  return out
}

function isQuotedToken(tok) {
  return tok.length >= 2 && tok.startsWith('"') && tok.endsWith('"')
}

/** Unquote TXT rdata. Adjacent quoted strings are concatenated (RFC 1035). */
export function parseTxtRdata(tokens) {
  let out = ''
  let lastQuoted = false
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]
    const quoted = isQuotedToken(tok)
    const s = quoted ? unescapeQuoted(tok.slice(1, -1)) : tok
    if (i > 0 && !quoted && !lastQuoted) out += ' '
    out += s
    lastQuoted = quoted
  }
  return out
}

function escapeQuoted(s) {
  return String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

/** Split on UTF-8 byte boundaries so each character-string is ≤ 255 octets. */
export function splitUtf8Bytes(str, maxBytes) {
  const encoder = new TextEncoder()
  const parts = []
  let current = ''
  let currentBytes = 0
  for (const ch of String(str ?? '')) {
    const n = encoder.encode(ch).length
    if (n > maxBytes) {
      if (current) {
        parts.push(current)
        current = ''
        currentBytes = 0
      }
      parts.push(ch)
      continue
    }
    if (currentBytes + n > maxBytes && current) {
      parts.push(current)
      current = ''
      currentBytes = 0
    }
    current += ch
    currentBytes += n
  }
  if (current) parts.push(current)
  return parts
}

/** Quote TXT for a zone file, splitting at 255-byte character-string limits. */
export function formatTxtRdata(value) {
  const chunks = splitUtf8Bytes(value ?? '', 255)
  if (!chunks.length) return '""'
  return chunks.map((c) => `"${escapeQuoted(c)}"`).join(' ')
}

export function padField(s, width) {
  const t = String(s ?? '')
  if (t.length > width) return `${t} `
  return t.padEnd(width)
}

function formatRdata(type, tokens, origin) {
  switch (type) {
    case 'CNAME':
    case 'NS':
    case 'PTR':
      return qualifyName(tokens[0], origin)
    case 'MX':
      if (tokens.length < 2) return tokens.join(' ')
      return `${tokens[0]} ${qualifyName(tokens[1], origin)}`
    case 'SRV':
      if (tokens.length < 4) return tokens.join(' ')
      return `${tokens[0]} ${tokens[1]} ${tokens[2]} ${qualifyName(tokens[3], origin)}`
    case 'TXT':
      return parseTxtRdata(tokens)
    default:
      return tokens.join(' ')
  }
}

function formatRecordValue(type, value) {
  if ((type || '').toUpperCase() === 'TXT') return formatTxtRdata(value)
  return value || ''
}

export function splitMacFromComment(comment) {
  let mac = ''
  const rest = []
  for (const part of String(comment || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean)) {
    const m = /^mac=(.+)$/i.exec(part)
    if (m && !mac) mac = m[1]
    else rest.push(part)
  }
  return { mac, description: rest.join(' ') }
}

function formatRRLine({ name, ttl, type, value, description, mac }) {
  let line = padField((name || '').trim() || '@', 40)
  const n = Number(ttl)
  const ttlStr = Number.isFinite(n) && n > 0 ? String(n) : ''
  line += padField(ttlStr, 8)
  line += padField((type || 'A').toUpperCase(), 8)
  line += formatRecordValue(type, value)
  const parts = []
  const hw = (mac || '').trim()
  if (hw) parts.push(`mac=${hw}`)
  const desc = (description || '').trim()
  if (desc) parts.push(desc)
  if (parts.length) line += ` ; ${parts.join(' ')}`
  return line
}

// Strip comments, drop parentheses, and turn newlines inside (...) into spaces
// so a multi-line SOA (or TXT) becomes one logical line.
export function unfoldZoneText(text) {
  let out = ''
  let depth = 0
  let inQuote = false
  let escape = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (escape) {
      out += c
      escape = false
      continue
    }
    if (c === '\\' && inQuote) {
      out += c
      escape = true
      continue
    }
    if (c === '"') {
      inQuote = !inQuote
      out += c
      continue
    }
    if (!inQuote && c === ';' && depth > 0) {
      while (i + 1 < text.length && text[i + 1] !== '\n' && text[i + 1] !== '\r') {
        i++
      }
      continue
    }
    if (!inQuote && c === '(') {
      depth++
      out += ' '
      continue
    }
    if (!inQuote && c === ')') {
      depth = Math.max(0, depth - 1)
      out += ' '
      continue
    }
    if (depth > 0 && (c === '\n' || c === '\r')) {
      out += ' '
      continue
    }
    out += c
  }
  if (inQuote) {
    throw new Error('Unterminated quoted string')
  }
  if (depth > 0) {
    throw new Error('Unterminated parenthesis')
  }
  return out
}

export function tokenizeZoneLine(line) {
  const tokens = []
  let i = 0
  while (i < line.length) {
    while (i < line.length && /\s/.test(line[i])) i++
    if (i >= line.length) break
    if (line[i] === '"') {
      let out = '"'
      i++
      let closed = false
      while (i < line.length) {
        if (line[i] === '\\' && i + 1 < line.length) {
          out += line[i] + line[i + 1]
          i += 2
          continue
        }
        if (line[i] === '"') {
          out += '"'
          i++
          closed = true
          break
        }
        out += line[i++]
      }
      if (!closed) {
        throw new Error('Unterminated quoted string')
      }
      tokens.push(out)
      continue
    }
    const start = i
    while (i < line.length && !/\s/.test(line[i])) i++
    tokens.push(line.slice(start, i))
  }
  return tokens
}

function toRecordRow({ name, ttl, type, value, description = '', mac = '' }) {
  return {
    _key: crypto.randomUUID(),
    name,
    ttl: ttl && ttl > 0 ? ttl : null,
    type,
    value,
    description,
    mac,
  }
}

function toCommentRow(text) {
  return {
    _key: crypto.randomUUID(),
    name: ';',
    ttl: null,
    type: COMMENT_TYPE,
    value: text,
    description: '',
  }
}

export function splitTrailingComment(line) {
  let inQuote = false
  let escape = false
  for (let i = 0; i < line.length; i++) {
    const c = line[i]
    if (escape) {
      escape = false
      continue
    }
    if (c === '\\' && inQuote) {
      escape = true
      continue
    }
    if (c === '"') {
      inQuote = !inQuote
      continue
    }
    if (!inQuote && c === ';') {
      return {
        rr: line.slice(0, i),
        comment: line.slice(i + 1).trim(),
      }
    }
  }
  return { rr: line, comment: '' }
}

/**
 * Parse a BIND-style zone file into table rows.
 * SOA records and apex NS records are skipped (they come from the product).
 */
export function parseZoneFile(text, zoneOrigin = '') {
  const origin0 = ensureDot((zoneOrigin || '').trim())
  let origin = origin0
  let lastName = '@'
  const records = []
  let skippedSoa = 0
  let skippedApexNs = 0
  const unsupported = []
  let seenRR = false

  function skipUnsupported(line, type, name = '') {
    const owner = (name || '').trim()
    unsupported.push({
      line,
      type,
      name: owner,
      message: owner
        ? `Line ${line}: unsupported type ${type} for ${owner}`
        : `Line ${line}: unsupported type ${type}`,
    })
  }

  const unfolded = unfoldZoneText(stripBom(text || ''))
  const lines = unfolded.split(/\r?\n/)

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (!line.trim()) continue

    const { rr, comment } = splitTrailingComment(line)
    if (!rr.trim()) {
      records.push(toCommentRow(comment))
      continue
    }

    const leadingSpace = /^\s/.test(rr)
    let tokens
    try {
      tokens = tokenizeZoneLine(rr)
    } catch (err) {
      throw new Error(`Line ${i + 1}: ${err.message}`, { cause: err })
    }
    if (tokens.length === 0) continue

    if (tokens[0].startsWith('$')) {
      const dir = tokens[0].toUpperCase()
      if (dir === '$ORIGIN') {
        if (!tokens[1]) {
          throw new Error(`Line ${i + 1}: $ORIGIN is missing a name`)
        }
        origin = ensureDot(qualifyName(tokens[1], origin))
        continue
      }
      if (dir === '$TTL') {
        continue
      }
      if (dir === '$INCLUDE') {
        throw new Error(`Line ${i + 1}: $INCLUDE is not supported`)
      }
      if (dir === '$DOMAIN') {
        records.push(
          toRecordRow({
            name: tokens[1] || '',
            ttl: null,
            type: DOMAIN_TYPE,
            value: '',
            description: comment,
          }),
        )
        continue
      }
      skipUnsupported(i + 1, dir)
      continue
    }

    let owner
    if (leadingSpace) {
      owner = lastName
    } else {
      owner = tokens.shift()
      lastName = owner
    }

    let ttl = null
    let sawClass = false
    let sawTtl = false
    while (tokens.length) {
      const t = tokens[0]
      if (!sawTtl) {
        const parsedTtl = parseTTLToken(t)
        if (parsedTtl != null) {
          ttl = parsedTtl
          sawTtl = true
          tokens.shift()
          continue
        }
      }
      if (!sawClass && isClass(t)) {
        sawClass = true
        tokens.shift()
        continue
      }
      break
    }

    if (!tokens.length) {
      throw new Error(`Line ${i + 1}: record is missing a type`)
    }
    const type = tokens.shift().toUpperCase()
    if (!tokens.length) {
      throw new Error(`Line ${i + 1}: record is missing a value`)
    }

    seenRR = true

    if (type === 'SOA') {
      skippedSoa++
      continue
    }

    const absName = qualifyName(owner, origin)
    const name = relativeName(absName, origin0)

    if (type === 'NS' && name === '@') {
      skippedApexNs++
      continue
    }

    if (!ZONE_RECORD_TYPES.includes(type)) {
      skipUnsupported(i + 1, type, name)
      continue
    }

    const { mac, description } = splitMacFromComment(comment)
    records.push(
      toRecordRow({
        name,
        ttl,
        type,
        value: formatRdata(type, tokens, origin),
        description,
        mac,
      }),
    )
  }

  if (!seenRR && records.length === 0) {
    throw new Error('No DNS records in the file')
  }

  return {
    records,
    skippedSoa,
    skippedApexNs,
    skippedUnknown: unsupported.length,
    unsupported,
  }
}

function commentLine(text) {
  const t = (text || '').trim()
  if (!t) return ';'
  return t.startsWith(';') ? t : `; ${t}`
}

/**
 * Serialize table rows (and optional SOA / NS from the product) to a BIND zone file.
 */
export function formatZoneFile({
  origin = '',
  soa = null,
  defaultTtl = 0,
  nameservers = [],
  records = [],
  comment = '',
} = {}) {
  const zone = ensureDot((origin || '').trim())
  const lines = []
  if (zone) lines.push(`$ORIGIN ${zone}`)
  if (defaultTtl) lines.push(`$TTL ${defaultTtl}`)
  for (const raw of String(comment || '').split(/\r?\n/)) {
    if (!raw.trim()) {
      if (raw.length) lines.push(';')
      continue
    }
    lines.push(commentLine(raw))
  }
  if (lines.length) lines.push('')
  if (soa) {
    const mname = ensureDot(soa.mname || 'ns')
    const rname = ensureDot(soa.rname || 'hostmaster')
    lines.push(`${padField('@', 40)}${padField('', 8)}${padField('SOA', 8)}${mname} ${rname} (`)
    const indent = ' '.repeat(56)
    lines.push(`${indent}${soa.serial ?? 1}\t; serial`)
    lines.push(`${indent}${soa.refresh ?? 3600}\t; refresh`)
    lines.push(`${indent}${soa.retry ?? 1800}\t; retry`)
    lines.push(`${indent}${soa.expire ?? 1209600}\t; expire`)
    lines.push(`${indent}${soa.ttl ?? 3600}\t; minimum`)
    lines.push(`${indent})`)
    for (const ns of nameservers || []) {
      if (!ns) continue
      lines.push(formatRRLine({ name: '@', type: 'NS', value: ensureDot(ns) }))
    }
    lines.push('')
  }
  for (const r of records || []) {
    if (isCommentRecord(r)) {
      lines.push(commentLine(r.value))
      continue
    }
    if (isDomainRecord(r)) {
      const name = (r.name || '').trim()
      if (!name) continue
      lines.push(`$DOMAIN ${name}`)
      continue
    }
    const name = (r.name || '').trim() || '@'
    const type = (r.type || 'A').toUpperCase()
    const value = r.value || ''
    if (!value) continue
    lines.push(
      formatRRLine({
        name,
        ttl: r.ttl,
        type,
        value,
        description: r.description,
        mac: r.mac,
      }),
    )
  }
  return `${lines.join('\n')}\n`
}
