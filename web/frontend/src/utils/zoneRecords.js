// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Types Portitor's fwconfig accepts (internal/fwconfig/validate.go).
export const ZONE_RECORD_TYPES = [
  'A',
  'AAAA',
  'CAA',
  'CNAME',
  'MX',
  'NS',
  'PTR',
  'SRV',
  'SSHFP',
  'TLSA',
  'TXT',
]

export const COMMENT_TYPE = 'COMMENT'
export const DOMAIN_TYPE = '$DOMAIN'

/** Leading integer fields in rdata: MX preference; SRV priority/weight/port; TLSA usage/selector/matching. */
export const RDATA_INT_PREFIX = {
  MX: 1,
  SRV: 3,
  TLSA: 3,
}

export function isCommentRecord(row) {
  return (row?.type || '').toUpperCase() === COMMENT_TYPE
}

export function isDomainRecord(row) {
  return (row?.type || '').toUpperCase() === DOMAIN_TYPE
}

export function isSpanningRecord(row) {
  return isCommentRecord(row) || isDomainRecord(row)
}

/**
 * Record indices that belong to the same $DOMAIN group as `index`.
 * The $DOMAIN header is not included. `hi` is exclusive.
 * Apex records (before the first $DOMAIN) use lo = 0.
 */
export function subzoneRecordRange(rows, index) {
  const list = rows || []
  if (index < 0 || index >= list.length) return { lo: 0, hi: 0 }
  if (isDomainRecord(list[index])) {
    let hi = list.length
    for (let i = index + 1; i < list.length; i++) {
      if (isDomainRecord(list[i])) {
        hi = i
        break
      }
    }
    return { lo: index + 1, hi }
  }
  let lo = 0
  for (let i = index - 1; i >= 0; i--) {
    if (isDomainRecord(list[i])) {
      lo = i + 1
      break
    }
  }
  let hi = list.length
  for (let i = index + 1; i < list.length; i++) {
    if (isDomainRecord(list[i])) {
      hi = i
      break
    }
  }
  return { lo, hi }
}

export function rdataPrefixCount(type) {
  return RDATA_INT_PREFIX[type] ?? 0
}

export function splitRdataFields(type, value) {
  const prefix = rdataPrefixCount(type)
  const fields = Array.from({ length: prefix + 1 }, () => '')
  const trimmed = (value ?? '').trim()
  if (!trimmed) return fields
  const tokens = trimmed.split(/\s+/)
  let i = 0
  while (i < prefix && i < tokens.length && /^\d+$/.test(tokens[i])) {
    fields[i] = tokens[i]
    i++
  }
  fields[prefix] = tokens.slice(i).join(' ')
  return fields
}

export function joinRdataFields(fields) {
  return (fields ?? [])
    .map((f) => String(f ?? '').trim())
    .join(' ')
    .replace(/\s+/g, ' ')
    .trim()
}

export function emptyZoneRecord() {
  return {
    _key: crypto.randomUUID(),
    name: '',
    ttl: null,
    type: 'A',
    value: '',
    description: '',
    mac: '',
  }
}

export function emptyCommentRecord() {
  return {
    _key: crypto.randomUUID(),
    name: ';',
    ttl: null,
    type: COMMENT_TYPE,
    value: '',
    description: '',
  }
}

export function emptyDomainRecord() {
  return {
    _key: crypto.randomUUID(),
    name: '',
    ttl: null,
    type: DOMAIN_TYPE,
    value: '',
    description: '',
  }
}

function normalizeTtl(ttl) {
  if (ttl === null || ttl === undefined || ttl === '') return null
  const n = Number(ttl)
  return Number.isFinite(n) ? n : null
}

export function recordOrigin(row) {
  const comment = isCommentRecord(row)
  const domain = isDomainRecord(row)
  return {
    name: comment ? ';' : row?.name || '',
    ttl: comment || domain ? null : normalizeTtl(row?.ttl),
    type: row?.type || '',
    value: domain ? '' : row?.value || '',
    description: comment || domain ? '' : row?.description || '',
    mac: comment || domain ? '' : row?.mac || '',
  }
}

export function attachRecordOrigin(row) {
  row._orig = recordOrigin(row)
  return row
}

export function isRecordChanged(row) {
  if (!row) return false
  if (row._orig == null) return true
  const cur = recordOrigin(row)
  const orig = row._orig
  return (
    cur.name !== orig.name ||
    cur.ttl !== orig.ttl ||
    cur.type !== orig.type ||
    cur.value !== orig.value ||
    cur.description !== orig.description ||
    cur.mac !== orig.mac
  )
}

export function fromApiRecord(row) {
  const type = row.type || 'A'
  const comment = isCommentRecord({ type })
  const domain = isDomainRecord({ type })
  return attachRecordOrigin({
    _key: row.id != null ? `id-${row.id}` : crypto.randomUUID(),
    name: comment ? ';' : row.name || '',
    ttl: comment || domain || !row.ttl ? null : row.ttl,
    type,
    value: domain ? '' : row.value || '',
    description: comment || domain ? '' : row.description || '',
    mac: comment || domain ? '' : row.mac || '',
  })
}

export function toApiRecords(rows) {
  return rows
    .filter((r) => {
      if (isCommentRecord(r) || isDomainRecord(r)) return true
      return (r.name || '').trim() || (r.value || '').trim()
    })
    .map((r) => {
      if (isCommentRecord(r)) {
        return {
          name: ';',
          ttl: 0,
          type: COMMENT_TYPE,
          value: (r.value || '').trim(),
          description: '',
          mac: '',
        }
      }
      if (isDomainRecord(r)) {
        return {
          name: (r.name || '').trim(),
          ttl: 0,
          type: DOMAIN_TYPE,
          value: '',
          description: '',
          mac: '',
        }
      }
      let ttl = 0
      if (r.ttl !== null && r.ttl !== undefined && r.ttl !== '') {
        const n = Number(r.ttl)
        if (Number.isFinite(n) && n > 0) ttl = n
      }
      const type = (r.type || '').toUpperCase()
      const mac = type === 'A' || type === 'AAAA' ? (r.mac || '').trim() : ''
      return {
        name: (r.name || '').trim(),
        ttl,
        type: r.type,
        value: (r.value || '').trim(),
        description: (r.description || '').trim(),
        mac,
      }
    })
}

export function isIPv4Address(value) {
  if (typeof value !== 'string' || value.includes(':')) return false
  const parts = value.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return false
    const n = Number(part)
    return n <= 255
  })
}

export function isIPv6Address(value) {
  if (typeof value !== 'string' || value.includes('.')) return false
  try {
    return Boolean(new URL(`http://[${value}]`).hostname)
  } catch {
    return false
  }
}

export function validateZoneRecord(row, t) {
  const name = (row.name || '').trim()
  const type = (row.type || '').toUpperCase()
  const value = (row.value || '').trim()
  if (type === COMMENT_TYPE) return null
  if (type === DOMAIN_TYPE) {
    if (!name) return t('zoneRecords.nameRequired')
    return null
  }
  if (!name) return t('zoneRecords.nameRequired')
  if (!type) return t('zoneRecords.typeRequired')
  if (!ZONE_RECORD_TYPES.includes(type)) {
    return t('zoneRecords.unknownType', { type })
  }
  if (!value) return t('zoneRecords.valueRequired')
  if (type === 'A' && !isIPv4Address(value)) {
    return t('zoneRecords.aMustBeIpv4')
  }
  if (type === 'AAAA' && !isIPv6Address(value)) {
    return t('zoneRecords.aaaaMustBeIpv6')
  }
  const mac = (row.mac || '').trim()
  if (mac && type !== 'A' && type !== 'AAAA') {
    return t('zoneRecords.macOnlyA')
  }
  if (mac && !isMacAddress(mac)) {
    return t('zoneRecords.macInvalid')
  }
  return null
}

export function isMacAddress(value) {
  if (typeof value !== 'string') return false
  const hex = value.toLowerCase().replace(/[:\-.]/g, '')
  return /^[0-9a-f]{12}$/.test(hex)
}

export function validateZoneRecords(rows, t) {
  const payload = toApiRecords(rows)
  for (let i = 0; i < payload.length; i++) {
    const err = validateZoneRecord(payload[i], t)
    if (err) return t('zoneRecords.recordN', { n: i + 1, message: err })
  }
  return null
}
