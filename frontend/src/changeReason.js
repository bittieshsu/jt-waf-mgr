// A change's reason in the reader's language (0.5.4): the sentences the system writes for its own proposals come
// from the server already found (reason_parts: {key, args, values} or {text}); a person's own words, and what a
// model wrote inside a sentence, are shown as they are.
import { t, tOr } from './i18n.js'

function args(p) {
  const a = { ...(p.args || {}) }
  for (const [n, v] of Object.entries(p.values || {})) a[n] = t('creason.v.' + v)
  if (a.severity && !(p.values || {}).severity) a.severity = tOr('intel.sev.' + a.severity, a.severity)
  if (a.duration && /^\d+ h$/.test(a.duration)) a.duration = t('creason.hours', { n: a.duration.slice(0, -2) })
  return a
}

export function reasonText(c) {
  if (!c) return ''
  const parts = c.reason_parts
  if (!Array.isArray(parts) || !parts.length) return c.reason || ''
  return parts.map((p) => (p.key ? t('creason.' + p.key, args(p)) : p.text || '')).join('\n')
}
