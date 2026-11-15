<!-- A block of configuration or command text with light syntax colours: comments, strings, keywords / directives,
     variables, numbers, section names and log levels. Plain text spans only (never HTML), so a value from a
     request or a file stays text. lang: nginx | shell | ini | modsec | json | log | text. -->
<template>
  <pre class="code codeblock" :class="{ small }"><template v-for="(line, i) in lines" :key="i"><span v-for="(p, j) in line" :key="j" :class="p.c ? 'cb-' + p.c : null">{{ p.s }}</span>{{ i < lines.length - 1 ? '\n' : '' }}</template></pre>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  code: { type: String, default: '' },
  lang: { type: String, default: 'text' },
  small: Boolean,
})

const NGINX = /^(?:include|server|location|if|return|deny|allow|listen|server_name|root|error_page|internal|ssi|add_header|modsecurity|modsecurity_rules_file|proxy_pass|set_real_ip_from|real_ip_header|http|events|map|geo|set|rewrite|try_files|client_max_body_size|ssl_certificate|ssl_certificate_key)\b/
const MODSEC = /^(?:SecRule|SecAction|SecRuleEngine|SecRuleRemoveById|SecRuleRemoveByTag|SecRuleUpdateTargetById|SecMarker|SecDefaultAction|Include)\b/
const SHELL = /^(?:sudo|install|nginx|systemctl|curl|cat|echo|export|cd|ls|chmod|chown|tar|sha256sum|openssl|python3|jt-waf-mgr|apt|ssh|scp)\b/
// one line -> pieces { s, c } (c: comment, string, key, var, num, section, level, punct)
function tokenize(line, lang) {
  const out = []
  const push = (s, c) => { if (s) out.push({ s, c }) }
  if (lang === 'text') return [{ s: line }]
  if (lang === 'log') {
    const m = /\[(emerg|alert|crit|error|warn|notice|info|debug)\]/.exec(line)
    if (!m) return /\b(successful|ok)\b/i.test(line) ? [{ s: line, c: 'ok' }] : [{ s: line }]
    push(line.slice(0, m.index)); push(m[0], ['warn', 'notice', 'info', 'debug'].includes(m[1]) ? 'warnlvl' : 'errlvl'); push(line.slice(m.index + m[0].length))
    return out
  }
  if (lang === 'ini') {
    const t = line.trim()
    if (/^[#;]/.test(t)) return [{ s: line, c: 'comment' }]
    if (/^\[.*\]$/.test(t)) return [{ s: line, c: 'section' }]
    const m = /^(\s*)([\w.-]+)(\s*=\s*)(.*)$/.exec(line)
    if (m) { push(m[1]); push(m[2], 'key'); push(m[3], 'punct'); out.push(...tokenize(m[4], 'shell')); return out }
  }
  if (lang === 'json') {
    const re = /("(?:[^"\\]|\\.)*")(\s*:)?|(-?\d+(?:\.\d+)?)|\b(true|false|null)\b/g
    let last = 0, m
    while ((m = re.exec(line))) {
      push(line.slice(last, m.index))
      if (m[1]) { push(m[1], m[2] ? 'key' : 'string'); push(m[2] || '', 'punct') } else push(m[0], m[3] ? 'num' : 'key')
      last = re.lastIndex
    }
    push(line.slice(last))
    return out
  }
  // nginx, modsec, shell: first word a directive / command, then strings, variables, numbers, a trailing comment
  let rest = line
  const lead = /^\s*/.exec(rest)[0]
  push(lead); rest = rest.slice(lead.length)
  if (rest.startsWith('#')) return out.concat({ s: rest, c: 'comment' })
  const kw = lang === 'nginx' ? NGINX : lang === 'modsec' ? MODSEC : SHELL
  const k = kw.exec(rest)
  if (k) { push(k[0], 'key'); rest = rest.slice(k[0].length) }
  const re = /("(?:[^"\\]|\\.)*"|'[^']*')|(\$[\w{}]+)|(\s#.*$)|\b(\d+(?:\.\d+)?[smhdkKmMgG]?)\b/g
  let last = 0, m
  while ((m = re.exec(rest))) {
    push(rest.slice(last, m.index))
    push(m[0], m[1] ? 'string' : m[2] ? 'var' : m[3] ? 'comment' : 'num')
    last = re.lastIndex
  }
  push(rest.slice(last))
  return out
}
const lines = computed(() => String(props.code || '').split('\n').map((l) => tokenize(l, props.lang)))
</script>

<style scoped>
.codeblock { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; }
.cb-comment { color: var(--muted); font-style: italic; }
.cb-string { color: var(--ok); }
.cb-key { color: var(--series-1); font-weight: 600; }
.cb-var { color: var(--blocked); }
.cb-num { color: var(--score, var(--warn)); }
.cb-section { color: var(--accent); font-weight: 700; }
.cb-punct { color: var(--muted); }
.cb-errlvl { color: var(--blocked); font-weight: 700; }
.cb-warnlvl { color: var(--warn); font-weight: 700; }
.cb-ok { color: var(--ok); }
</style>
