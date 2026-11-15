<!-- War room, decision flow: how the events of the window were decided, as bands whose width is the number of
     events: source (outside / inside) -> what decided (confident rule, CRS score, country rule, other rule, logged
     only; decided_by values of the events) -> outcome (blocked / logged). One event counts once. A band or a node picks that decision (emits pick).
     props: flow { external: { confident, fallback, score, other, logged }, internal: {...} }, labels { key: text } -->
<template>
  <svg class="war-flow" :viewBox="'0 0 ' + W + ' ' + H" preserveAspectRatio="xMidYMid meet" role="img" :aria-label="label">
    <g v-for="l in links" :key="l.key" class="wf-link" :class="'t-' + l.tone" @click="emit('pick', l.pick)">
      <path :d="l.d"><title>{{ l.title }}</title></path>
    </g>
    <g v-for="n in nodes" :key="n.key" class="wf-node" :class="'t-' + n.tone" tabindex="0" role="button" :aria-label="n.label + ' ' + n.value"
       @click="emit('pick', n.pick)" @keydown.enter.prevent="emit('pick', n.pick)">
      <rect :x="n.x" :y="n.y" :width="NW" :height="Math.max(2, n.h)" rx="1.5" />
      <text :x="n.col === 2 ? n.x + NW + 8 : n.x + NW + 6" :y="n.y + n.h / 2 + 5" class="wf-label">{{ n.label }} {{ fmt(n.value) }}</text>
    </g>
    <text v-for="(c, i) in columns" :key="'c' + i" :x="colX[i]" y="18" class="wf-col">{{ c }}</text>
  </svg>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  flow: { type: Object, default: () => ({}) },
  labels: { type: Object, default: () => ({}) },
  columns: { type: Array, default: () => ['', '', ''] },
  label: { type: String, default: '' },
})
const emit = defineEmits(['pick'])
const W = 900, H = 330, NW = 8, TOP = 36, GAP = 14
const colX = [110, 420, 730]
const DEC = ['confident', 'fallback', 'score', 'other', 'logged']
const TONE = { external: 'ext', internal: 'int', confident: 'blocked', fallback: 'blocked', score: 'score', other: 'other', logged: 'logged', blocked: 'blocked', outlogged: 'logged' }
const fmt = (n) => Number(n || 0).toLocaleString()

const model = computed(() => {
  const f = props.flow || {}
  const src = ['external', 'internal'].map((k) => ({ key: k, value: Object.values(f[k] || {}).reduce((a, b) => a + b, 0) })).filter((x) => x.value > 0)
  const dec = DEC.map((k) => ({ key: k, value: (f.external?.[k] || 0) + (f.internal?.[k] || 0) })).filter((x) => x.value > 0)
  const blocked = dec.filter((d) => d.key !== 'logged').reduce((a, d) => a + d.value, 0)
  const logged = dec.find((d) => d.key === 'logged')?.value || 0
  const out = [{ key: 'blocked', value: blocked }, { key: 'outlogged', value: logged }].filter((x) => x.value > 0)
  return { src, dec, out, total: src.reduce((a, b) => a + b.value, 0) }
})
// one scale for every column (px per event), so a band is as wide at both ends
const k = computed(() => {
  const m = model.value
  const most = Math.max(1, m.src.length, m.dec.length, m.out.length)
  return (H - TOP - 10 - GAP * (most - 1)) / Math.max(1, m.total)
})
function place(list, col) {
  let y = TOP
  return list.map((n) => {
    const h = n.value * k.value
    const o = { ...n, col, x: colX[col], y, h }
    y += h + GAP
    return o
  })
}
const placed = computed(() => [place(model.value.src, 0), place(model.value.dec, 1), place(model.value.out, 2)])
const nodes = computed(() => placed.value.flat().map((n) => ({
  ...n, tone: TONE[n.key] || 'other', label: props.labels[n.key === 'outlogged' ? 'logged' : n.key] || n.key,
  pick: n.col === 0 ? { origin: n.key } : n.col === 1 ? { decision: n.key } : { outcome: n.key === 'outlogged' ? 'logged' : 'blocked' },
})))
function band(a, b, v) {
  const h = v * k.value
  const y0 = a.y + a.used, y1 = b.y + b.usedIn
  a.used += h; b.usedIn += h
  const x0 = a.x + NW, x1 = b.x, cx = (x0 + x1) / 2
  return 'M' + x0 + ',' + y0 + ' C' + cx + ',' + y0 + ' ' + cx + ',' + y1 + ' ' + x1 + ',' + y1 +
    ' L' + x1 + ',' + (y1 + h) + ' C' + cx + ',' + (y1 + h) + ' ' + cx + ',' + (y0 + h) + ' ' + x0 + ',' + (y0 + h) + ' Z'
}
const links = computed(() => {
  const [S, D, O] = placed.value.map((col) => col.map((n) => ({ ...n, used: 0, usedIn: 0 })))
  const by = (arr, k) => arr.find((n) => n.key === k)
  const out = []
  const f = props.flow || {}
  for (const s of S) {
    for (const d of D) {
      const v = f[s.key]?.[d.key] || 0
      if (v > 0) out.push({ key: s.key + d.key, d: band(s, d, v), tone: TONE[d.key], pick: { origin: s.key, decision: d.key },
                            title: (props.labels[s.key] || s.key) + ' → ' + (props.labels[d.key] || d.key) + ': ' + fmt(v) })
    }
  }
  for (const d of D) {
    const o = by(O, d.key === 'logged' ? 'outlogged' : 'blocked')
    if (o) out.push({ key: d.key + o.key, d: band(d, o, d.value), tone: TONE[d.key], pick: { decision: d.key },
                      title: (props.labels[d.key] || d.key) + ' → ' + (props.labels[o.key === 'outlogged' ? 'logged' : 'blocked'] || o.key) + ': ' + fmt(d.value) })
  }
  return out
})
</script>

<style scoped>
.war-flow { width: 100%; height: 100%; display: block; }
.wf-col { fill: #d6e4df; font-size: 15px; font-weight: 600; text-anchor: start; }
.wf-label { fill: #f6efe1; font-size: 14px; paint-order: stroke; stroke: #0a2024; stroke-width: 3px; }
.wf-link path { opacity: .42; cursor: pointer; }
.wf-link:hover path { opacity: .7; }
.wf-node { cursor: pointer; outline: none; }
.wf-node:focus-visible rect { stroke: #f3c778; stroke-width: 2; }
.t-blocked rect, .t-blocked path { fill: #ff9974; }
.t-score rect, .t-score path { fill: #f3c778; }
.t-logged rect, .t-logged path { fill: #77ebd0; }
.t-other rect, .t-other path { fill: #c99bd8; }
.t-ext rect { fill: #ff9974; }
.t-int rect { fill: #77ebd0; }
</style>
