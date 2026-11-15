<!-- War room, flat board: the world (dotted land, graticule) with one dot per source country of the window and,
     when a destination is set, an arc from each country to it. Arcs show activity in the window (colour of the
     majority outcome, width by events); only NEW batches launch a moving tracer (blocked: orange-red, solid head
     and tapering tail; logged: cyan, dashed and finer), which ends in a short ring at the destination.
     Without a destination there are no arcs and no destination: new batches pulse at their source instead.
     The tracers stand for "events arrived from a country" (GeoIP of the source address), not for a route.
     props:  sources [{ cc, events, blocked, logged, sources, name? }]   batches [{ id, cc, outcome, count, t }]
             destination { label, lat, lon } | null   paused   reduced   focus (ISO code)   label   describe(s)
     emits:  pick(cc) -->
<template>
  <div class="war-atlas">
    <svg class="wa-svg" viewBox="0 9 360 139" preserveAspectRatio="xMidYMid meet" role="group" :aria-label="label || null">
      <defs>
        <!-- the outline goes down to Antarctica: keep to 81 N - 58 S even where the board is taller than the map -->
        <clipPath :id="ids.clip"><rect x="0" y="9" width="360" height="139" /></clipPath>
        <pattern :id="ids.dots" patternUnits="userSpaceOnUse" width="1.55" height="1.55">
          <rect width="1.55" height="1.55" :fill="C.landBase" />
          <circle cx=".72" cy=".72" r=".43" :fill="C.landDot" />
        </pattern>
        <filter :id="ids.shine" x="-200%" y="-200%" width="500%" height="500%">
          <feGaussianBlur stdDeviation=".75" />
          <feMerge><feMergeNode /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>

      <g :clip-path="'url(#' + ids.clip + ')'">
      <g class="wa-grid" :stroke="C.grid" aria-hidden="true">
        <path v-for="x in GRID_X" :key="'x' + x" :d="'M' + x + ' 8V150'" />
        <path v-for="y in GRID_Y" :key="'y' + y" :d="'M0 ' + y + 'H360'" />
      </g>
      <path v-if="land" class="wa-land" :d="land" :fill="'url(#' + ids.dots + ')'" :stroke="C.landEdge" aria-hidden="true" />

      <!-- activity in the window: a faint wide halo, the arc itself, and a wider invisible stroke to click -->
      <g v-if="dest" class="wa-arcs">
        <g v-for="a in arcs" :key="'a' + a.cc">
          <path class="wa-halo" :d="a.d" :stroke="a.color" aria-hidden="true" />
          <path class="wa-arc" :d="a.d" :stroke="a.color" :stroke-width="a.w" :stroke-dasharray="a.dash" aria-hidden="true" />
          <path class="wa-hit" :d="a.d" @click="emit('pick', a.cc)"><title>{{ a.text }}</title></path>
        </g>
      </g>

      <!-- new batches in flight (redrawn about 30 times a second while any is moving) -->
      <g v-if="moving.trails.length || moving.rings.length" class="wa-moving" aria-hidden="true">
        <path v-for="s in moving.trails" :key="s.key" :d="s.d" :stroke="s.color" :stroke-width="s.w"
              :stroke-opacity="s.op" :stroke-dasharray="s.dash" />
        <circle v-for="r in moving.rings" :key="r.key" :cx="r.x" :cy="r.y" :r="r.r" :stroke="r.color"
                :stroke-width="r.w" :stroke-opacity="r.op" fill="none" />
        <circle v-for="h in moving.heads" :key="h.key" :cx="h.x" :cy="h.y" :r="h.r" :fill="h.fill"
                :fill-opacity="h.op" :filter="h.glow ? 'url(#' + ids.shine + ')' : null" />
        <text v-for="g in moving.tags" :key="g.key" class="wa-tag" :x="g.x" :y="g.y" :fill="g.color"
              :stroke="C.labelHalo">{{ g.text }}</text>
      </g>

      <!-- source countries: focusable, Enter / click picks -->
      <g class="wa-points">
        <g v-for="p in points" :key="'p' + p.cc" class="wa-pt" :class="{ on: p.cc === focusCc }" tabindex="0" role="button"
           :aria-label="p.text" @click="emit('pick', p.cc)" @keydown.enter.prevent="emit('pick', p.cc)"
           @keydown.space.prevent="emit('pick', p.cc)">
          <title>{{ p.text }}</title>
          <circle :cx="p.x" :cy="p.y" :r="p.halo" :fill="p.color" fill-opacity=".15" />
          <circle :cx="p.x" :cy="p.y" r="1.35" :fill="p.color" />
          <circle class="wa-ring" :cx="p.x" :cy="p.y" r="3" fill="none" :stroke="C.focus" />
          <text class="wa-code" :x="p.lx" :y="p.ly" :fill="C.label" :stroke="C.labelHalo">{{ p.cc }}</text>
        </g>
      </g>

      <!-- the receiving node -->
      <g v-if="dest" class="wa-dest" aria-hidden="true">
        <g :transform="'translate(' + dest.x + ' ' + dest.y + ')'" fill="none" :stroke="C.dest">
          <circle r="6.5" stroke-width=".3" />
          <circle r="3.8" stroke-width=".45" />
          <path d="M-8 0h4m4-8v4m8 4h-4m-4 8V4" stroke-width=".4" />
          <path d="M0 -1.8 1.8 0 0 1.8 -1.8 0Z" :fill="C.destCore" />
        </g>
        <text class="wa-destlabel" :x="dest.lx" :y="dest.y + 8" :text-anchor="dest.anchor" :fill="C.dest">{{ dest.label }}</text>
      </g>
      </g>
    </svg>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { COLORS as C, MAX_TRACERS, RING, TRAVEL, arcControl, arcPath, centre, describeDefault, eqXY, majority, quadAt, tone } from './warColors.js'
import { nextId, useTracers } from './warTracers.js'

const props = defineProps({
  sources: { type: Array, default: () => [] },
  batches: { type: Array, default: () => [] },
  destination: { type: Object, default: null },
  paused: Boolean,
  reduced: Boolean,
  focus: { type: String, default: '' },
  label: { type: String, default: '' },          // spoken name of the whole map
  describe: { type: Function, default: null },   // (source) => spoken text of a country, with its numbers
})
const emit = defineEmits(['pick'])

const GRID_X = [0, 30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 330, 360]
const GRID_Y = [30, 60, 90, 120]
const ids = { dots: nextId('wa-dots-'), shine: nextId('wa-shine-'), clip: nextId('wa-clip-') }
const land = ref('')
const focusCc = computed(() => String(props.focus || '').toUpperCase())
const say = (s) => (props.describe || describeDefault)(s)

// ---- static layer: the window's countries, their arcs, the destination ----
const dest = computed(() => {
  const d = props.destination
  if (!d || !Number.isFinite(d.lat) || !Number.isFinite(d.lon)) return null
  const [x, y] = eqXY(d.lat, d.lon)
  const right = x > 320          // near the right edge the label goes to the left of the node
  return { x, y, label: String(d.label || ''), lx: right ? x - 4 : x + 4, anchor: right ? 'end' : 'start' }
})
const placed = computed(() => props.sources
  .filter((s) => s && (s.events || 0) > 0 && centre(s.cc))
  .map((s) => {
    const [lat, lon] = centre(s.cc)
    const [x, y] = eqXY(lat, lon)
    return { s, cc: String(s.cc).toUpperCase(), x, y, n: s.events || 0, outcome: majority(s) }
  })
  .sort((a, b) => b.n - a.n))
const maxN = computed(() => Math.max(1, ...placed.value.map((p) => p.n)))

const arcs = computed(() => {
  if (!dest.value) return []
  const d = [dest.value.x, dest.value.y]
  return placed.value.map((p) => ({
    cc: p.cc, d: arcPath([p.x, p.y], d), color: tone(p.outcome), text: say(p.s),
    w: 0.25 + 0.55 * p.n / maxN.value, dash: p.outcome === 'blocked' ? null : '1 1',
  }))
})

// Country codes: try a few spots around the dot and take the first that hits no other label, dot or the
// destination label (the prototype placed them by hand for its ten countries).
const points = computed(() => {
  const boxes = placed.value.map((p) => [p.x - 1.6, p.y - 1.6, 3.2, 3.2])
  if (dest.value) {
    const w = dest.value.label.length * 2 + 1
    boxes.push([dest.value.anchor === 'end' ? dest.value.lx - w : dest.value.lx, dest.value.y + 5.4, w, 3.4], [dest.value.x - 6.5, dest.value.y - 6.5, 13, 13])
  }
  const hit = (b) => boxes.some((o) => b[0] < o[0] + o[2] && o[0] < b[0] + b[2] && b[1] < o[1] + o[3] && o[1] < b[1] + b[3])
  return placed.value.map((p) => {
    const w = p.cc.length * 2.05
    const spots = [[2.4, -1.4], [2.4, 4.2], [-2.4 - w, -1.4], [-2.4 - w, 4.2], [-w / 2, -3.2], [-w / 2, 6]]
    let [dx, dy] = spots[0]
    for (const sp of spots) {
      if (!hit([p.x + sp[0], p.y + sp[1] - 2.6, w, 3.2])) { [dx, dy] = sp; break }
    }
    boxes.push([p.x + dx, p.y + dy - 2.6, w, 3.2])
    return { cc: p.cc, x: p.x, y: p.y, lx: p.x + dx, ly: p.y + dy, color: tone(p.outcome), text: say(p.s),
             halo: 4.1 * (0.6 + 0.4 * Math.sqrt(p.n / maxN.value)) }
  })
})

// ---- moving layer ----
const tracers = useTracers()
const tick = ref(0)
let raf = 0, lastPaint = 0
const mq = typeof matchMedia === 'function' ? matchMedia('(prefers-reduced-motion: reduce)') : null
const systemReduced = ref(!!(mq && mq.matches))
const still = computed(() => props.reduced || systemReduced.value)
const canFly = () => !props.paused && !still.value && !(typeof document !== 'undefined' && document.hidden)

const moving = computed(() => {
  tick.value                                     // redraw on every painted frame
  const out = { trails: [], heads: [], rings: [], tags: [] }
  const clock = tracers.clock
  const d = dest.value ? [dest.value.x, dest.value.y] : null
  for (const tr of tracers.list) {
    const age = clock - tr.start
    if (age < 0) continue
    const [lat, lon] = centre(tr.cc)
    const s = eqXY(lat, lon)
    const color = tone(tr.outcome)
    const blocked = tr.outcome === 'blocked'
    if (!d) {                                    // no destination: a pulse where the events come from
      const g = age / 1.2
      if (g < 1) out.rings.push({ key: tr.id, x: s[0], y: s[1], r: 1.3 + 5 * g, color, w: blocked ? 0.55 : 0.35, op: (1 - g) * 0.9 })
      continue
    }
    const c = arcControl(s, d)
    const f = age / TRAVEL
    if (f < 1) {
      const head = quadAt(s, c, d, f)
      if (blocked) {
        // solid tail in six pieces, thinner and fainter towards the back, shorter as it lands
        const len = 0.13 * (1 - 0.45 * f)
        for (let k = 0; k < 6; k++) {
          const a = Math.max(0, f - len * (k + 1) / 6), b = Math.max(0, f - len * k / 6)
          if (b <= a) break
          const p = quadAt(s, c, d, a), m = quadAt(s, c, d, (a + b) / 2), q = quadAt(s, c, d, b)
          out.trails.push({ key: tr.id + '-' + k, d: line([p, m, q]), color, w: 1.25 * (1 - k / 7), op: 0.95 - k * 0.13, dash: null })
        }
        out.heads.push({ key: tr.id + '-h0', x: head[0], y: head[1], r: 2.1, fill: color, op: 0.35, glow: false })
        out.heads.push({ key: tr.id + '-h', x: head[0], y: head[1], r: 1.1, fill: C.head, op: 1, glow: true })
      } else {
        const pts = []
        for (let k = 0; k <= 6; k++) pts.push(quadAt(s, c, d, Math.max(0, f - 0.09 * (1 - k / 6))))
        out.trails.push({ key: tr.id + '-t', d: line(pts), color, w: 0.5, op: 0.85, dash: '1.1 .9' })
        out.heads.push({ key: tr.id + '-h', x: head[0], y: head[1], r: 0.7, fill: color, op: 0.95, glow: false })
      }
      if (tr.count > 1) out.tags.push({ key: tr.id + '-n', x: head[0] + 1.8, y: head[1] - 1.8, text: '×' + tr.count, color })
    } else {
      const g = (age - TRAVEL) / RING            // arrival: a short ring, stronger for a block
      if (g < 1) out.rings.push({ key: tr.id + '-r', x: d[0], y: d[1], r: blocked ? 1.5 + 5.5 * g : 1.2 + 3.3 * g,
                                  color, w: blocked ? 0.6 : 0.35, op: 1 - g })
    }
  }
  return out
})
function line(pts) { return pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(2) + ' ' + p[1].toFixed(2)).join('') }

function frame(ts) {
  raf = 0
  if (!canFly()) return
  if (ts - lastPaint >= 30) {                    // about 30 frames a second is enough for a wall
    tracers.step(lastPaint ? (ts - lastPaint) / 1000 : 0)
    lastPaint = ts
    tick.value++
  }
  if (tracers.list.length) raf = requestAnimationFrame(frame)
  else tick.value++                              // last frame: clear the finished tracers off the map
}
function run() {
  if (!raf && tracers.list.length && canFly()) { lastPaint = 0; raf = requestAnimationFrame(frame) }
}
function halt() { if (raf) cancelAnimationFrame(raf); raf = 0 }

watch(() => props.batches, (b) => { if (tracers.take(b, canFly(), MAX_TRACERS)) run() }, { deep: 1, immediate: true })
watch(() => props.paused, (p) => { if (p) halt(); else run() })
watch(still, (s) => { if (s) { halt(); tracers.clear(); tick.value++ } })
// a hidden tab draws nothing; what was in flight is stale when it comes back, so it is dropped
function onVisibility() { if (document.hidden) { halt(); tracers.clear(); tick.value++ } }
function onMotion(e) { systemReduced.value = e.matches }

onMounted(async () => {
  document.addEventListener('visibilitychange', onVisibility)
  if (mq) mq.addEventListener('change', onMotion)
  try { land.value = (await import('../charts/worldLand.js')).default } catch { land.value = '' }
})
onBeforeUnmount(() => {
  halt()
  document.removeEventListener('visibilitychange', onVisibility)
  if (mq) mq.removeEventListener('change', onMotion)
})
</script>

<style scoped>
.war-atlas { width: 100%; height: 100%; background: radial-gradient(ellipse at 64% 53%, #163737 0%, #0b2025 49%, #08191f 88%); }
.wa-svg { display: block; width: 100%; height: 100%; overflow: hidden; }
.wa-svg text { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
.wa-grid path { stroke-width: .17; fill: none; }
.wa-land { stroke-width: .15; }
.wa-halo { fill: none; stroke-width: 1.8; opacity: .09; }
.wa-arc { fill: none; opacity: .76; }
.wa-hit { fill: none; stroke: transparent; stroke-width: 3; pointer-events: stroke; cursor: pointer; }
.wa-moving path { fill: none; stroke-linecap: round; }
.wa-tag { font-size: 3px; font-weight: 700; stroke-width: .7; paint-order: stroke; }
.wa-pt { cursor: pointer; outline: none; }
.wa-pt:hover, .wa-pt:focus-visible { filter: brightness(1.55); }
.wa-ring { stroke-width: .45; opacity: 0; }
.wa-pt.on .wa-ring, .wa-pt:focus-visible .wa-ring { opacity: 1; }
.wa-code { font-size: 3.3px; stroke-width: .85; paint-order: stroke; }
.wa-destlabel { font-size: 3.3px; }
</style>
