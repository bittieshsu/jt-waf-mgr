<!-- War room, globe board: an orthographic globe on a canvas (back side hidden), dotted land and coasts from the
     same outline as the flat maps, graticule and glow. It turns slowly by itself (`spin`), can be dragged (the drag
     takes over from the spin) and turns smoothly to the `focus` country. Same data and colours as WarAtlas: the
     window's countries with their arcs to the destination (great circles), and for each NEW batch a tracer that
     rises and falls onto the destination, a blocked one ending in an interception ring. No destination: only the
     sources, new batches pulse there. Under load, fewer tracers first, then fewer frames.
     A visually hidden list makes every source reachable by keyboard (also those on the back side): focusing one
     turns the globe to it, Enter picks it.
     props:  sources  batches  destination  paused  reduced  spin  focus  label  describe   (see WarAtlas)
     emits:  pick(cc) -->
<template>
  <div ref="root" class="war-globe">
    <canvas ref="cv" class="wg-canvas" :class="{ dragging: dragOn }" role="img" :aria-label="label || null"
            @pointerdown="down" @pointermove="move" @pointerup="up" @pointercancel="cancel" />
    <ul class="wg-keys">
      <li v-for="p in placed" :key="p.cc" role="button" tabindex="0" :aria-label="p.text"
          @focus="kb = p.cc" @blur="kb = ''" @keydown.enter.prevent="emit('pick', p.cc)"
          @keydown.space.prevent="emit('pick', p.cc)">{{ p.cc }}</li>
    </ul>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { COLORS as C, RING, TRAVEL, angle, centre, describeDefault, lift, majority, slerp, tone, vec } from './warColors.js'
import { useTracers } from './warTracers.js'
import { globeLand } from './globeLand.js'

const props = defineProps({
  sources: { type: Array, default: () => [] },
  batches: { type: Array, default: () => [] },
  destination: { type: Object, default: null },
  paused: Boolean,
  reduced: Boolean,
  spin: { type: Boolean, default: true },
  focus: { type: String, default: '' },
  label: { type: String, default: '' },
  describe: { type: Function, default: null },
})
const emit = defineEmits(['pick'])

const RAD = Math.PI / 180
const SPIN = 1.5                       // degrees a second, westwards like the Earth seen from space
const CAPS = [24, 12, 6, 3]            // visible tracers by load level
const FRAME = [33, 33, 50, 66]         // ms between frames by load level
// graticule, once: parallels every 15 degrees, meridians every 30
const GRAT = []
for (let lat = -75; lat <= 75; lat += 15) GRAT.push(Array.from({ length: 121 }, (_, j) => vec(lat, j * 3 - 180)))
for (let lon = -180; lon < 180; lon += 30) GRAT.push(Array.from({ length: 61 }, (_, j) => vec(j * 3 - 90, lon)))

const root = ref(null)
const cv = ref(null)
const kb = ref('')                     // source focused in the keyboard list
const dragOn = ref(false)
let ctx = null, land = null, ro = null
let w = 0, h = 0, dpr = 1
let yaw = 20, pitch = 20               // the point at the centre of the view (degrees)
let aim = null                         // { yaw, pitch } to turn to
let drag = null, dragEnd = 0, hits = []
let raf = 0, lastPaint = 0, level = 0, slow = 0, calm = 0
let V = null                           // this frame's projection (rotation, radius, centre)

const tracers = useTracers()
const mq = typeof matchMedia === 'function' ? matchMedia('(prefers-reduced-motion: reduce)') : null
const systemReduced = ref(!!(mq && mq.matches))
const still = computed(() => props.reduced || systemReduced.value)
const focusCc = computed(() => (kb.value || String(props.focus || '')).toUpperCase())
const say = (s) => (props.describe || describeDefault)(s)
const canFly = () => !props.paused && !still.value && !document.hidden

const target = computed(() => {
  const d = props.destination
  return d && Number.isFinite(d.lat) && Number.isFinite(d.lon) ? { v: vec(d.lat, d.lon), label: String(d.label || '') } : null
})
const placed = computed(() => {
  const list = props.sources
    .filter((s) => s && (s.events || 0) > 0 && centre(s.cc))
    .map((s) => {
      const [lat, lon] = centre(s.cc)
      return { cc: String(s.cc).toUpperCase(), v: vec(lat, lon), n: s.events || 0, outcome: majority(s), text: say(s) }
    })
    .sort((a, b) => b.n - a.n)
  const max = Math.max(1, ...list.map((p) => p.n))
  for (const p of list) p.share = p.n / max
  return list
})

// ---- projection ----
// orthographic: [x, y, depth, visible]; alt > 1 lifts the point (tracers), visible when in front of the globe or
// lifted far enough to show beside its edge
function pj(v, alt = 1) {
  const k = v[0] * V.cy + v[1] * V.sy
  const depth = k * V.cp + v[2] * V.sp
  const x = -v[0] * V.sy + v[1] * V.cy, y = -k * V.sp + v[2] * V.cp
  return [V.ox + V.R * alt * x, V.oy - V.R * alt * y, depth, depth > 0.012 || (alt > 1 && alt * Math.hypot(x, y) > 1)]
}
function curve(a, b, f, omega) { return pj(slerp(a, b, f, omega), lift(f, omega)) }
function arcPoints(a, b, n, from = 0, to = 1) {
  const omega = angle(a, b), out = []
  for (let k = 0; k <= n; k++) out.push(curve(a, b, from + (to - from) * k / n, omega))
  return out
}

// ---- drawing ----
function dot(x, y, r, fill) { ctx.fillStyle = fill; ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill() }
function line(pts, colour, width, dash = null) {
  ctx.strokeStyle = colour
  ctx.lineWidth = width
  ctx.setLineDash(dash || [])
  ctx.beginPath()
  let pen = false
  for (const p of pts) {
    if (!p[3]) { pen = false; continue }
    if (pen) ctx.lineTo(p[0], p[1]); else ctx.moveTo(p[0], p[1])
    pen = true
  }
  ctx.stroke()
  ctx.setLineDash([])
}
function ringAt(x, y, r, colour, width, alpha) {
  ctx.globalAlpha = Math.max(0, alpha)
  ctx.strokeStyle = colour
  ctx.lineWidth = width
  ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.stroke()
  ctx.globalAlpha = 1
}

function draw() {
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  ctx.clearRect(0, 0, w, h)
  const R = Math.min(w, h) * 0.41, ox = w / 2, oy = h / 2
  V = { R, ox, oy, cy: Math.cos(yaw * RAD), sy: Math.sin(yaw * RAD), cp: Math.cos(pitch * RAD), sp: Math.sin(pitch * RAD) }
  const font = Math.max(11, Math.round(R * 0.04))

  // the board: a sparse dot grid, the glow around the globe, the sea
  ctx.fillStyle = C.gBackDots
  for (let x = 12; x < w; x += 32) for (let y = 8; y < h; y += 32) ctx.fillRect(x, y, 1, 1)
  const glow = ctx.createRadialGradient(ox, oy, R * 0.8, ox, oy, R * 1.22)
  glow.addColorStop(0, C.gGlow[0]); glow.addColorStop(0.66, C.gGlow[1]); glow.addColorStop(1, C.gGlow[2])
  dot(ox, oy, R * 1.23, glow)
  const sea = ctx.createRadialGradient(ox - R * 0.45, oy - R * 0.55, 0, ox, oy, R * 1.1)
  sea.addColorStop(0, C.gOcean[0]); sea.addColorStop(0.72, C.gOcean[1]); sea.addColorStop(1, C.gOcean[2])
  dot(ox, oy, R, sea)
  for (const g of GRAT) line(g.map((v) => pj(v)), C.gGrid, 0.6)

  // dotted land: two paths (near the centre brighter), one fill each
  if (land) {
    const near = new Path2D(), far = new Path2D(), d = land.dots, s = Math.min(2.2, R * 0.0065)
    for (let i = 0; i < d.length; i += 3) {
      const k = d[i] * V.cy + d[i + 1] * V.sy
      const depth = k * V.cp + d[i + 2] * V.sp
      if (depth <= 0.02) continue
      const x = ox + R * (-d[i] * V.sy + d[i + 1] * V.cy), y = oy - R * (-k * V.sp + d[i + 2] * V.cp);
      (depth > 0.52 ? near : far).rect(x, y, Math.max(0.6, s * depth), Math.max(0.7, s))
    }
    ctx.fillStyle = C.gDotFar; ctx.fill(far)
    ctx.fillStyle = C.gDotNear; ctx.fill(near)
    for (const c of land.coasts) {
      const pts = []
      for (let i = 0; i < c.length; i += 3) pts.push(pj([c[i], c[i + 1], c[i + 2]]))
      line(pts, C.gCoast, 0.65)
    }
  }
  ctx.lineWidth = 1.2; ctx.strokeStyle = C.gRim
  ctx.beginPath(); ctx.arc(ox, oy, R, 0, Math.PI * 2); ctx.stroke()
  if (w > 600) {                       // a scale-like arc above the globe (decoration, as in the design)
    const e = R * 1.09
    ctx.strokeStyle = '#49787388'; ctx.lineWidth = 0.65
    ctx.setLineDash([2, 9]); ctx.beginPath(); ctx.arc(ox, oy, e, -2.95, -0.15); ctx.stroke(); ctx.setLineDash([])
    ctx.beginPath()
    for (let k = 0; k < 32; k++) {
      const a = -2.95 + k * 0.09
      ctx.moveTo(ox + Math.cos(a) * e, oy + Math.sin(a) * e); ctx.lineTo(ox + Math.cos(a) * (e + 3), oy + Math.sin(a) * (e + 3))
    }
    ctx.stroke()
  }

  // the window: an arc from each country to the destination, then the countries on top
  const dest = target.value
  if (dest) {
    for (const p of placed.value) {
      line(arcPoints(p.v, dest.v, 52), tone(p.outcome) + 'bb', 0.8 + 0.8 * p.share, p.outcome === 'blocked' ? null : [4, 4])
    }
  }
  hits = []
  const boxes = []
  ctx.font = font + 'px ui-monospace, Menlo, Consolas, monospace'
  for (const p of placed.value) {
    const q = pj(p.v)
    if (!q[3]) continue
    const colour = tone(p.outcome)
    dot(q[0], q[1], 2.6 + 2.4 * Math.sqrt(p.share), colour + '55')
    dot(q[0], q[1], 2.1, colour)
    if (p.cc === focusCc.value) ringAt(q[0], q[1], 8, C.focus, 1.5, 1)
    hits.push([q[0], q[1], p.cc])
    // a code is left out when it would cover one already written (bigger countries first), unless focused
    const bw = ctx.measureText(p.cc).width, box = [q[0] + 5, q[1] - 5 - font, bw, font]
    const over = boxes.some((o) => box[0] < o[0] + o[2] && o[0] < box[0] + box[2] && box[1] < o[1] + o[3] && o[1] < box[1] + box[3])
    if (!over || p.cc === focusCc.value) {
      boxes.push(box)
      ctx.lineWidth = 3; ctx.strokeStyle = C.labelHalo; ctx.strokeText(p.cc, q[0] + 5, q[1] - 5)
      ctx.fillStyle = C.label; ctx.fillText(p.cc, q[0] + 5, q[1] - 5)
    }
  }

  drawTracers(dest, font)

  if (dest) {
    const q = pj(dest.v)
    if (q[3]) {
      ctx.strokeStyle = C.dest; ctx.lineWidth = 1.2
      ctx.strokeRect(q[0] - 4, q[1] - 4, 8, 8)
      ctx.fillStyle = C.destCore; ctx.fillRect(q[0] - 1.5, q[1] - 1.5, 3, 3)
      ctx.font = 'bold ' + (font + 1) + 'px ui-monospace, Menlo, Consolas, monospace'
      ctx.lineWidth = 3; ctx.strokeStyle = C.labelHalo; ctx.strokeText(dest.label, q[0] + 8, q[1] + 16)
      ctx.fillStyle = C.dest; ctx.fillText(dest.label, q[0] + 8, q[1] + 16)
    }
  }
}

function drawTracers(dest, font) {
  const clock = tracers.clock
  const fx = level < 2                 // glow only while frames are cheap
  ctx.font = 'bold ' + font + 'px ui-monospace, Menlo, Consolas, monospace'
  for (const tr of tracers.list) {
    const age = clock - tr.start
    if (age < 0) continue
    const [lat, lon] = centre(tr.cc)
    const a = vec(lat, lon), colour = tone(tr.outcome), blocked = tr.outcome === 'blocked'
    if (!dest) {                       // no destination: a pulse at the source
      const g = age / 1.2, q = pj(a)
      if (g < 1 && q[3]) ringAt(q[0], q[1], 3 + 16 * g, colour, blocked ? 1.6 : 1, 1 - g)
      continue
    }
    const f = age / TRAVEL
    if (f < 1) {
      const omega = angle(a, dest.v)
      if (blocked) {
        // solid tail in three pieces, thinner and fainter towards the back
        const len = 0.1 * (1 - 0.4 * f)
        for (let k = 2; k >= 0; k--) {
          const from = Math.max(0, f - len * (k + 1) / 3), to = Math.max(0, f - len * k / 3)
          if (to <= from) continue
          ctx.globalAlpha = 1 - k * 0.3
          line(arcPoints(a, dest.v, 4, from, to), colour, 3.4 - k * 0.9)
        }
        ctx.globalAlpha = 1
      } else {
        line(arcPoints(a, dest.v, 6, Math.max(0, f - 0.08), f), colour, 1.4, [3, 3])
      }
      const q = curve(a, dest.v, f, omega)
      if (q[3]) {
        if (fx) { ctx.shadowColor = colour; ctx.shadowBlur = blocked ? 14 : 8 }
        dot(q[0], q[1], blocked ? 2.2 : 1.5, blocked ? C.head : colour)
        ctx.shadowBlur = 0
        if (tr.count > 1) {
          const tag = '×' + tr.count
          ctx.lineWidth = 3; ctx.strokeStyle = C.labelHalo; ctx.strokeText(tag, q[0] + 6, q[1] - 6)
          ctx.fillStyle = colour; ctx.fillText(tag, q[0] + 6, q[1] - 6)
        }
      }
    } else {
      const g = (age - TRAVEL) / RING, q = pj(dest.v)
      if (g < 1 && q[3]) {
        if (blocked) {                 // interception: a ring opening at the destination, a second one behind it
          ringAt(q[0], q[1], 4 + 18 * g, colour, 1.8, 1 - g)
          if (g > 0.25) ringAt(q[0], q[1], 4 + 18 * (g - 0.25), colour, 1, (1 - g) * 0.6)
        } else ringAt(q[0], q[1], 3 + 8 * g, colour, 0.8, (1 - g) * 0.7)
      }
    }
  }
}

// ---- the loop: runs only while something moves; otherwise one frame per change ----
function busy() {
  if (document.hidden || !ctx) return false
  if (aim || drag) return true
  if (props.paused || still.value) return false
  return tracers.list.length > 0 || (props.spin && !focusCc.value)
}
function frame(ts) {
  raf = 0
  if (!ctx || document.hidden) return
  const interval = lastPaint ? ts - lastPaint : FRAME[level]
  if (interval < FRAME[level] - 3) { raf = requestAnimationFrame(frame); return }
  lastPaint = ts
  const dt = Math.min(0.1, interval / 1000)
  if (canFly()) tracers.step(dt)
  turn(dt)
  const t0 = performance.now()
  draw()
  shed(interval, performance.now() - t0)
  if (busy()) raf = requestAnimationFrame(frame)
}
function kick() {
  if (raf || !ctx || document.hidden) return
  lastPaint = 0
  raf = requestAnimationFrame(frame)
}
function halt() { if (raf) cancelAnimationFrame(raf); raf = 0 }

function turn(dt) {
  if (drag) return
  if (aim) {
    if (still.value) { yaw = aim.yaw; pitch = aim.pitch; aim = null; return }
    const dy = ((aim.yaw - yaw + 540) % 360) - 180, dp = aim.pitch - pitch
    const k = Math.min(1, dt * 3.5)
    yaw += dy * k; pitch += dp * k
    if (Math.abs(dy) < 0.2 && Math.abs(dp) < 0.2) { yaw = aim.yaw; pitch = aim.pitch; aim = null }
    return
  }
  // the spin takes over again a few seconds after a drag, and never while a country is in focus
  if (props.spin && !props.paused && !still.value && !focusCc.value && performance.now() - dragEnd > 4000) yaw -= SPIN * dt
}

// Under load (frames slower than 50 ms a few times in a row) show fewer tracers first, then draw less often;
// after ten calm seconds go back one step.
function shed(interval, cost) {
  if (cost > 50 || interval > Math.max(50, FRAME[level] * 2)) {
    calm = 0
    if (++slow >= 4 && level < CAPS.length - 1) { level++; slow = 0; tracers.trim(CAPS[level]) }
  } else {
    slow = 0
    calm += interval
    if (calm > 10000 && level > 0) { level--; calm = 0 }
  }
}

// ---- pointer: drag to turn, a short click picks the nearest visible source ----
function down(e) {
  drag = { x: e.clientX, y: e.clientY, yaw, pitch }
  dragOn.value = true
  aim = null
  cv.value.setPointerCapture(e.pointerId)
  kick()
}
function move(e) {
  if (!drag) return
  const k = 90 / Math.max(60, Math.min(w, h) * 0.41)      // about a quarter turn for a drag across the radius
  yaw = drag.yaw - (e.clientX - drag.x) * k
  pitch = Math.max(-80, Math.min(80, drag.pitch + (e.clientY - drag.y) * k))
  kick()
}
function up(e) {
  if (drag && Math.hypot(e.clientX - drag.x, e.clientY - drag.y) < 5) {
    const r = cv.value.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top
    let best = null, bd = 14
    for (const [hx, hy, cc] of hits) {
      const d = Math.hypot(hx - x, hy - y)
      if (d < bd) { bd = d; best = cc }
    }
    if (best) emit('pick', best)
  }
  cancel()
}
function cancel() { drag = null; dragOn.value = false; dragEnd = performance.now(); kick() }

// ---- data and props ----
function aimAt(cc) {
  const c = cc && centre(cc)
  if (!c) { aim = null; return }
  aim = { yaw: c[1], pitch: Math.max(-60, Math.min(60, c[0])) }
}
watch(() => props.batches, (b) => { if (tracers.take(b, canFly(), CAPS[level])) kick() }, { deep: 1, immediate: true })
watch(focusCc, (cc) => { aimAt(cc); kick() })
watch(still, (s) => { if (s) tracers.clear(); kick() })
watch(() => [props.sources, props.destination, props.spin, props.paused], kick, { deep: 2 })

function resize() {
  if (!root.value || !cv.value) return
  dpr = Math.min(1.5, window.devicePixelRatio || 1)
  w = root.value.clientWidth
  h = root.value.clientHeight
  cv.value.width = Math.max(1, Math.round(w * dpr))
  cv.value.height = Math.max(1, Math.round(h * dpr))
  halt()
  kick()
}
function onVisibility() {
  if (document.hidden) { halt(); tracers.clear() } else kick()
}
function onMotion(e) { systemReduced.value = e.matches }

onMounted(async () => {
  ctx = cv.value.getContext('2d')
  const d = props.destination
  if (d && Number.isFinite(d.lon)) { yaw = d.lon - 45; pitch = 25 }
  if (focusCc.value) aimAt(focusCc.value)
  ro = new ResizeObserver(resize)
  ro.observe(root.value)
  resize()
  document.addEventListener('visibilitychange', onVisibility)
  if (mq) mq.addEventListener('change', onMotion)
  land = await globeLand()
  kick()
})
onBeforeUnmount(() => {
  halt()
  ctx = null
  if (ro) ro.disconnect()
  document.removeEventListener('visibilitychange', onVisibility)
  if (mq) mq.removeEventListener('change', onMotion)
})
</script>

<style scoped>
.war-globe { position: relative; width: 100%; height: 100%; overflow: hidden;
  background: radial-gradient(ellipse at 52% 45%, #173c3c, #0a1b22 67%); }
.wg-canvas { display: block; width: 100%; height: 100%; touch-action: none; cursor: grab; }
.wg-canvas.dragging { cursor: grabbing; }
/* keyboard list of the sources: off screen, read by screen readers, focus turns the globe */
.wg-keys { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; overflow: hidden;
  clip: rect(0 0 0 0); white-space: nowrap; list-style: none; }
</style>
