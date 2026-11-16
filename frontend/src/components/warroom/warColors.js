// Shared palette, timing and geometry of the war-room maps (WarAtlas = flat SVG, WarGlobe = canvas globe).
// Both draw the same numbers with the same colours, so the wall can switch between them without a legend change.
// The board is always dark (it hangs on a wall), so these are fixed colours, not the app's light/dark tokens.
import CENTRE from '../charts/countryCentroids.js'

export const COLORS = {
  blocked: '#ff9974',       // orange-red: the WAF refused the request
  logged: '#77ebd0',        // cyan: only logged (detection, request went through)
  head: '#fff3ce',          // the bright head of a moving tracer
  ink: '#071216',           // board background
  inkHi: '#163737',         // centre of the board's radial glow
  inkMid: '#0b2025',
  inkLo: '#08191f',
  grid: '#315759',          // graticule on the flat map
  landDot: '#588d82',       // dotted land (flat map)
  landBase: '#193c3d',
  landEdge: '#3d6e6c',
  dest: '#bcffe3',          // the receiving node (crosshair, label)
  destCore: '#ecffdc',
  label: '#f6efe1',         // country codes
  labelHalo: '#0a2024',
  focus: '#f3c778',         // the selected country (keyboard focus, `focus` prop)
  // globe
  gGrid: '#63979456',
  gDotNear: '#79a99b',
  gDotFar: '#457c76',
  gCoast: '#89c2ae77',
  gRim: '#71c4b49c',
  gOcean: ['#27504e', '#143538', '#081a26'],
  gGlow: ['#387a7960', '#1d7d7450', '#15323800'],
  gBackDots: '#27444a',
}

// Tracer timing (seconds), the same on both maps: travel time, gap between tracers of one update, arrival ring.
export const TRAVEL = 2.65
export const STAGGER = 0.13
export const RING = 0.7
export const MAX_TRACERS = 24     // visible at once; the numbers next to the map keep every event

export function tone(outcome) { return outcome === 'blocked' ? COLORS.blocked : COLORS.logged }
// a country's static arc / dot takes the colour of the majority outcome in the window
export function majority(s) { return (s.blocked || 0) > (s.logged || 0) ? 'blocked' : 'logged' }

// [lat, lon] of a country, or null when it has no position (LAN, "?", unknown codes): those stay off the map
export function centre(cc) {
  const c = CENTRE[String(cc || '').toUpperCase()]
  return c ? c : null
}

// ---- flat map: equirectangular, 360 x 180 (x = lon + 180, y = 90 - lat), as worldLand.js ----
export function eqXY(lat, lon) { return [lon + 180, 90 - lat] }

// Control point of the arc from a source to the destination: a quadratic curve bowed upwards, flatter for
// close pairs (the prototype's route()); x is not wrapped, so the arcs never cross the map's edge.
export function arcControl(s, d) {
  return [(s[0] + d[0]) / 2, Math.max(4, Math.min(s[1], d[1]) - Math.abs(s[0] - d[0]) * 0.19 - 5)]
}
export function arcPath(s, d) {
  const c = arcControl(s, d)
  return 'M' + r2(s[0]) + ' ' + r2(s[1]) + ' Q' + r2(c[0]) + ' ' + r2(c[1]) + ' ' + r2(d[0]) + ' ' + r2(d[1])
}
// point at fraction f of the quadratic curve s -> c -> d
export function quadAt(s, c, d, f) {
  const g = 1 - f
  return [g * g * s[0] + 2 * g * f * c[0] + f * f * d[0], g * g * s[1] + 2 * g * f * c[1] + f * f * d[1]]
}
function r2(n) { return Math.round(n * 100) / 100 }

// ---- globe: unit vectors and great circles ----
const RAD = Math.PI / 180
export function vec(lat, lon) {
  const la = lat * RAD, lo = lon * RAD
  return [Math.cos(la) * Math.cos(lo), Math.cos(la) * Math.sin(lo), Math.sin(la)]
}
export function angle(a, b) { return Math.acos(Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]))) }
// spherical interpolation: the point at fraction f along the great circle a -> b (omega = angle(a, b), precomputed)
export function slerp(a, b, f, omega = angle(a, b)) {
  const s = Math.sin(omega)
  if (s < 1e-6) return a
  const p = Math.sin((1 - f) * omega) / s, q = Math.sin(f * omega) / s
  return [a[0] * p + b[0] * q, a[1] * p + b[1] * q, a[2] * p + b[2] * q]
}
// height of a tracer above the surface at fraction f: rises and falls, higher for longer routes (capped)
// at most 1.08 radius high: the globe (0.46 of the shorter side) keeps its arcs inside the board
export function lift(f, omega) { return 1 + Math.sin(Math.PI * f) * Math.min(0.08, omega * 0.06) }

// default spoken text of a source (aria-label): no words, so it needs no translation; pages pass `describe`
export function describeDefault(s) {
  return (s.name || s.cc) + ': ' + (s.events || 0) + ' (' + (s.blocked || 0) + ' / ' + (s.logged || 0) + '), ' + (s.sources || 0)
}
