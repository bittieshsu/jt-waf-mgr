// Tracer bookkeeping shared by WarAtlas and WarGlobe: which batches are new, when each tracer starts, and the
// animation clock that stands still while the board is paused (so a pause never replays old batches as new).
import { MAX_TRACERS, RING, STAGGER, TRAVEL, centre } from './warColors.js'

let seq = 0
// ids for SVG <defs> (patterns, filters): unique per component instance, as two maps may share a page
export function nextId(prefix) { seq += 1; return prefix + seq }

export function useTracers() {
  const seen = new Set()
  const order = []           // seen ids in arrival order, to forget the oldest (the set stays small)
  let list = []              // live tracers: { id, cc, outcome, count, start }
  let clock = 0              // seconds of animation time

  function remember(id) {
    if (seen.has(id)) return false
    seen.add(id)
    order.push(id)
    if (order.length > 2000) seen.delete(order.shift())
    return true
  }

  // Take the batches of one update. Only ids not seen before start a tracer; with `launch` false (paused,
  // reduced motion, hidden tab) they are only marked as seen, so they do not fly later.
  // Over the cap, the batches with the most events go first; the rest are not drawn (the counts keep them).
  function take(batches, launch, cap = MAX_TRACERS) {
    const fresh = (batches || []).filter((b) => b && b.id != null && remember(b.id) && centre(b.cc))
    if (!launch || !fresh.length) return 0
    const room = Math.max(0, cap - list.length)
    fresh.sort((a, b) => (b.count || 1) - (a.count || 1))
    fresh.slice(0, room).forEach((b, i) => {
      list.push({ id: b.id, cc: String(b.cc).toUpperCase(), outcome: b.outcome === 'blocked' ? 'blocked' : 'logged',
                  count: b.count || 1, start: clock + i * STAGGER })
    })
    return Math.min(room, fresh.length)
  }

  // advance the clock by dt seconds (capped: a slow frame must not skip a whole flight) and drop finished tracers
  function step(dt) {
    clock += Math.min(0.1, Math.max(0, dt))
    list = list.filter((t) => clock - t.start < TRAVEL + RING)
  }
  // keep only the first n (load shedding)
  function trim(n) { if (list.length > n) list = list.slice(0, n) }
  function clear() { list = [] }

  return {
    take, step, trim, clear,
    get list() { return list },
    get clock() { return clock },
  }
}
