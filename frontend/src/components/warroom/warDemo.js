// Demo mode for the war room: made-up traffic of a site under steady attack, made in the browser. Nothing is read from
// or sent to the server (no event, no address, no site of ours): the answers have the shapes of /warroom/snapshot,
// /warroom/events and /warroom/ops so the board draws them like the real ones. Sites are example.com names, internal
// ones the same aliases the real board uses; ids start far above real ones and are never links (the board blocks them).
//
// The rate is a smooth swell plus "waves": for some 4-minute slots one country sends much more. The same function of
// time feeds the snapshot (counted per step, not event by event, so 7 days cost nothing) and the 5-second polls, so a
// timeline and the events that follow it agree.

const COUNTRIES = [['CN', 22], ['US', 16], ['RU', 12], ['NL', 7], ['DE', 6], ['BR', 5], ['IN', 5], ['VN', 5], ['KR', 4], ['SG', 4],
  ['FR', 3], ['GB', 3], ['HK', 3], ['ID', 3], ['JP', 2], ['TR', 2], ['UA', 2], ['IR', 2], ['RO', 1], ['ZA', 1]]
const HOSTS = [['www.example.com', 20], ['shop.example.com', 16], ['api.example.com', 14], ['portal.example.com', 9],
  ['mail.example.com', 7], ['blog.example.org', 6], ['cdn.example.net', 5], ['internal-1', 3], ['internal-2', 2]]
const DECISIONS = [['confident', 55], ['score', 28], ['fallback', 12], ['other', 5]]
const SLOT = 240000                       // a wave lasts one slot (4 minutes)
const INTERNAL = 0.04, UNLOCATED = 0.02, BLOCKED_OUT = 0.72, BLOCKED_IN = 0.15

const sum = (l) => l.reduce((a, x) => a + x[1], 0)
const iso = (ms) => new Date(ms).toISOString()
// a fixed pseudo-random number for an integer (the same slot always has the same wave)
function hash(n) { const x = Math.sin(n * 12.9898 + 78.233) * 43758.5453; return x - Math.floor(x) }
function pickW(list, r) {
  let x = r * sum(list)
  for (const [k, w] of list) { x -= w; if (x < 0) return k }
  return list[list.length - 1][0]
}
// the wave at a time: { cc, rate } or null
function wave(ms) {
  const slot = Math.floor(ms / SLOT)
  if (hash(slot) < 0.5) return null
  const f = (ms - slot * SLOT) / SLOT
  return { cc: COUNTRIES[Math.floor(hash(slot + 3) * 6)][0], rate: (3 + 7 * hash(slot + 7)) * Math.sin(Math.PI * f) ** 2 }
}
// events a second at a time (a base that never stops, slow swells, the wave)
function base(ms) { const t = ms / 1000; return 1.6 + 0.8 * Math.sin(t / 97) + 0.5 * Math.sin(t / 23 + 1) }
function rate(ms) { const w = wave(ms); return base(ms) + (w ? w.rate : 0) }

export function createDemo(destination) {
  let id = 900000000
  let last = Date.now()
  // the events already shown, newest last: a new snapshot lists these again (same ids), so the latest-events list
  // only ever gets new ones pushed in at the top -- never a whole new set every minute
  let recent = []
  const remember = (list) => { recent = recent.concat(list).slice(-80) }

  function event(ms, cc0) {
    const internal = Math.random() < INTERNAL
    const host = pickW(HOSTS, Math.random())
    const cc = internal ? 'LAN' : (Math.random() < UNLOCATED ? '?' : cc0 || pickW(COUNTRIES, Math.random()))
    const blocked = Math.random() < (internal ? BLOCKED_IN : BLOCKED_OUT)
    return { id: ++id, ts: iso(ms), cc, origin: internal ? 'internal' : 'external', host,
             outcome: blocked ? 'blocked' : 'logged', decided_by: blocked ? pickW(DECISIONS, Math.random()) : '' }
  }

  function events() {
    const now = Date.now()
    const span = Math.max(0, Math.min(60000, now - last))
    const mid = now - span / 2
    const want = rate(mid) * span / 1000
    const n = Math.max(0, Math.min(500, Math.round(want + (Math.random() - 0.5) * 2 * Math.sqrt(want))))
    const w = wave(mid)
    const share = w ? w.rate / rate(mid) : 0
    const times = Array.from({ length: n }, () => now - Math.random() * span).sort((a, b) => a - b)
    const out = times.map((ms) => event(ms, Math.random() < share ? w.cc : null))
    remember(out)
    last = now
    return { now: iso(now), after: 0, high_water_id: id, more: false, collector: { stopped: false }, events: out }
  }

  function snapshot(rng, seconds, only) {
    const now = Date.now()
    const W = seconds * 1000, step = W / 30, cell = W / 15
    const since = now - W
    const first = Math.floor(since / step)
    const totals = { events: 0, blocked: 0, logged: 0, external: 0, internal: 0, unlocated: 0 }
    const countries = {}, flow = { external: {}, internal: {} }, sites = {}, score = {}, decided = {}
    const minutes = []
    const add = (o, k, n) => { o[k] = (o[k] || 0) + n }
    const wOut = sum(COUNTRIES), wHost = sum(HOSTS), wDec = sum(DECISIONS)
    for (let i = 0; i <= 30; i++) {
      const t0 = (first + i) * step, mid = t0 + step / 2
      const n = Math.round(rate(mid) * step / 1000 * (0.85 + 0.3 * Math.random()))
      const w = wave(mid)
      const share = w ? w.rate / rate(mid) : 0
      const nIn = Math.round(n * INTERNAL), nOut = n - nIn
      const bOut = Math.round(nOut * BLOCKED_OUT), bIn = Math.round(nIn * BLOCKED_IN)
      minutes.push({ t: iso(t0), blocked: bOut + bIn, logged: n - bOut - bIn })
      totals.events += n; totals.blocked += bOut + bIn; totals.logged += n - bOut - bIn
      totals.external += nOut; totals.internal += nIn
      const nUn = Math.round(nOut * UNLOCATED)
      totals.unlocated += nUn
      // the outside events by country (the wave's country takes its share first), blocked and logged alike
      for (const [cc, wt] of COUNTRIES) {
        const k = (nOut - nUn) * ((1 - share) * wt / wOut + (w && w.cc === cc ? share : 0))
        if (k < 0.5) continue
        const c = countries[cc] || (countries[cc] = { cc, events: 0, blocked: 0, logged: 0 })
        const e = Math.round(k), b = Math.round(e * BLOCKED_OUT)
        c.events += e; c.blocked += b; c.logged += e - b
      }
      for (const [d, wt] of DECISIONS) {
        add(flow.external, d, Math.round(bOut * wt / wDec)); add(flow.internal, d, Math.round(bIn * wt / wDec))
        add(decided, d, Math.round((bOut + bIn) * wt / wDec))
      }
      add(flow.external, 'logged', nOut - bOut); add(flow.internal, 'logged', nIn - bIn)
      const ci = Math.min(14, Math.max(0, Math.floor((mid - since) / cell)))
      for (const [h, wt] of HOSTS) {
        const e = Math.round(n * wt / wHost)
        if (!e) continue
        const s = sites[h] || (sites[h] = { host: h, events: 0, blocked: 0, logged: 0, buckets: new Array(15).fill(0) })
        const b = Math.round(e * BLOCKED_OUT)
        s.events += e; s.blocked += b; s.logged += e - b; s.buckets[ci] += e
        add(score, h, Math.round(b * 28 / wDec))
      }
    }
    for (const c of Object.values(countries)) c.sources = Math.max(1, Math.round(c.events ** 0.6))
    const blockedOnly = only === 'blocked'
    if (blockedOnly) {
      // the blocked events alone: every count keeps its blocked part
      totals.events = totals.blocked; totals.logged = 0
      totals.internal = Math.round(totals.internal * BLOCKED_IN)
      totals.external = totals.blocked - totals.internal
      totals.unlocated = Math.round(totals.unlocated * BLOCKED_OUT)
      for (const c of Object.values(countries)) { c.events = c.blocked; c.logged = 0 }
      for (const m of minutes) m.logged = 0
      for (const s of Object.values(sites)) {
        const k = s.events ? s.blocked / s.events : 0
        s.buckets = s.buckets.map((n) => Math.round(n * k)); s.events = s.blocked; s.logged = 0
      }
      delete flow.external.logged; delete flow.internal.logged
    }
    const list = Object.values(countries).filter((c) => c.events > 0).sort((a, b) => b.events - a.events)
    if (!recent.length) remember(Array.from({ length: 60 }, (_, k) => event(now - (60 - k) * 1700, null)))
    const latest = recent.filter((e) => !blockedOnly || e.outcome === 'blocked').slice(-30).reverse()
    return {
      now: iso(now), window_start: iso(since), window_end: iso(now), window_seconds: seconds, range: rng,
      only: blockedOnly ? 'blocked' : '', step_seconds: Math.round(step / 1000), cell_seconds: Math.round(cell / 1000), node_id: 'demo', high_water_id: id,
      collector: { stopped: false }, totals: { ...totals, countries: list.length }, decided_by: decided, countries: list,
      minutes, latest, destination: destination() || { label: '', lat: 25.03, lon: 121.56 }, flow,
      score_only: Object.entries(score).map(([host, events]) => ({ host, events })).sort((a, b) => b.events - a.events),
      sites: Object.values(sites).sort((a, b) => b.events - a.events), watched: [], rotate_seconds: 25, demo: true,
    }
  }

  function ops() {
    const now = Date.now()
    const ago = (m) => iso(now - m * 60000)
    const chg = (n, op, kind, direction, state, m, by) => ({ id: n, op, kind, direction, state, updated_at: ago(m), by })
    return {
      now: iso(now),
      analysis: { latest: { id: 9128, started_at: ago(6), finished_at: ago(5), seconds: 47, candidates: 37, proposals: 3,
                            verdicts: { attack: 18, attack_probe: 11, false_positive: 3, legitimate: 2, unsure: 2, invalid: 1 },
                            events_scanned: 4821, error: false, window_hours: 168 },
                  runs_24h: 48, errors_24h: 0, enabled: true },
      intel: { enabled: true, last_run_at: ago(52), open: 6, affected: 2, unknown: 3, exploited: 1, patched_by_rule: 1,
               software_confirmed: 14, software_unconfirmed: 2,
               top: [{ id: 'DEMO-0001', product: 'nginx', severity: 'high', affected: 'yes', exploited: true },
                     { id: 'DEMO-0002', product: 'openssl', severity: 'medium', affected: 'unknown', exploited: false },
                     { id: 'DEMO-0003', product: 'php', severity: 'medium', affected: 'yes', exploited: false }] },
      alerts: [{ id: 9901, kind: 'attack_in_progress', severity: 'warning', created_at: ago(3) },
               { id: 9900, kind: 'traffic_spike', severity: 'warning', created_at: ago(14) },
               { id: 9899, kind: 'false_positive', severity: 'info', created_at: ago(41) }],
      changes: { checking: [chg(9055, 'add', 'confident_block', 'tighten', 'checking', 2, 'analyst')],
                 pending: [chg(9054, 'add', 'exclusion', 'loosen', 'pending_approval', 18, 'analyst'),
                           chg(9053, 'add', 'confident_block', 'tighten', 'pending_approval', 35, 'intel')],
                 applied: [chg(9052, 'add', 'confident_block', 'tighten', 'applied', 64, 'analyst'),
                           chg(9051, 'modify', 'country', 'tighten', 'applied', 190, 'person')] },
    }
  }

  return { snapshot, events, ops }
}
