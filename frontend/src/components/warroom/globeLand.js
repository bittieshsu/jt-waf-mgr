// Land of the globe, from the same outline as the flat maps (worldLand.js): the outline is filled once on a small
// off-screen canvas (Path2D, no inline data), sampled every 1.5 degrees for the dotted land, and its rings are kept
// as coast lines. Done once per page and shared by every globe; the result is unit vectors, flat arrays for speed.
import { vec } from './warColors.js'

let pending = null

export function globeLand() {
  if (!pending) {
    pending = import('../charts/worldLand.js')
      .then((m) => build(m.default))
      .catch(() => { pending = null; return { dots: new Float32Array(0), coasts: [] } })
  }
  return pending
}

function build(land) {
  // 2 pixels per degree; the outline's coordinates are x = lon + 180, y = 90 - lat
  const canvas = document.createElement('canvas')
  canvas.width = 720
  canvas.height = 360
  const ctx = canvas.getContext('2d', { willReadFrequently: true })
  ctx.scale(2, 2)
  ctx.fill(new Path2D(land))
  const px = ctx.getImageData(0, 0, 720, 360).data
  const dots = []
  for (let lat = -74; lat < 85; lat += 1.5) {
    // fewer samples towards the poles, so the dots keep about the same spacing on the sphere
    const dx = 1.5 / Math.max(0.25, Math.cos(lat * Math.PI / 180))
    for (let lon = -180; lon < 180; lon += dx) {
      const i = (Math.floor((90 - lat) * 2) * 720 + Math.floor((lon + 180) * 2)) * 4
      if (px[i + 3] > 150) dots.push(...vec(lat, lon))
    }
  }
  // coast lines: one ring per "M ... Z" of the outline; tiny islands (8 points or fewer) are left to the dots
  const coasts = []
  for (const ring of land.match(/M[^Z]+/g) || []) {
    const xy = [...ring.matchAll(/(-?[\d.]+),(-?[\d.]+)/g)]
    if (xy.length <= 8) continue
    const v = new Float32Array(xy.length * 3)
    xy.forEach((m, k) => { v.set(vec(90 - Number(m[2]), Number(m[1]) - 180), k * 3) })
    coasts.push(v)
  }
  return { dots: new Float32Array(dots), coasts }
}
