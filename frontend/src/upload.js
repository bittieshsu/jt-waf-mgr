// Upload a file in pieces (the web service and the nginx in front of it take requests of up to 1 MB): announce the
// name, size and SHA-256, send each piece, then finish -- the server puts the file together and checks it.
import { post } from './api.js'

function b64(buf) {
  const bytes = new Uint8Array(buf)
  let s = ''
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000))
  return btoa(s)
}

async function sha256hex(file) {
  const buf = await file.arrayBuffer()
  const h = await crypto.subtle.digest('SHA-256', buf)
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join('')
}

// kind: 'hub' or 'crs'; finishBody: extra fields for the last call (the CRS signature); onProgress(sent, total)
export async function uploadInParts(kind, file, finishBody = {}, onProgress = () => {}) {
  const sha256 = await sha256hex(file)
  const s = await post('/uploads', { kind, name: file.name, size: file.size, sha256 })
  for (let i = 0, off = 0; off < file.size; i++, off += s.chunk_bytes) {
    const part = await file.slice(off, Math.min(file.size, off + s.chunk_bytes)).arrayBuffer()
    await post('/uploads/' + s.id + '/chunk', { index: i, data: b64(part) })
    onProgress(Math.min(file.size, off + s.chunk_bytes), file.size)
  }
  return post('/uploads/' + s.id + '/finish', finishBody)
}
