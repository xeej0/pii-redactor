// Runs the GLiNER2 PII model off the main thread. The model (~142 MB) is served by this
// site, downloaded once and kept in the browser's Cache Storage. The text you redact is
// only ever passed to this worker, never sent over the network.
import * as ort from './vendor/ort.wasm.min.mjs'
import { Tokenizer } from './vendor/tokenizers.min.mjs'
import { Gliner2 } from './gliner2.js'

const BASE = new URL('./model/g2pii-v1/', import.meta.url).href
const CACHE = 'gliner2-pii-v2'
const OLD_CACHES = ['gliner2-pii-q4-v1'] // earlier 470 MB model: removed to free space

ort.env.logLevel = 'error'
ort.env.wasm.wasmPaths = new URL('./vendor/', import.meta.url).href
ort.env.wasm.numThreads = self.crossOriginIsolated ? Math.min(4, Math.max(1, (navigator.hardwareConcurrency || 2) - 1)) : 1

let model = null
let loading = null

async function openCache() {
  try { return await caches.open(CACHE) } catch { return null }
}
async function cleanup() {
  for (const c of OLD_CACHES) { try { await caches.delete(c) } catch { /* ignore */ } }
}

async function getManifest(cache) {
  const url = BASE + 'manifest.json'
  const hit = cache && (await cache.match(url))
  if (hit) return hit.json()
  const res = await fetch(url, { cache: 'no-store' })
  if (!res.ok) throw new Error('Could not get the model manifest (' + res.status + ')')
  return res.json()
}

async function isCached() {
  const c = await openCache()
  if (!c) return false
  const m = await c.match(BASE + 'manifest.json')
  if (!m) return false
  const { parts } = await m.json()
  for (const f of ['tokenizer.json', 'tokenizer_config.json', ...parts]) if (!(await c.match(BASE + f))) return false
  return true
}

// fetch() and body reads reject with a bare "network error" when the connection drops
const INTERRUPTED = 'Download interrupted. Check your connection and press Download AI model to retry.'
const net = (p) => p.catch(() => { throw new Error(INTERRUPTED) })

async function download(post) {
  const cache = await openCache()
  const manifest = await getManifest(cache)
  const files = ['tokenizer.json', 'tokenizer_config.json', ...manifest.parts]
  const got = {}
  let total = manifest.bytes + 4.5e6
  const report = () => post({ type: 'status', state: 'downloading', done: Object.values(got).reduce((a, b) => a + b, 0), total })
  const out = {}
  // up to 3 files at a time
  const queue = [...files]
  await Promise.all([0, 1, 2].map(async () => {
    for (let f; (f = queue.shift());) {
      const url = BASE + f
      const hit = cache && (await cache.match(url))
      if (hit) { out[f] = new Uint8Array(await hit.arrayBuffer()); got[f] = out[f].length; report(); continue }
      const res = await net(fetch(url))
      if (!res.ok) throw new Error(`Download failed (${res.status}) for ${f}`)
      const reader = res.body.getReader()
      const chunks = []
      got[f] = 0
      for (;;) {
        const { done, value } = await net(reader.read())
        if (done) break
        chunks.push(value); got[f] += value.length
        if (chunks.length % 30 === 0) report()
      }
      const buf = new Uint8Array(got[f])
      let o = 0
      for (const c of chunks) { buf.set(c, o); o += c.length }
      out[f] = buf
      report()
      if (cache) { try { await cache.put(url, new Response(buf)) } catch { /* storage full: still works this session */ } }
    }
  }))
  const model = new Uint8Array(manifest.bytes)
  let o = 0
  for (const p of manifest.parts) { model.set(out[p], o); o += out[p].length }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', model))
  const hex = [...digest].map((b) => b.toString(16).padStart(2, '0')).join('')
  if (hex !== manifest.sha256) {
    if (cache) await caches.delete(CACHE)
    throw new Error('The downloaded model was damaged. Please try again.')
  }
  if (cache) { try { await cache.put(BASE + 'manifest.json', new Response(JSON.stringify(manifest))) } catch { /* ignore */ } }
  return { model, tokenizer: out['tokenizer.json'], config: out['tokenizer_config.json'] }
}

async function load(post, onlyIfCached, labels) {
  if (model) return model
  cleanup()
  if (onlyIfCached && !(await isCached())) { post({ type: 'status', state: 'off' }); return null }
  loading ??= (async () => {
    const files = await download(post)
    post({ type: 'status', state: 'loading' })
    const dec = new TextDecoder()
    const tok = new Tokenizer(JSON.parse(dec.decode(files.tokenizer)), JSON.parse(dec.decode(files.config)))
    const session = await ort.InferenceSession.create(files.model, { executionProviders: ['wasm'], logSeverityLevel: 3 })
    model = new Gliner2(tok, session, ort, labels || ['person'])
    post({ type: 'status', state: 'ready', threads: ort.env.wasm.numThreads })
    return model
  })()
  try { return await loading } catch (e) { loading = null; throw e }
}

// One job at a time; a scan request is skipped if a newer one is already queued.
let chain = Promise.resolve()
let newest = 0
self.onmessage = ({ data }) => {
  if (data.type === 'predict') newest = Math.max(newest, data.id)
  chain = chain.then(() => handle(data))
}

async function handle(data) {
  const post = (m) => self.postMessage(m)
  if (data.type === 'predict' && data.id < newest) return
  try {
    if (data.type === 'load') await load(post, data.onlyIfCached, data.labels)
    else if (data.type === 'forget') { await caches.delete(CACHE); await cleanup(); post({ type: 'forgot' }) }
    else if (data.type === 'predict') {
      const m = await load(post, false, data.labels)
      if (m.labels.join('\n') !== data.labels.join('\n')) m.setLabels(data.labels)
      const t0 = performance.now()
      const ents = await m.predict(data.text, { threshold: data.threshold ?? 0.5, onProgress: (p) => post({ type: 'progress', id: data.id, p }) })
      post({ type: 'result', id: data.id, ents, ms: Math.round(performance.now() - t0) })
    }
  } catch (e) {
    post({ type: 'error', id: data.id, message: String(e?.message || e) })
  }
}
