// Runs the GLiNER2 PII model off the main thread. The model files are fetched
// once from Hugging Face and kept in the browser's Cache Storage; the text you
// redact is only ever passed to this worker, never sent over the network.
import * as ort from './vendor/ort.wasm.min.mjs'
import { Tokenizer } from './vendor/tokenizers.min.mjs'
import { Gliner2 } from './gliner2.js'

const REPO = 'https://huggingface.co/okasi/gliner2-privacy-filter-pii-multi-onnx/resolve/main/'
const FILES = ['tokenizer.json', 'tokenizer_config.json', 'model_q4.onnx', 'model_q4.onnx.data']
const CACHE = 'gliner2-pii-q4-v1'

ort.env.logLevel = 'error'
ort.env.wasm.wasmPaths = new URL('./vendor/', import.meta.url).href
ort.env.wasm.numThreads = self.crossOriginIsolated ? Math.min(4, Math.max(1, (navigator.hardwareConcurrency || 2) - 1)) : 1

let model = null
let loading = null

async function openCache() {
  try { return await caches.open(CACHE) } catch { return null }
}

// Browsers refuse very large single cache entries, so files are stored in pieces.
const PART = 64 * 1048576
async function cacheGet(c, url) {
  const meta = await c.match(url + '?parts')
  if (!meta) return null
  const n = +(await meta.text())
  const parts = []
  for (let i = 0; i < n; i++) {
    const r = await c.match(url + '?part=' + i)
    if (!r) return null
    parts.push(new Uint8Array(await r.arrayBuffer()))
  }
  const buf = new Uint8Array(parts.reduce((a, b) => a + b.length, 0))
  let o = 0
  for (const x of parts) { buf.set(x, o); o += x.length }
  return buf
}
async function cachePut(c, url, buf) {
  const n = Math.max(1, Math.ceil(buf.length / PART))
  for (let i = 0; i < n; i++) await c.put(url + '?part=' + i, new Response(buf.subarray(i * PART, (i + 1) * PART)))
  await c.put(url + '?parts', new Response(String(n))) // written last: marks the file complete
}

async function isCached() {
  const c = await openCache()
  if (!c) return false
  for (const f of FILES) if (!(await c.match(REPO + f + '?parts'))) return false
  return true
}

async function fetchAll(post) {
  const cache = await openCache()
  const out = {}
  const sizes = {}, got = {}
  const report = () => {
    const total = Object.values(sizes).reduce((a, b) => a + b, 0)
    const done = Object.values(got).reduce((a, b) => a + b, 0)
    post({ type: 'status', state: 'downloading', done, total })
  }
  await Promise.all(FILES.map(async (f) => {
    const url = REPO + f
    const hit = cache && (await cacheGet(cache, url))
    if (hit) { out[f] = hit; sizes[f] = got[f] = hit.length; report(); return }
    const res = await fetch(url)
    if (!res.ok) throw new Error(`Download failed (${res.status}) for ${f}`)
    sizes[f] = +res.headers.get('content-length') || 0
    const reader = res.body.getReader()
    const chunks = []
    got[f] = 0
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      chunks.push(value); got[f] += value.length
      if (chunks.length % 40 === 0) report()
    }
    const buf = new Uint8Array(got[f])
    let o = 0
    for (const c of chunks) { buf.set(c, o); o += c.length }
    out[f] = buf
    report()
    if (cache) { try { await cachePut(cache, url, buf) } catch { /* storage full: still works this session */ } }
  }))
  return out
}

async function load(post, onlyIfCached) {
  if (model) return model
  if (onlyIfCached && !(await isCached())) { post({ type: 'status', state: 'off' }); return null }
  loading ??= (async () => {
    const files = await fetchAll(post)
    post({ type: 'status', state: 'loading' })
    const dec = new TextDecoder()
    const tok = new Tokenizer(JSON.parse(dec.decode(files['tokenizer.json'])), JSON.parse(dec.decode(files['tokenizer_config.json'])))
    const session = await ort.InferenceSession.create(files['model_q4.onnx'], {
      executionProviders: ['wasm'],
      logSeverityLevel: 3,
      externalData: [{ path: 'model_q4.onnx.data', data: files['model_q4.onnx.data'] }],
    })
    model = new Gliner2(tok, session, ort)
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
    if (data.type === 'load') await load(post, data.onlyIfCached)
    else if (data.type === 'forget') { await caches.delete(CACHE); post({ type: 'forgot' }) }
    else if (data.type === 'predict') {
      const m = await load(post)
      const t0 = performance.now()
      const ents = await m.predict(data.text, { threshold: data.threshold ?? 0.5, onProgress: (p) => post({ type: 'progress', id: data.id, p }) })
      post({ type: 'result', id: data.id, ents, ms: Math.round(performance.now() - t0) })
    }
  } catch (e) {
    post({ type: 'error', id: data.id, message: String(e?.message || e) })
  }
}
