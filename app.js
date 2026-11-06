import { analyze as presidio } from './presidio.js'

const $ = (id) => document.getElementById(id)

// ---------- categories ----------
const CATS = [
  { id: 'name', name: 'Names', label: 'NAME' },
  { id: 'email', name: 'Emails', label: 'EMAIL' },
  { id: 'phone', name: 'Phones', label: 'PHONE' },
  { id: 'address', name: 'Addresses', label: 'ADDRESS' },
  { id: 'zip', name: 'ZIP / postcodes', label: 'POSTCODE' },
  { id: 'card', name: 'Card numbers', label: 'CARD' },
  { id: 'iban', name: 'IBANs', label: 'IBAN' },
  { id: 'ssn', name: 'SSNs', label: 'SSN' },
  { id: 'ids', name: 'Other IDs & accounts', label: 'ID' },
  { id: 'username', name: 'Usernames', label: 'USERNAME' },
  { id: 'ip', name: 'IP / MAC addresses', label: 'IP' },
  { id: 'date', name: 'Dates', label: 'DATE' },
  { id: 'url', name: 'URLs', label: 'URL', off: true },
  { id: 'secret', name: 'API keys / tokens', label: 'SECRET' },
  { id: 'custom', name: 'Your list', label: 'TERM' },
]
const CAT = Object.fromEntries(CATS.map((c) => [c.id, c]))
const SOURCE_NAME = { patterns: 'Patterns', presidio: 'Presidio', gliner: 'GLiNER2', custom: 'Your list' }

// ---------- engine 1: built-in patterns ----------
function luhn(d) {
  let sum = 0, alt = false
  for (let i = d.length - 1; i >= 0; i--) { let n = +d[i]; if (alt) { n *= 2; if (n > 9) n -= 9 } sum += n; alt = !alt }
  return sum % 10 === 0
}
function ibanOk(s) {
  const t = s.replace(/\s+/g, '').toUpperCase()
  if (t.length < 15 || t.length > 34) return false
  const r = (t.slice(4) + t.slice(0, 4)).replace(/[A-Z]/g, (c) => c.charCodeAt(0) - 55)
  let m = 0
  for (const ch of r) m = (m * 10 + +ch) % 97
  return m === 1
}
const MONTHS = 'Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?'
const STREET = 'Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Way|Terrace|Ter|Parkway|Pkwy|Highway|Hwy|Circle|Cir|Square|Sq'
const PATTERNS = [
  { cat: 'email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { cat: 'url', re: /\bhttps?:\/\/[^\s<>"')\]]+/g },
  { cat: 'card', re: /\b(?:\d[ -]?){12,18}\d\b/g, ok: (m) => { const d = m.replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && luhn(d) } },
  { cat: 'iban', re: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g, ok: ibanOk },
  { cat: 'ssn', re: /\b(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b/g },
  { cat: 'phone', re: /(?:(?<![\w+])\+\d{1,3}[\s.-]?)?(?<![\w+])(?:\(\d{2,4}\)|\d{2,4})[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?:\s?(?:x|ext\.?)\s?\d{1,5})?\b/g,
    ok: (m) => { const d = m.replace(/\D/g, ''); return d.length >= 10 && d.length <= 15 && !/^\d{4}-\d{2}-\d{2}$/.test(m.trim()) } },
  { cat: 'ip', re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?\b/g },
  { cat: 'date', re: new RegExp(String.raw`\b(?:\d{1,2}[/.-]\d{1,2}[/.-](?:\d{4}|\d{2})|\d{4}-\d{2}-\d{2}|(?:${MONTHS})\.? \d{1,2}(?:st|nd|rd|th)?,? \d{4}|\d{1,2}(?:st|nd|rd|th)? (?:${MONTHS})\.?,? \d{4})\b`, 'gi') },
  { cat: 'address', keepTrail: true, re: new RegExp(String.raw`\b\d{1,6}(?:-\d{1,4})? (?:[NSEW]\.? )?(?:[A-Z0-9][\w'.-]*\s){0,4}(?:${STREET})\b\.?(?:,?\s(?:Apt|Apartment|Suite|Ste|Unit|Fl|Floor|#)\.?\s?[\w-]+)?`, 'g') },
  { cat: 'zip', re: /\b[A-Z]{2}\s\d{5}(?:-\d{4})?\b|\b[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2}\b/g },
  { cat: 'name', re: /\b(?:(?:Mr|Mrs|Ms|Mx|Miss|Dr|Prof|Sir|Madam)\.?\s+(?:[A-Z][a-zA-Z'-]+)(?:\s+[A-Z][a-zA-Z'-]+){0,2}|(?<=\b(?:[Nn]ame|[Pp]atient|[Cc]lient|[Cc]ustomer|[Ee]mployee|[Cc]ontact|[Ff]rom|[Tt]o|[Dd]ear|[Ss]igned|[Rr]egards,?)\s*[:,]?\s+)[A-Z][a-zA-Z'-]+(?:\s+[A-Z]\.)?(?:\s+[A-Z][a-zA-Z'-]+){1,2})/g },
  { cat: 'secret', re: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bxox[abpr]-[A-Za-z0-9-]{10,}\b|\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b|\bsk-[A-Za-z0-9_-]{20,}\b/g },
]
function runPatterns(text) {
  const out = []
  for (const p of PATTERNS) {
    p.re.lastIndex = 0
    for (const m of text.matchAll(p.re)) {
      let s = m[0]
      if (!p.keepTrail) s = s.replace(/[\s.,;:]+$/, '')
      if (!s || (p.ok && !p.ok(s))) continue
      out.push({ start: m.index, end: m.index + s.length, cat: p.cat, source: 'patterns', score: 0.9 })
    }
  }
  return out
}

// ---------- engine 2: Presidio ----------
const PRESIDIO_CAT = { EMAIL_ADDRESS: 'email', URL: 'url', CREDIT_CARD: 'card', IBAN_CODE: 'iban', US_SSN: 'ssn', IP_ADDRESS: 'ip', MAC_ADDRESS: 'ip', DATE_TIME: 'date', UK_POSTCODE: 'zip', CA_POSTAL_CODE: 'zip' }
function runPresidio(text) {
  return presidio(text).map((r) => {
    const cat = PRESIDIO_CAT[r.entity] || 'ids'
    return { start: r.start, end: r.end, cat, source: 'presidio', score: r.score, label: cat === 'ids' ? r.entity : undefined, detail: r.entity }
  })
}

// ---------- engine 3: GLiNER2 (in a worker) ----------
const GLINER_CAT = { name: 'name', address: 'address', email: 'email', phone_num: 'phone', id_num: 'ids', url: 'url', username: 'username' }
const gl = { worker: null, state: 'off', hits: null, forText: null, reqId: 0, timer: 0, ms: 0 }

function glStatus(html, cls = '', pct = null) {
  const s = $('g-status')
  s.className = 'st ' + cls
  s.innerHTML = html
  $('g-bar').hidden = pct === null
  if (pct !== null) $('g-bar').firstElementChild.style.width = Math.round(pct * 100) + '%'
}
function glRender() {
  const on = state.engines.gliner
  const mb = (n) => Math.round(n / 1048576)
  switch (gl.state) {
    case 'downloading': return glStatus(`Downloading model… ${mb(gl.done)} / ${gl.total ? mb(gl.total) : '~470'} MB`, '', gl.total ? gl.done / gl.total : 0)
    case 'loading': return glStatus('Starting model…', '', 1)
    case 'scanning': return glStatus('Scanning…', '', gl.progress ?? 0)
    case 'ready': return glStatus(on ? `<span class="ok">Ready</span>${gl.ms ? ` · last scan ${(gl.ms / 1000).toFixed(1)} s` : ''}` : 'Off (model downloaded)', '')
    case 'error': return glStatus(gl.error, 'warn')
    default: return glStatus(on ? 'Waiting…' : 'Off · ~470 MB download when turned on', '')
  }
}
function glWorker() {
  if (gl.worker) return gl.worker
  const w = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' })
  w.onmessage = ({ data: m }) => {
    if (m.type === 'status') {
      if (m.state === 'off') { state.engines.gliner = false; $('e-gliner').checked = false; save(); gl.state = 'off' }
      else Object.assign(gl, { state: m.state, done: m.done, total: m.total })
      if (m.state === 'ready') { $('forget').hidden = false; scheduleScan(0) }
    } else if (m.type === 'progress' && m.id === gl.reqId) { gl.progress = m.p }
    else if (m.type === 'result' && m.id === gl.reqId) {
      gl.state = 'ready'; gl.ms = m.ms; gl.forText = gl.pending
      gl.hits = m.ents.map((e) => ({ start: e.start, end: e.end, cat: GLINER_CAT[e.label] || 'ids', source: 'gliner', score: e.score, detail: e.label }))
      run()
    } else if (m.type === 'error') { gl.state = 'error'; gl.error = 'Error: ' + m.message }
    else if (m.type === 'forgot') { toast('Model removed from this browser') }
    glRender()
  }
  w.onerror = (e) => { gl.state = 'error'; gl.error = 'Error: ' + (e.message || 'could not start the model'); glRender() }
  return (gl.worker = w)
}
function scheduleScan(delay = 600) {
  clearTimeout(gl.timer)
  if (!state.engines.gliner || !['ready', 'scanning'].includes(gl.state)) return
  const text = $('input').value
  if (!text.trim() || text === gl.forText) return
  gl.timer = setTimeout(() => {
    gl.reqId++; gl.pending = text; gl.state = 'scanning'; gl.progress = 0
    gl.worker.postMessage({ type: 'predict', id: gl.reqId, text })
    glRender()
  }, delay)
}

// ---------- merge + redact ----------
const state = { on: {}, mode: 'label', engines: { patterns: true, presidio: true, gliner: false } }
try { const s = JSON.parse(localStorage.getItem('pii-opts') || '{}'); Object.assign(state, s, { engines: { ...state.engines, ...s.engines } }) } catch {}
for (const c of CATS) if (!(c.id in state.on)) state.on[c.id] = !c.off

const splitList = (s) => s.split(/[,\n]/).map((x) => x.trim()).filter(Boolean)
const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const escHtml = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c])

function collect(text) {
  const hits = []
  const custom = splitList($('custom').value).sort((a, b) => b.length - a.length)
  if (custom.length) {
    const re = new RegExp('(?<![\\w])(?:' + custom.map(escRe).join('|') + ')(?![\\w])', 'gi')
    for (const m of text.matchAll(re)) hits.push({ start: m.index, end: m.index + m[0].length, cat: 'custom', source: 'custom', score: 2, tier: 0 })
  }
  if (state.engines.patterns) hits.push(...runPatterns(text).map((h) => ({ ...h, tier: 1 })))
  if (state.engines.presidio) hits.push(...runPresidio(text).map((h) => ({ ...h, tier: 1 })))
  if (state.engines.gliner && gl.hits && gl.forText === text) hits.push(...gl.hits.map((h) => ({ ...h, tier: 2 })))
  const allow = new Set(splitList($('allow').value).map((s) => s.toLowerCase()))
  return hits.filter((h) => state.on[h.cat] && !allow.has(text.slice(h.start, h.end).toLowerCase()))
}

// Overlaps: your list first, then rules (higher score, then longer), then the AI model.
// A later match of the same type that overlaps is merged into the span and credited.
function merge(hits) {
  hits.sort((a, b) => a.tier - b.tier || b.score - a.score || (b.end - b.start) - (a.end - a.start))
  const acc = []
  for (const h of hits) {
    const ov = acc.filter((a) => h.start < a.end && h.end > a.start)
    if (!ov.length) { acc.push({ ...h, sources: new Set([h.source]) }); continue }
    for (const a of ov) if (a.cat === h.cat) a.sources.add(h.source)
    if (ov.length === 1 && ov[0].cat === h.cat) {
      const a = ov[0], s = Math.min(a.start, h.start), e = Math.max(a.end, h.end)
      if (!acc.some((o) => o !== a && s < o.end && e > o.start)) { a.start = s; a.end = e }
    }
  }
  return acc.sort((a, b) => a.start - b.start)
}

function replacement(h, text, ids) {
  const orig = text.slice(h.start, h.end)
  switch (state.mode) {
    case 'block': return '█'.repeat(Math.min(Math.max(orig.length, 4), 24))
    case 'generic': return '[REDACTED]'
    case 'mask': {
      const keepN = ['card', 'phone', 'ssn', 'iban', 'ids'].includes(h.cat) ? 4 : 0
      let seen = 0
      const chars = [...orig]
      for (let i = chars.length - 1; i >= 0; i--) if (/[\p{L}\p{N}]/u.test(chars[i])) chars[i] = seen++ < keepN ? chars[i] : '*'
      return chars.join('')
    }
    default: {
      const label = h.label || CAT[h.cat].label
      const key = label + '\u0000' + orig.toLowerCase().replace(/\s+/g, ' ')
      if (!ids.map.has(key)) { ids.n[label] = (ids.n[label] || 0) + 1; ids.map.set(key, `[${label}_${ids.n[label]}]`) }
      return ids.map.get(key)
    }
  }
}

let last = { plain: '', rows: [] }
function run() {
  const text = $('input').value
  const hits = merge(collect(text))
  const ids = { n: {}, map: new Map() }
  const counts = {}
  let plain = '', html = '', pos = 0
  const rows = [], seen = new Set()
  for (const h of hits) {
    const orig = text.slice(h.start, h.end)
    const rep = replacement(h, text, ids)
    const src = [...h.sources]
    const cls = src.includes('patterns') || src.includes('custom') ? '' : src.includes('presidio') ? 's-presidio' : 's-gliner'
    plain += text.slice(pos, h.start) + rep
    html += escHtml(text.slice(pos, h.start)) + `<mark class="${cls}" title="${escHtml(CAT[h.cat].name + ' · ' + src.map((s) => SOURCE_NAME[s]).join(', '))}">${escHtml(rep)}</mark>`
    pos = h.end
    counts[h.cat] = (counts[h.cat] || 0) + 1
    const rk = rep + '\u0000' + orig
    if (!seen.has(rk)) {
      seen.add(rk)
      const by = src.map((s) => SOURCE_NAME[s]).join(', ')
      rows.push([rep, h.detail && h.cat === 'ids' ? h.detail.replace(/_/g, ' ') : CAT[h.cat].name, orig, by])
    }
  }
  plain += text.slice(pos); html += escHtml(text.slice(pos))
  last = { plain, rows }
  const out = $('output')
  if (!text) out.innerHTML = '<span class="muted">The redacted text will appear here.</span>'
  else if ($('hl').checked) out.innerHTML = html
  else out.textContent = plain
  for (const c of CATS) { const el = document.querySelector(`[data-n="${c.id}"]`); if (el) el.textContent = counts[c.id] || '' }
  const waiting = state.engines.gliner && text.trim() && gl.forText !== text && ['ready', 'scanning'].includes(gl.state)
  $('total').textContent = text ? `${hits.length} redaction${hits.length === 1 ? '' : 's'}${waiting ? ' (AI still scanning)' : ''}` : ''
  $('inCount').textContent = text ? `${text.length.toLocaleString()} chars` : ''
  $('mapCount').textContent = rows.length ? `(${rows.length})` : ''
  $('map').innerHTML = rows.map((r) => `<tr><td><code>${escHtml(r[0])}</code></td><td>${escHtml(r[1])}</td><td><code>${escHtml(r[2])}</code></td><td>${escHtml(r[3])}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">Nothing found yet.</td></tr>'
}

let runTimer = 0
function onInput() {
  clearTimeout(runTimer)
  const big = $('input').value.length > 40000
  runTimer = setTimeout(run, big ? 250 : 0)
  scheduleScan()
}

// ---------- UI wiring ----------
function save() { try { localStorage.setItem('pii-opts', JSON.stringify({ on: state.on, mode: state.mode, engines: state.engines })) } catch {} }
function toast(msg) { const t = $('toast'); t.textContent = msg; t.classList.add('on'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('on'), 1800) }
function download(name, content, type) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([content], { type }))
  a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000)
}
function readFile(f) {
  if (!f) return
  if (f.size > 5e6) return toast('File is larger than 5 MB')
  f.text().then((t) => { $('input').value = t; onInput() })
}

$('cats').innerHTML = CATS.map((c) => `<label class="chip"><input type="checkbox" data-id="${c.id}" ${state.on[c.id] ? 'checked' : ''}>${c.name} <span class="n" data-n="${c.id}"></span></label>`).join('')
$('cats').addEventListener('change', (e) => { state.on[e.target.dataset.id] = e.target.checked; save(); run() })
for (const k of ['patterns', 'presidio', 'gliner']) {
  const el = $('e-' + k)
  el.checked = state.engines[k]
  el.addEventListener('change', () => {
    state.engines[k] = el.checked
    save()
    if (k === 'gliner' && el.checked) {
      if (gl.state === 'off' || gl.state === 'error') { gl.state = 'downloading'; gl.done = 0; gl.total = 0; glWorker().postMessage({ type: 'load' }) }
      else scheduleScan(0)
    }
    glRender(); run()
  })
}
$('mode').value = state.mode
$('mode').addEventListener('change', (e) => { state.mode = e.target.value; save(); run() })
$('input').addEventListener('input', onInput)
for (const id of ['custom', 'allow']) $(id).addEventListener('input', run)
$('hl').addEventListener('change', run)
$('copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(last.plain); toast('Copied redacted text') }
  catch { const r = document.createRange(); r.selectNodeContents($('output')); getSelection().removeAllRanges(); getSelection().addRange(r); toast('Press Ctrl+C to copy') }
})
$('download').addEventListener('click', () => download('redacted.txt', last.plain, 'text/plain'))
$('dlMap').addEventListener('click', () => {
  const csv = 'replacement,type,original,found_by\n' + last.rows.map((r) => r.map((c) => '"' + c.replace(/"/g, '""') + '"').join(',')).join('\n')
  download('redaction-key.csv', csv, 'text/csv')
})
$('clear').addEventListener('click', () => { $('input').value = ''; onInput(); $('input').focus() })
$('load').addEventListener('click', () => $('file').click())
$('file').addEventListener('change', (e) => { readFile(e.target.files[0]); e.target.value = '' })
$('forget').addEventListener('click', () => {
  gl.worker?.postMessage({ type: 'forget' })
  setTimeout(() => { gl.worker?.terminate(); gl.worker = null; gl.hits = null; gl.forText = null; gl.state = 'off'; state.engines.gliner = false; $('e-gliner').checked = false; save(); $('forget').hidden = true; glRender(); run() }, 300)
})
const ta = $('input')
ta.addEventListener('dragover', (e) => { e.preventDefault(); ta.classList.add('drop') })
ta.addEventListener('dragleave', () => ta.classList.remove('drop'))
ta.addEventListener('drop', (e) => { if (e.dataTransfer.files.length) { e.preventDefault(); ta.classList.remove('drop'); readFile(e.dataTransfer.files[0]) } })
$('sample').addEventListener('click', () => {
  ta.value = `Dear Ms. Priya Raman,

Thanks for calling on March 3, 2026. Your account (priya.raman@example.com, phone (917) 555-0142) was updated.
Shipping to 221 W 44th Street, Apt 5B, New York, NY 10036.
Card on file: 4111 1111 1111 1111. SSN on record: 219-09-9999. DOB 07/14/1988.
Passport number 912803456, ITIN 912-70-1234. Login from 203.0.113.42, refund to IBAN GB82 WEST 1234 5698 7654 32.
Your husband Tom mentioned he'd prefer texts. His handle is @tomr88 and he lives at 14 Rue des Lilas, Lyon.

Regards, Daniel Okafor
+44 20 7946 0958`
  onInput()
})

const root = document.documentElement
try { const th = localStorage.getItem('pii-theme'); if (th) root.dataset.theme = th } catch {}
$('theme').addEventListener('click', () => {
  const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches
  root.dataset.theme = dark ? 'light' : 'dark'
  try { localStorage.setItem('pii-theme', root.dataset.theme) } catch {}
})

// Reopen the AI model automatically if it was on and is already downloaded
if (state.engines.gliner) { gl.state = 'loading'; glWorker().postMessage({ type: 'load', onlyIfCached: true }) }
glRender()
run()
