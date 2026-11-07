import { analyze as presidio } from './presidio.js'
import COMMON from './common-words.js'

const $ = (id) => document.getElementById(id)

// ---------- categories, and the AI labels asked for each ----------
const CATS = [
  { id: 'name', name: 'Names', label: 'NAME', ai: ['person'] },
  { id: 'org', name: 'Companies & organizations', label: 'ORG', ai: ['organization', 'company', 'law firm'] },
  { id: 'address', name: 'Street addresses', label: 'ADDRESS', ai: ['street_address'] },
  { id: 'place', name: 'Cities, states & countries', label: 'PLACE', ai: ['city', 'state_or_region', 'country'] },
  { id: 'zip', name: 'ZIP / postcodes', label: 'POSTCODE', ai: ['postal_code'] },
  { id: 'phone', name: 'Phones & faxes', label: 'PHONE', ai: ['phone_number'] },
  { id: 'email', name: 'Emails', label: 'EMAIL', ai: ['email'] },
  { id: 'date', name: 'Dates', label: 'DATE', ai: ['date', 'date_of_birth'] },
  { id: 'ssn', name: 'SSNs & national IDs', label: 'SSN', ai: ['national_id_number'] },
  { id: 'ids', name: 'Other IDs & account numbers', label: 'ID', ai: ['government_id', 'passport_number', 'drivers_license_number', 'tax_id', 'account_number', 'bank_account'] },
  { id: 'card', name: 'Card numbers', label: 'CARD', ai: ['card_number'] },
  { id: 'iban', name: 'IBANs', label: 'IBAN', ai: ['iban'] },
  { id: 'username', name: 'Usernames', label: 'USERNAME', ai: ['username'] },
  { id: 'secret', name: 'Passwords & API keys', label: 'SECRET', ai: ['password', 'api_key'] },
  { id: 'ip', name: 'IP / MAC addresses', label: 'IP', ai: ['ip_address'] },
  { id: 'url', name: 'URLs', label: 'URL', ai: ['url'], off: true },
  { id: 'custom', name: 'Your list', label: 'TERM', ai: [] },
]
const CAT = Object.fromEntries(CATS.map((c) => [c.id, c]))
const AI_CAT = Object.fromEntries(CATS.flatMap((c) => c.ai.map((l) => [l, c.id])))
const SOURCE_NAME = { patterns: 'Rules', presidio: 'Rules (Presidio)', gliner: 'AI', custom: 'Your list', repeat: 'Repeat of a found name' }
const SENSITIVITY = { balanced: 0.5, high: 0.35, max: 0.2 }

// ---------- rules 1: built-in patterns ----------
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
const STREET = 'Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Way|Terrace|Ter|Parkway|Pkwy|Highway|Hwy|Circle|Cir|Square|Sq|Broadway|Plaza|Turnpike|Tpke|Expressway|Expy|Alley|Row|Walk|Trail|Crescent|Close|Mews'
const STATES = 'Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New Hampshire|New Jersey|New Mexico|New York|North Carolina|North Dakota|Ohio|Oklahoma|Oregon|Pennsylvania|Rhode Island|South Carolina|South Dakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|West Virginia|Wisconsin|Wyoming|District of Columbia'
const ORG_SUFFIX = String.raw`LLP|L\.L\.P\.|LLC|L\.L\.C\.|PLLC|P\.L\.L\.C\.|P\.C\.|P\.A\.|Inc\.?|Incorporated|Corp\.?|Corporation|Co\.|Ltd\.?|Limited|GmbH|AG|S\.A\.|N\.V\.|B\.V\.|S\.r\.l\.|LP|L\.P\.`
const ROLE = 'Defendants?|Plaintiffs?|Respondents?|Petitioners?|Appellants?|Appellees?|Claimants?|The|By|To|From|And|Of|For|With|Attorneys?|Counsel|Dated|Re|Dear|Between'
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
  { cat: 'address', keepTrail: true, re: new RegExp(String.raw`\b\d{1,6}(?:-\d{1,4})? (?:[NSEW]\.? )?(?:[A-Z0-9][\w'.-]*\s){0,4}(?:${STREET})\b\.?(?:,?\s(?:Apt|Apartment|Suite|Ste|Unit|Fl|Floor|Room|Rm|#)\.?\s?[\w-]+|,?\s\d+(?:st|nd|rd|th) Floor)*`, 'g') },
  { cat: 'zip', re: /\b[A-Z]{2}\s\d{5}(?:-\d{4})?\b|\b[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2}\b/g },
  { cat: 'zip', re: new RegExp(String.raw`(?<=\b(?:${STATES}),?\s)\d{5}(?:-\d{4})?\b`, 'g') },
  { cat: 'org', re: new RegExp(String.raw`\b(?:(?!(?:${ROLE}|Esq|Esquire)\b)[A-Z][\w'’.-]*,?\s+(?:&\s+)?){1,6}(?:${ORG_SUFFIX})(?![\w])`, 'g') },
  { cat: 'name', re: new RegExp(String.raw`\b(?:(?:Mr|Mrs|Ms|Mx|Miss|Dr|Prof|Sir|Madam|Hon|Judge|Justice)\.?\s+[A-Z][a-zA-Z'-]+(?:\s+[A-Z]\.)?(?:\s+[A-Z][a-zA-Z'-]+){0,2}|(?!(?:${ROLE})\b)[A-Z][a-zA-Z'-]+(?:\s+[A-Z]\.)?(?:\s+[A-Z][a-zA-Z'-]+){1,2}(?=,?\s+(?:Esq|M\.?D|Ph\.?D|J\.?D)\b)|(?<=\b(?:[Nn]ame|[Pp]atient|[Cc]lient|[Cc]ustomer|[Ee]mployee|[Cc]ontact|[Dd]ear|[Ss]igned|[Rr]egards,?|[Ss]incerely,?)\s*[:,]?\s+)(?!(?:${ROLE})\b)[A-Z][a-zA-Z'-]+(?:\s+[A-Z]\.)?(?:\s+[A-Z][a-zA-Z'-]+){1,2})`, 'g') },
  { cat: 'secret', re: /\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bxox[abpr]-[A-Za-z0-9-]{10,}\b|\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b|\bsk-[A-Za-z0-9_-]{20,}\b/g },
]
function runPatterns(text) {
  const out = []
  for (const p of PATTERNS) {
    p.re.lastIndex = 0
    for (const m of text.matchAll(p.re)) {
      let s = m[0]
      if (!p.keepTrail) s = s.replace(/[\s,;:]+$/, '').replace(/(?<![A-Z])\.$/, '')
      if (!s || (p.ok && !p.ok(s))) continue
      out.push({ start: m.index, end: m.index + s.length, cat: p.cat, source: 'patterns', score: 0.9 })
    }
  }
  return out
}

// ---------- rules 2: Presidio ----------
const PRESIDIO_CAT = { EMAIL_ADDRESS: 'email', URL: 'url', CREDIT_CARD: 'card', IBAN_CODE: 'iban', US_SSN: 'ssn', IP_ADDRESS: 'ip', MAC_ADDRESS: 'ip', DATE_TIME: 'date', UK_POSTCODE: 'zip', CA_POSTAL_CODE: 'zip' }
function runPresidio(text) {
  return presidio(text).map((r) => {
    const cat = PRESIDIO_CAT[r.entity] || 'ids'
    return { start: r.start, end: r.end, cat, source: 'presidio', score: r.score, label: cat === 'ids' ? r.entity : undefined, detail: r.entity }
  })
}

// ---------- AI: GLiNER2 in a worker ----------
const gl = { worker: null, state: 'off', hits: null, forKey: null, reqId: 0, timer: 0, ms: 0, cached: false }
const aiLabels = () => CATS.filter((c) => state.on[c.id]).flatMap((c) => c.ai)
const aiThreshold = () => SENSITIVITY[state.sensitivity] ?? 0.35
const aiKey = (text) => text + '\u0001' + aiLabels().join(',') + '\u0001' + aiThreshold()

function glStatus(html, cls = '', pct = null) {
  const s = $('g-status')
  s.className = 'st ' + cls
  s.innerHTML = html
  $('g-bar').hidden = pct === null
  if (pct !== null) $('g-bar').firstElementChild.style.width = Math.round(pct * 100) + '%'
}
function glRender() {
  const on = state.engines.gliner
  const mb = (n) => Math.round(n / 1e6)
  $('g-download').hidden = !(on && gl.state === 'notdownloaded')
  switch (gl.state) {
    case 'downloading': return glStatus(`Downloading AI model… ${mb(gl.done || 0)} / ${gl.total ? mb(gl.total) : 146} MB`, '', gl.total ? gl.done / gl.total : 0)
    case 'loading': return glStatus('Starting AI model…', '', 1)
    case 'scanning': return glStatus('AI scanning…', '', gl.progress ?? 0)
    case 'ready': return glStatus(on ? `<span class="ok">Ready</span>${gl.ms ? ` · last scan ${(gl.ms / 1000).toFixed(1)} s` : ''}` : 'Off (model downloaded)')
    case 'notdownloaded': return glStatus(on ? '<span class="warn">Not downloaded yet.</span> Until then only the rules run.' : 'Off')
    case 'error': return glStatus(gl.error, 'warn')
    default: return glStatus(on ? 'Checking…' : 'Off')
  }
}
function glWorker() {
  if (gl.worker) return gl.worker
  const w = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' })
  w.onmessage = ({ data: m }) => {
    if (m.type === 'status') {
      if (m.state === 'off') gl.state = 'notdownloaded'
      else Object.assign(gl, { state: m.state, done: m.done, total: m.total })
      if (m.state === 'ready') { $('forget').hidden = false; scheduleScan(0) }
    } else if (m.type === 'progress' && m.id === gl.reqId) { gl.progress = m.p }
    else if (m.type === 'result' && m.id === gl.reqId) {
      gl.state = 'ready'; gl.ms = m.ms; gl.forKey = gl.pendingKey
      gl.hits = m.ents.map((e) => ({ start: e.start, end: e.end, cat: AI_CAT[e.label] || 'ids', source: 'gliner', score: e.score, detail: e.label }))
      run()
    } else if (m.type === 'error') { gl.state = 'error'; gl.error = 'Error: ' + m.message }
    else if (m.type === 'forgot') { toast('AI model removed from this browser') }
    glRender()
  }
  w.onerror = (e) => { gl.state = 'error'; gl.error = 'Error: ' + (e.message || 'could not start the AI model'); glRender() }
  return (gl.worker = w)
}
function glDownload() {
  gl.state = 'downloading'; gl.done = 0; gl.total = 0
  glWorker().postMessage({ type: 'load', labels: aiLabels() })
  glRender()
}
function scheduleScan(delay = 600) {
  clearTimeout(gl.timer)
  if (!state.engines.gliner || !['ready', 'scanning'].includes(gl.state)) return
  const text = $('input').value
  const key = aiKey(text)
  if (!text.trim() || key === gl.forKey) return
  gl.timer = setTimeout(() => {
    gl.reqId++; gl.pendingKey = key; gl.state = 'scanning'; gl.progress = 0
    gl.worker.postMessage({ type: 'predict', id: gl.reqId, text, labels: aiLabels(), threshold: aiThreshold() })
    glRender()
  }, delay)
}

// ---------- merge + redact ----------
const state = { on: {}, mode: 'label', sensitivity: 'high', propagate: true, engines: { rules: true, gliner: true } }
try {
  const s = JSON.parse(localStorage.getItem('pii-opts-v2') || '{}')
  Object.assign(state, s, { engines: { ...state.engines, ...s.engines }, on: { ...s.on } })
} catch {}
for (const c of CATS) if (!(c.id in state.on)) state.on[c.id] = !c.off

const splitList = (s) => s.split(/[,\n]/).map((x) => x.trim()).filter(Boolean)
const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const escHtml = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c])

function collect(text) {
  const hits = []
  const custom = splitList($('custom').value).sort((a, b) => b.length - a.length)
  if (custom.length) {
    const re = new RegExp('(?<![\\p{L}\\p{N}])(?:' + custom.map((c) => escRe(c).replace(/\s+/g, '\\s+')).join('|') + ')(?![\\p{L}\\p{N}])', 'giu')
    for (const m of text.matchAll(re)) hits.push({ start: m.index, end: m.index + m[0].length, cat: 'custom', source: 'custom', score: 2, tier: 0 })
  }
  if (state.engines.rules) {
    hits.push(...runPatterns(text).map((h) => ({ ...h, tier: 1 })))
    hits.push(...runPresidio(text).map((h) => ({ ...h, tier: 1 })))
  }
  if (state.engines.gliner && gl.hits && gl.forKey === aiKey(text)) hits.push(...gl.hits.map((h) => ({ ...h, tier: 2 })))
  const allow = new Set(splitList($('allow').value).map((s) => s.toLowerCase()))
  const ok = (h) => state.on[h.cat] && !allow.has(text.slice(h.start, h.end).trim().toLowerCase())
  const found = hits.filter(ok)
  return [...found, ...propagate(text, found).filter(ok)]
}

// Once a name or company is found, redact its other mentions too (and a person's
// first or last name on its own), so "Linda Mei" also catches "Defendant Mei".
const NAME_STOP = new Set(['mr', 'mrs', 'ms', 'mx', 'miss', 'dr', 'prof', 'sir', 'madam', 'hon', 'judge', 'justice', 'esq', 'jr', 'sr', 'ii', 'iii', 'the', 'and', 'of', 'for', 'von', 'van', 'de', 'la', 'del', 'du', 'der', 'des', 'di', 'da', 'le', 'cpa', 'md', 'phd', 'jd'])
function propagate(text, hits) {
  if (!state.propagate) return []
  const terms = new Map()
  for (const h of hits) {
    if (!['name', 'org', 'custom'].includes(h.cat)) continue
    const t = text.slice(h.start, h.end).replace(/\s+/g, ' ').trim()
    if (t.length >= 3) terms.set(t.toLowerCase(), h.cat === 'custom' ? 'custom' : h.cat)
    if (h.cat === 'name') {
      for (const w of t.match(/\p{L}[\p{L}'’-]+/gu) || []) {
        const lw = w.toLowerCase().replace(/['’]s$/, '')
        if (w.length >= 3 && !NAME_STOP.has(lw) && !COMMON.has(lw) && /^\p{Lu}/u.test(w) && !terms.has(lw)) terms.set(lw, 'name')
      }
    }
  }
  if (!terms.size) return []
  const list = [...terms.keys()].sort((a, b) => b.length - a.length)
  const re = new RegExp('(?<![\\p{L}\\p{N}])(?:' + list.map((t) => escRe(t).replace(/ /g, '\\s+')).join('|') + ')(?![\\p{L}\\p{N}])', 'giu')
  const out = []
  for (const m of text.matchAll(re)) out.push({ start: m.index, end: m.index + m[0].length, cat: terms.get(m[0].replace(/\s+/g, ' ').toLowerCase()) || 'name', source: 'repeat', score: 0.5, tier: 3 })
  return out
}

// Overlaps: your list first, then rules (higher score, then longer), then the AI, then repeats.
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
    const cls = src.includes('gliner') && !src.includes('patterns') && !src.includes('presidio') ? 's-gliner' : src.every((s) => s === 'repeat') ? 's-repeat' : ''
    const by = src.map((s) => SOURCE_NAME[s]).join(', ')
    plain += text.slice(pos, h.start) + rep
    html += escHtml(text.slice(pos, h.start)) + `<mark class="${cls}" title="${escHtml(CAT[h.cat].name + ' · ' + by)}">${escHtml(rep)}</mark>`
    pos = h.end
    counts[h.cat] = (counts[h.cat] || 0) + 1
    const rk = rep + '\u0000' + orig
    if (!seen.has(rk)) {
      seen.add(rk)
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
  const waiting = state.engines.gliner && text.trim() && gl.forKey !== aiKey(text) && ['ready', 'scanning'].includes(gl.state)
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
function save() { try { localStorage.setItem('pii-opts-v2', JSON.stringify({ on: state.on, mode: state.mode, sensitivity: state.sensitivity, propagate: state.propagate, engines: state.engines })) } catch {} }
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
const settingsChanged = () => { save(); run(); scheduleScan(200); glRender() }

$('cats').innerHTML = CATS.map((c) => `<label class="chip"><input type="checkbox" data-id="${c.id}" ${state.on[c.id] ? 'checked' : ''}>${c.name} <span class="n" data-n="${c.id}"></span></label>`).join('')
$('cats').addEventListener('change', (e) => { state.on[e.target.dataset.id] = e.target.checked; settingsChanged() })
for (const k of ['rules', 'gliner']) {
  const el = $('e-' + k)
  el.checked = state.engines[k]
  el.addEventListener('change', () => {
    state.engines[k] = el.checked
    if (k === 'gliner' && el.checked && (gl.state === 'off' || gl.state === 'error')) glWorker().postMessage({ type: 'load', onlyIfCached: true, labels: aiLabels() })
    settingsChanged()
  })
}
$('g-download').addEventListener('click', (e) => { e.preventDefault(); glDownload() })
$('sensitivity').value = state.sensitivity
$('sensitivity').addEventListener('change', (e) => { state.sensitivity = e.target.value; settingsChanged() })
$('propagate').checked = state.propagate
$('propagate').addEventListener('change', (e) => { state.propagate = e.target.checked; settingsChanged() })
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
  setTimeout(() => { gl.worker?.terminate(); gl.worker = null; gl.hits = null; gl.forKey = null; gl.state = 'notdownloaded'; $('forget').hidden = true; glRender(); run() }, 300)
})
const ta = $('input')
ta.addEventListener('dragover', (e) => { e.preventDefault(); ta.classList.add('drop') })
ta.addEventListener('dragleave', () => ta.classList.remove('drop'))
ta.addEventListener('drop', (e) => { if (e.dataTransfer.files.length) { e.preventDefault(); ta.classList.remove('drop'); readFile(e.dataTransfer.files[0]) } })
$('sample').addEventListener('click', () => {
  ta.value = `Defendant Acme Widgets, Inc. ("Acme"), by its attorneys, HARTWELL BRENNAN
& COLE, LLP, responds as follows to Plaintiff's First Set of Interrogatories.

These responses are based on information provided by Priya Raman, CFO of Defendant Acme.
Dated: White Plains, New York
March 3, 2026
Daniel Okafor, Esq.
HARTWELL BRENNAN & COLE, LLP
44 South Broadway, Suite 1100
White Plains, New York 10601
(914) 555-0142
TO: Tom Reyes, Esq., Attorney for Plaintiff, reyes@reyeslaw.com
Ms. Raman's SSN on file is 219-09-9999; her passport number is 912803456.`
  onInput()
})

const root = document.documentElement
try { const th = localStorage.getItem('pii-theme'); if (th) root.dataset.theme = th } catch {}
$('theme').addEventListener('click', () => {
  const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches
  root.dataset.theme = dark ? 'light' : 'dark'
  try { localStorage.setItem('pii-theme', root.dataset.theme) } catch {}
})

// Open the AI model straight away if it's already downloaded; otherwise offer the download.
if (state.engines.gliner) { gl.state = 'loading'; glWorker().postMessage({ type: 'load', onlyIfCached: true, labels: aiLabels() }) }
glRender()
run()
