import { analyze as presidio } from './presidio.js'
import COMMON from './common-words.js'

const $ = (id) => document.getElementById(id)

// ---------- categories, and the AI labels asked for each ----------
const CATS = [
  { id: 'name', group: 'People & companies', name: 'Names', label: 'NAME', ai: ['person'] },
  { id: 'org', group: 'People & companies', name: 'Companies & organizations', label: 'ORG', ai: ['organization', 'company', 'law firm'] },
  { id: 'address', group: 'Places', name: 'Street addresses', label: 'ADDRESS', ai: ['street_address'] },
  { id: 'place', group: 'Places', name: 'Cities, states & countries', label: 'PLACE', ai: ['city', 'state_or_region', 'country'] },
  { id: 'zip', group: 'Places', name: 'ZIP / postcodes', label: 'POSTCODE', ai: ['postal_code'] },
  { id: 'phone', group: 'Contact', name: 'Phones & faxes', label: 'PHONE', ai: ['phone_number'] },
  { id: 'email', group: 'Contact', name: 'Emails', label: 'EMAIL', ai: ['email'] },
  { id: 'date', group: 'Dates', name: 'Dates', label: 'DATE', ai: ['date', 'date_of_birth'] },
  { id: 'ssn', group: 'Numbers & IDs', name: 'SSNs & national IDs', label: 'SSN', ai: ['national_id_number'] },
  { id: 'ids', group: 'Numbers & IDs', name: 'Other IDs & account numbers', label: 'ID', ai: ['government_id', 'passport_number', 'drivers_license_number', 'tax_id', 'account_number', 'bank_account'] },
  { id: 'card', group: 'Numbers & IDs', name: 'Card numbers', label: 'CARD', ai: ['card_number'] },
  { id: 'iban', group: 'Numbers & IDs', name: 'IBANs', label: 'IBAN', ai: ['iban'] },
  { id: 'username', group: 'Online & secrets', name: 'Usernames', label: 'USERNAME', ai: ['username'] },
  { id: 'secret', group: 'Online & secrets', name: 'Passwords & API keys', label: 'SECRET', ai: ['password', 'api_key'] },
  { id: 'ip', group: 'Online & secrets', name: 'IP / MAC addresses', label: 'IP', ai: ['ip_address'] },
  { id: 'url', group: 'Contact', name: 'URLs', label: 'URL', ai: ['url'], off: true },
  { id: 'custom', group: 'Your lists', name: 'Your list', label: 'TERM', ai: [] },
]
const CAT = Object.fromEntries(CATS.map((c) => [c.id, c]))
const AI_CAT = Object.fromEntries(CATS.flatMap((c) => c.ai.map((l) => [l, c.id])))
const SOURCE_NAME = { patterns: 'Rules', presidio: 'Rules (Presidio)', gliner: 'AI', 'cloud-gliner': 'Cloud AI', 'cloud-llm': 'Cloud LLM reviewer', custom: 'Your list', repeat: 'Repeat of a found name' }
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
  { cat: 'email', re: /(?<![\p{L}\p{N}._%+-])[\p{L}\p{M}\p{N}._%+-]+@[\p{L}\p{M}\p{N}.-]+\.\p{L}{2,}(?![\p{L}\p{N}])/gu },
  { cat: 'url', re: /\bhttps?:\/\/[^\s<>"')\]]+/g },
  { cat: 'card', re: /\b(?:\d[ -]?){12,18}\d\b/g, ok: (m) => { const d = m.replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && luhn(d) } },
  { cat: 'iban', re: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/gi, ok: ibanOk },
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
  updateNote()
  const on = state.engines.gliner
  const mb = (n) => Math.round(n / 1e6)
  $('g-download').hidden = !(on && (gl.state === 'notdownloaded' || (gl.state === 'error' && gl.retry)))
  switch (gl.state) {
    case 'downloading': return glStatus(`Downloading AI model… ${mb(gl.done || 0)} / ${gl.total ? mb(gl.total) : 146} MB`, '', gl.total ? gl.done / gl.total : 0)
    case 'loading': return glStatus('Starting AI model…', '', 1)
    case 'scanning': return glStatus('AI scanning…', '', gl.progress ?? 0)
    case 'ready': return glStatus(on ? `<span class="ok">Ready</span>${gl.ms ? ` · last scan ${(gl.ms / 1000).toFixed(1)} s` : ''}` : 'Off (model downloaded)')
    case 'notdownloaded': return glStatus(on ? '<span class="warn">Not downloaded yet.</span> Until then only the rules run.' : 'Off')
    case 'error': return glStatus(escHtml(gl.error), 'warn')
    default: return glStatus(on ? 'Checking…' : 'Off')
  }
}
function glWorker() {
  if (gl.worker) return gl.worker
  const w = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' })
  w.onmessage = ({ data: m }) => {
    if (m.type === 'status') {
      if (m.state === 'off') gl.state = 'notdownloaded'
      // after a failed download, progress still arriving from the other files must not hide the error
      else if (!(gl.state === 'error' && m.state === 'downloading')) Object.assign(gl, { state: m.state, done: m.done, total: m.total })
      if (m.state === 'ready') { $('forget').hidden = false; scheduleScan(0) }
    } else if (m.type === 'progress' && m.id === gl.reqId) { gl.progress = m.p }
    else if (m.type === 'result' && m.id === gl.reqId) {
      gl.state = 'ready'; gl.ms = m.ms; gl.forKey = gl.pendingKey
      gl.hits = m.ents.map((e) => ({ start: e.start, end: e.end, cat: AI_CAT[e.label] || 'ids', source: 'gliner', score: e.score, detail: e.label }))
      run()
    } else if (m.type === 'error') { gl.retry = ['downloading', 'loading'].includes(gl.state); gl.state = 'error'; gl.error = 'Error: ' + m.message }
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

// ---------- cloud GPU: optional, on the user's own Modal endpoint (see cloud/) ----------
// Never automatic: a scan is sent only when the user presses "Cloud scan" and confirms.
const CLOUD_KEY = 'pii-cloud-v1'
const cloud = { url: '', token: '', ack: false, remember: true, busy: false, result: null, ctrl: null, t0: 0, tick: 0, error: '', msg: '', confirmed: false }
try {
  const c = JSON.parse(localStorage.getItem(CLOUD_KEY) || sessionStorage.getItem(CLOUD_KEY) || '{}')
  for (const k of ['url', 'token', 'ack', 'remember']) if (k in c) cloud[k] = c[k]
} catch {}
function cloudSave() {
  const data = JSON.stringify({ url: cloud.url, token: cloud.token, ack: cloud.ack, remember: cloud.remember })
  try {
    if (cloud.remember) { localStorage.setItem(CLOUD_KEY, data); sessionStorage.removeItem(CLOUD_KEY) }
    else { sessionStorage.setItem(CLOUD_KEY, data); localStorage.removeItem(CLOUD_KEY) }
  } catch {}
}
const cloudBase = () => {
  try { const u = new URL(cloud.url.trim()); return u.protocol === 'https:' && u.hostname.endsWith('.modal.run') ? u.origin : null } catch { return null }
}
const cloudCats = () => CATS.filter((c) => state.on[c.id] && c.id !== 'custom').map((c) => c.id)
function cloudProblem() {
  if (!cloudBase()) return 'Enter your endpoint URL (https://…modal.run)'
  if (cloud.token.trim().length < 24) return 'Enter your access token'
  if (!cloud.ack) return 'Tick the box to confirm you understand the cost and privacy trade-off'
  return ''
}
async function cloudFetch(path, body, signal) {
  let res
  try {
    res = await fetch(cloudBase() + path, {
      method: 'POST', body: JSON.stringify(body || {}), signal, credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store',
      headers: { Authorization: 'Bearer ' + cloud.token.trim(), 'Content-Type': 'application/json' },
    })
  } catch (e) {
    if (signal?.aborted) throw e
    throw new Error('Could not reach the server. Check the URL, and that the app is deployed.')
  }
  let data = null
  try { data = await res.json() } catch {}
  if (!res.ok) throw new Error(data?.detail || `Server replied ${res.status}`)
  return data
}
async function cloudTest() {
  if (!cloudBase() || cloud.token.trim().length < 24) { cloud.msg = '<span class="bad">' + escHtml(cloudProblem()) + '</span>'; return cloudRender() }
  cloud.msg = 'Checking…'; cloudRender()
  try {
    const r = await cloudFetch('/check')
    cloud.msg = `<span class="ok">Connected.</span> ${escHtml(r.model || '')} on ${escHtml(r.gpu || 'GPU')}. The GPU was not started.`
  } catch (e) { cloud.msg = '<span class="bad">' + escHtml(e.message) + '</span>' }
  cloudRender()
}
async function cloudScan() {
  if (cloud.busy) { cloud.ctrl?.abort('cancel'); return }
  const text = $('input').value
  const problem = cloudProblem()
  if (problem) { toast(problem); $('cloudPanel').hidden = false; return }
  if (!text.trim()) return toast('Paste some text first')
  if (!cloud.confirmed && !confirm(`Send this text (${text.length.toLocaleString()} characters) to ${new URL(cloudBase()).hostname} for a cloud scan?\n\nIt runs a GPU on your Modal account and is billed to it, usually a few cents.`)) return
  cloud.confirmed = true // ask once per visit
  Object.assign(cloud, { busy: true, error: '', t0: performance.now(), ctrl: new AbortController() })
  const ctrl = cloud.ctrl
  const limit = setTimeout(() => ctrl.abort('timeout'), 10 * 60e3)
  cloud.tick = setInterval(cloudRender, 1000)
  cloudRender(); run()
  try {
    const r = await cloudFetch('/scan', { text, cats: cloudCats(), threshold: aiThreshold(), llm: true }, ctrl.signal)
    cloud.result = { text, spans: r.spans || [], secs: (performance.now() - cloud.t0) / 1000, model: r.model }
    toast(`Cloud scan done: ${cloud.result.spans.length} items`)
  } catch (e) {
    cloud.error = ctrl.signal.aborted ? (ctrl.signal.reason === 'timeout' ? 'Gave up after 10 minutes.' : 'Stopped waiting. The GPU may still finish the job and bill for it.') : e.message
  } finally {
    clearTimeout(limit); clearInterval(cloud.tick)
    cloud.busy = false
    cloudRender(); run()
  }
}
// Cloud results, mapped onto the current text. If the text was edited after the scan,
// the same strings are looked up again.
function cloudHits(text) {
  const r = cloud.result
  if (!state.engines.cloud || !r) return []
  const mk = (start, end, sp) => ({ start, end, cat: CAT[sp.cat] ? sp.cat : 'ids', source: sp.source, score: sp.score ?? 0.8, tier: 2 })
  if (r.text === text) {
    // The server is Python, whose offsets count code points; JS strings count UTF-16 units
    // (an emoji is 1 vs 2), so map them or every span after an emoji lands in the wrong place.
    const at = [0]
    for (const ch of text) at.push(at[at.length - 1] + ch.length)
    return r.spans.filter((sp) => sp.start < sp.end && sp.end < at.length).map((sp) => mk(at[sp.start], at[sp.end], sp))
  }
  const out = [], seen = new Set()
  for (const sp of r.spans) {
    const k = sp.cat + '\u0000' + sp.text
    if (seen.has(k) || !sp.text?.trim()) continue
    seen.add(k)
    const re = new RegExp((/^[\p{L}\p{N}]/u.test(sp.text) ? '(?<![\\p{L}\\p{N}])' : '') + escRe(sp.text.trim()).replace(/\s+/g, '\\s+') + (/[\p{L}\p{N}]$/u.test(sp.text) ? '(?![\\p{L}\\p{N}])' : ''), 'gu')
    for (const m of text.matchAll(re)) out.push(mk(m.index, m.index + m[0].length, sp))
  }
  return out
}
function cloudRender() {
  const on = state.engines.cloud
  $('cloudPanel').hidden = !on
  $('cloudScan').hidden = !on
  document.querySelector('.lg-cloud').hidden = !on
  const p = $('privacy')
  p.className = 'pill ' + (on ? 'warn' : 'ok')
  p.lastElementChild.textContent = on ? 'Cloud scan on: text is sent when you press Cloud scan.' : 'On this device. Nothing is uploaded.'
  const secs = Math.round((performance.now() - cloud.t0) / 1000)
  const st = $('c-state')
  st.className = 'st'
  if (!on) st.textContent = 'Off'
  else if (cloud.busy) st.innerHTML = `Working… ${secs} s${secs > 15 ? ' (the GPU may be starting, 1 to 3 min)' : ''}`
  else if (cloud.error) st.innerHTML = '<span class="bad">' + escHtml(cloud.error) + '</span>'
  else if (cloudProblem()) st.innerHTML = '<span class="warn">Set up below.</span>'
  else if (cloud.result) st.innerHTML = `<span class="ok">Last scan:</span> ${cloud.result.spans.length} items in ${Math.round(cloud.result.secs)} s${cloud.result.text !== $('input').value ? ' (text changed since)' : ''}`
  else st.innerHTML = '<span class="ok">Ready.</span> Press Cloud scan under the result.'
  const b = $('cloudScan')
  b.textContent = cloud.busy ? `Cancel cloud scan (${secs} s)` : 'Cloud scan (billed to Modal)'
  $('c-msg').innerHTML = cloud.msg
}

// ---------- merge + redact ----------
const state = { on: {}, mode: 'label', sensitivity: 'high', propagate: true, engines: { rules: true, gliner: true, cloud: false } }
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
  hits.push(...cloudHits(text))
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
// Any part of a later match that no earlier span covers is still redacted on its own,
// so "Acme" on your list can't leave "Widgets, Inc." of "Acme Widgets, Inc." showing.
function merge(hits, text) {
  hits.sort((a, b) => a.tier - b.tier || b.score - a.score || (b.end - b.start) - (a.end - a.start))
  // acc never holds overlapping spans, so it is kept sorted by position and searched by
  // bisection: scanning all of it for every hit froze the page for 30 s on a 1 MB paste.
  const acc = []
  const after = (pos) => { let lo = 0, hi = acc.length; while (lo < hi) { const m = (lo + hi) >> 1; if (acc[m].end > pos) hi = m; else lo = m + 1 } return lo }
  const within = (s, e) => { const out = []; for (let i = after(s); i < acc.length && acc[i].start < e; i++) out.push(acc[i]); return out }
  const add = (span) => acc.splice(after(span.start), 0, span)
  for (const h of hits) {
    const ov = within(h.start, h.end)
    if (!ov.length) { add({ ...h, sources: new Set([h.source]) }); continue }
    for (const a of ov) if (a.cat === h.cat) a.sources.add(h.source)
    if (ov.length === 1 && ov[0].cat === h.cat) {
      const a = ov[0], s = Math.min(a.start, h.start), e = Math.max(a.end, h.end)
      if (within(s, e).length === 1) { a.start = s; a.end = e }
    }
    const gaps = []
    let pos = h.start
    for (const a of within(h.start, h.end)) {
      if (a.start > pos) gaps.push([pos, a.start])
      pos = Math.max(pos, a.end)
    }
    if (pos < h.end) gaps.push([pos, h.end])
    for (let [s, e] of gaps) {
      while (s < e && /[\s,;:]/.test(text[s])) s++
      while (e > s && /[\s,;:]/.test(text[e - 1])) e--
      if (/[\p{L}\p{N}]/u.test(text.slice(s, e))) add({ ...h, start: s, end: e, sources: new Set([h.source]) })
    }
  }
  return acc
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
  const hits = merge(collect(text), text)
  const ids = { n: {}, map: new Map() }
  const counts = {}
  let plain = '', html = '', pos = 0
  const rows = [], seen = new Set()
  for (const h of hits) {
    const orig = text.slice(h.start, h.end)
    const rep = replacement(h, text, ids)
    const src = [...h.sources]
    const cls = src.includes('patterns') || src.includes('presidio') || src.includes('custom') ? '' : src.includes('gliner') ? 's-gliner' : src.some((s) => s.startsWith('cloud')) ? 's-cloud' : 's-repeat'
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
  if (!text) out.innerHTML = '<span class="empty">The redacted text appears here as you type or paste.</span>'
  else if ($('hl').checked) out.innerHTML = html
  else out.textContent = plain
  for (const c of CATS) { const el = document.querySelector(`[data-n="${c.id}"]`); if (el) el.textContent = counts[c.id] || '' }
  $('total').textContent = text ? `${hits.length} redaction${hits.length === 1 ? '' : 's'}` : ''
  updateNote()
  $('inCount').textContent = text ? `${text.length.toLocaleString()} chars` : ''
  $('mapCount').textContent = rows.length ? `(${rows.length})` : ''
  $('map').innerHTML = rows.map((r) => `<tr><td><code>${escHtml(r[0])}</code></td><td>${escHtml(r[1])}</td><td><code>${escHtml(r[2])}</code></td><td>${escHtml(r[3])}</td></tr>`).join('') || '<tr><td colspan="4" class="muted">Nothing found yet.</td></tr>'
}

// What is still running, so the user doesn't copy a half-finished result.
function pending() {
  const text = $('input').value
  if (!text.trim()) return ''
  if (state.engines.gliner && gl.forKey !== aiKey(text) && ['ready', 'scanning', 'loading'].includes(gl.state)) return 'The AI is still scanning. More items may be redacted in a moment.'
  if (state.engines.gliner && gl.state === 'downloading') return 'The AI model is downloading. Only the rules have run so far.'
  if (cloud.busy) return 'Cloud scan in progress.'
  return ''
}

function updateNote() {
  const note = pending()
  $('outNote').hidden = !note
  $('outNote').lastElementChild.textContent = note
  $('cloudScan').disabled = !$('input').value.trim() && !cloud.busy
}

let runTimer = 0
function onInput() {
  clearTimeout(runTimer)
  if (cloud.result) cloudRender()
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
const settingsChanged = () => { save(); run(); scheduleScan(200); glRender(); cloudRender() }

const chip = (c) => `<label class="chip"><input type="checkbox" data-id="${c.id}" ${state.on[c.id] ? 'checked' : ''}>${c.name} <span class="n" data-n="${c.id}"></span></label>`
$('cats').innerHTML = [...new Set(CATS.map((c) => c.group))].map((g) => `<div class="grp"><span>${g}</span><div class="chips">${CATS.filter((c) => c.group === g).map(chip).join('')}</div></div>`).join('')
$('cats').addEventListener('change', (e) => { state.on[e.target.dataset.id] = e.target.checked; settingsChanged() })
for (const [id, val] of [['allOn', true], ['allOff', false]]) $(id).addEventListener('click', () => {
  for (const c of CATS) state.on[c.id] = val
  for (const el of $('cats').querySelectorAll('input')) el.checked = val
  settingsChanged()
})
for (const k of ['rules', 'gliner', 'cloud']) {
  const el = $('e-' + k)
  el.checked = state.engines[k]
  el.addEventListener('change', () => {
    state.engines[k] = el.checked
    if (k === 'gliner' && el.checked && (gl.state === 'off' || gl.state === 'error')) glWorker().postMessage({ type: 'load', onlyIfCached: true, labels: aiLabels() })
    if (k === 'rules') $('r-status').textContent = el.checked ? 'On' : 'Off'
    settingsChanged()
  })
}
$('g-download').addEventListener('click', (e) => { e.preventDefault(); glDownload() })
$('r-status').textContent = state.engines.rules ? 'On' : 'Off'
$('c-url').value = cloud.url
$('c-token').value = cloud.token
$('c-ack').checked = cloud.ack
$('c-remember').checked = cloud.remember
for (const [id, key, prop] of [['c-url', 'url', 'value'], ['c-token', 'token', 'value'], ['c-ack', 'ack', 'checked'], ['c-remember', 'remember', 'checked']]) {
  $(id).addEventListener(prop === 'value' ? 'input' : 'change', (e) => { cloud[key] = e.target[prop]; cloud.msg = ''; cloudSave(); cloudRender() })
}
$('c-test').addEventListener('click', cloudTest)
$('cloudScan').addEventListener('click', cloudScan)
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
  const p = pending()
  if (p && !confirm(p + '\n\nCopy the current result anyway?')) return
  try { await navigator.clipboard.writeText(last.plain); toast('Copied redacted text') }
  catch { const r = document.createRange(); r.selectNodeContents($('output')); getSelection().removeAllRanges(); getSelection().addRange(r); toast('Press Ctrl+C to copy') }
})
$('download').addEventListener('click', () => { const p = pending(); if (!p || confirm(p + '\n\nDownload the current result anyway?')) download('redacted.txt', last.plain, 'text/plain') })
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
cloudRender()
run()
