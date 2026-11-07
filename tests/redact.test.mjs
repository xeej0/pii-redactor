// Redaction checks for app.js in Node, with a tiny fake DOM: node --test tests/
import { test } from 'node:test'
import assert from 'node:assert/strict'

const els = new Map()
function el(id) {
  if (!els.has(id)) {
    els.set(id, {
      id, value: '', checked: false, hidden: false, disabled: false, innerHTML: '', textContent: '', className: '', style: {}, dataset: {},
      listeners: {}, classList: { add() {}, remove() {} }, firstElementChild: { style: {} }, lastElementChild: { textContent: '' },
      addEventListener(t, f) { (this.listeners[t] ||= []).push(f) },
      fire(t) { for (const f of this.listeners[t] || []) f({ target: this, preventDefault() {} }) },
      querySelectorAll: () => [], focus() {}, click() {},
    })
  }
  return els.get(id)
}
const store = () => { const m = new Map(); return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) } }
globalThis.document = { getElementById: el, querySelector: () => el('__any'), documentElement: { dataset: {} }, createElement: () => ({ click() {} }) }
globalThis.localStorage = store()
globalThis.sessionStorage = store()
globalThis.Worker = class { postMessage() {} }
globalThis.matchMedia = () => ({ matches: false })
globalThis.confirm = () => true
await import('../app.js')

const tick = () => new Promise((r) => setTimeout(r, 0))
async function redact(text, { custom = '' } = {}) {
  el('hl').checked = false
  el('custom').value = custom
  el('input').value = text
  el('input').fire('input')
  await tick()
  return el('output').textContent
}

test('a partly overlapping lower-priority match is still redacted', async () => {
  const out = await redact('Defendant Acme Widgets, Inc. responds.', { custom: 'Acme' })
  assert.ok(!out.includes('Widgets'), out)
})

test('lowercase IBAN is redacted', async () => {
  const out = await redact('Pay to de89 3704 0044 0532 0130 00 today.')
  assert.ok(!/0130|3704/.test(out), out)
})

test('emails with accented or non-Latin local parts are redacted whole', async () => {
  const out = await redact('Write to josé.garcía@example.com or أحمد@example.com, or bob@example.co.uk.')
  for (const s of ['jos', 'garc', 'أحمد', 'example', 'bob']) assert.ok(!out.includes(s), out)
  assert.ok(out.endsWith('.'), out)
})

test('names with accented letters are redacted whole by the rules', async () => {
  const out = await redact('Seen by Ms. Zoë Ångström and Émile Zola, Esq. for patient: José Müller.')
  for (const s of ['Zo', 'Ångström', 'Émile', 'Zola', 'José', 'Müller']) assert.ok(!out.includes(s), out)
})

test('basic rules still work', async () => {
  const out = await redact('SSN 219-09-9999, email jane@example.com, card 4111 1111 1111 1111, call (914) 555-0142.')
  for (const s of ['219-09-9999', 'jane@example.com', '4111', '555-0142']) assert.ok(!out.includes(s), out)
})

test('cloud spans (Python code point offsets) land on the right text after an emoji', async () => {
  const text = 'Hi 😀😀 from Priya Raman today'
  // offsets as Python counts them: each emoji is one character
  const py = [...text]
  const start = py.join('').indexOf('Priya') - 2, end = start + 'Priya Raman'.length
  assert.equal(py.slice(start, end).join(''), 'Priya Raman')
  globalThis.fetch = async () => ({ ok: true, json: async () => ({ spans: [{ start, end, cat: 'name', text: 'Priya Raman', source: 'cloud-llm' }] }) })
  el('e-cloud').checked = true; el('e-cloud').fire('change')
  el('c-url').value = 'https://me--pii-redactor-web.modal.run'; el('c-url').fire('input')
  el('c-token').value = 'x'.repeat(32); el('c-token').fire('input')
  el('c-ack').checked = true; el('c-ack').fire('change')
  el('input').value = text
  el('cloudScan').fire('click')
  await tick(); await tick()
  const out = await redact(text)
  assert.equal(out, 'Hi 😀😀 from [NAME_1] today')
})

test('title + name stops at a possessive and never absorbs an all-caps word', async () => {
  const out = await redact("Ms. Raman's SSN on file. Dr. Lee DOB unknown. The SSN and MRN fields.")
  assert.ok(out.includes("'s SSN on file"), out)
  assert.ok(out.includes(' DOB unknown'), out)
  assert.ok(out.includes('The SSN and MRN fields.'), out)
  for (const s of ['Raman', 'Lee']) assert.ok(!out.includes(s), out)
})

test('title + full name and accented names still redact whole', async () => {
  const out = await redact("Ms. Priya Raman signed. Dr. Zoë Ångström's chart. Mr. O'Brien called.")
  for (const s of ['Priya', 'Raman', 'Zo', 'Ångström', 'Brien']) assert.ok(!out.includes(s), out)
  assert.ok(out.includes("'s chart"), out)
})

test('US phones with dashes are phones, not UK NHS numbers; real NHS numbers still found', async () => {
  const out = await redact('Call 212-555-0199 or 212.555.0199 or (212) 555-0199. NHS number 943 476 5919.')
  assert.equal(out, 'Call [PHONE_1] or [PHONE_2] or [PHONE_3]. NHS number [UK_NHS_1].')
})
