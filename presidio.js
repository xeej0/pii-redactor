// Microsoft Presidio's pattern recognizers, running in the browser.
// Patterns, scores and context words come from presidio-data.js (generated from
// presidio-analyzer); the validators below are ports of Presidio's Python ones.
// Scoring follows Presidio: a validator returning true sets the score to 1,
// false drops the match, and a context word in the 5 words before a match adds
// 0.35 (with a floor of 0.4).
import DATA from './presidio-data.js'

const digits = (s) => s.replace(/\D/g, '')
const sanitize = (s, pairs = []) => pairs.reduce((t, [a, b]) => t.split(a).join(b), s)
const isDigits = (s) => /^\d+$/.test(s)

function luhn(d) {
  let sum = 0
  for (let i = 0; i < d.length; i++) {
    let n = +d[d.length - 1 - i]
    if (i % 2) { n *= 2; if (n > 9) n -= 9 }
    sum += n
  }
  return sum % 10 === 0
}

const VD = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
const VP = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
function verhoeff(s) {
  let c = 0
  const r = [...s].reverse().map(Number)
  for (let i = 0; i < r.length; i++) c = VD[c][VP[i % 8][r[i]]]
  return c === 0
}

function weighted(s, w) { let t = 0; for (let i = 0; i < w.length; i++) t += +s[i] * w[i]; return t }

// Small synchronous SHA-256, only used to check Bitcoin address checksums.
function sha256(bytes) {
  const K = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2])
  const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19])
  const len = bytes.length, total = ((len + 9 + 63) >> 6) << 6
  const m = new Uint8Array(total); m.set(bytes); m[len] = 0x80
  const dv = new DataView(m.buffer); dv.setUint32(total - 4, len * 8); dv.setUint32(total - 8, Math.floor(len / 0x20000000))
  const w = new Uint32Array(64), rot = (x, n) => (x >>> n) | (x << (32 - n))
  for (let o = 0; o < total; o += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4)
    for (let i = 16; i < 64; i++) w[i] = (rot(w[i-15],7) ^ rot(w[i-15],18) ^ (w[i-15] >>> 3)) + w[i-16] + (rot(w[i-2],17) ^ rot(w[i-2],19) ^ (w[i-2] >>> 10)) + w[i-7]
    let [a, b, c, d, e, f, g, h] = H
    for (let i = 0; i < 64; i++) {
      const t1 = (h + (rot(e,6) ^ rot(e,11) ^ rot(e,25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0
      const t2 = ((rot(a,2) ^ rot(a,13) ^ rot(a,22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h
  }
  const out = new Uint8Array(32), odv = new DataView(out.buffer)
  H.forEach((x, i) => odv.setUint32(i * 4, x))
  return out
}

function base58check(s) {
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  let n = 0n
  for (const ch of s) { const v = A.indexOf(ch); if (v < 0) return false; n = n * 58n + BigInt(v) }
  const bytes = []
  while (n > 0n) { bytes.unshift(Number(n & 255n)); n >>= 8n }
  for (const ch of s) { if (ch !== '1') break; bytes.unshift(0) }
  if (bytes.length < 5) return false
  const body = new Uint8Array(bytes.slice(0, -4)), chk = sha256(sha256(body))
  return bytes.slice(-4).every((b, i) => b === chk[i])
}

function bech32(s) {
  const C = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l', a = s.toLowerCase()
  if (s !== a && s !== s.toUpperCase()) return false
  const pos = a.lastIndexOf('1')
  if (pos < 1 || pos + 7 > a.length || a.length > 90) return false
  const hrp = a.slice(0, pos), data = []
  for (const ch of a.slice(pos + 1)) { const v = C.indexOf(ch); if (v < 0) return false; data.push(v) }
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
  let chk = 1
  for (const v of [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31), ...data]) {
    const b = chk >>> 25; chk = ((chk & 0x1ffffff) << 5) ^ v
    for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= G[i]
  }
  return chk === 1 || chk === 0x2bc830a3 // bech32 or bech32m
}

function ibanOk(s) {
  const t = s.toUpperCase()
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(t) || t.length < 15 || t.length > 34) return false
  const r = (t.slice(4) + t.slice(0, 4)).replace(/[A-Z]/g, (c) => c.charCodeAt(0) - 55)
  let m = 0
  for (const ch of r) m = (m * 10 + +ch) % 97
  return m === 1
}

function ipOk(s) {
  const t = s.replace(/\/\d+$/, '')
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return t.split('.').every((p) => +p <= 255 && !(p.length > 1 && p[0] === '0'))
  if (!t.includes(':')) return false
  const parts = t.split('::')
  if (parts.length > 2) return false
  const groups = parts.flatMap((p) => (p ? p.split(':') : []))
  const v4 = groups.length && groups[groups.length - 1].includes('.')
  if (v4 && !ipOk(groups.pop())) return false
  const max = v4 ? 6 : 8
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return false
  return parts.length === 2 ? groups.length < max : groups.length === max
}

function zaBirth(d) {
  const y = +d.slice(0, 2), mo = +d.slice(2, 4), da = +d.slice(4, 6), now = new Date()
  const year = (y > now.getFullYear() % 100 ? 1900 : 2000) + y
  const dt = new Date(year, mo - 1, da)
  return dt.getFullYear() === year && dt.getMonth() === mo - 1 && dt.getDate() === da && dt <= now
}

// validate(text, rec): true -> score 1, false -> drop, undefined -> keep score.
// invalidate(text, rec): true -> drop.
const V = {
  AbaRoutingRecognizer: { validate: (t, r) => { const s = sanitize(t, r.replace); return weighted(s, [3,7,1,3,7,1,3,7,1]) % 10 === 0 } },
  AuAbnRecognizer: { validate: (t, r) => { const d = [...sanitize(t, r.replace)].filter((c) => c.trim()).map(Number); d[0] -= 1; return weighted(d, [10,1,3,5,7,9,11,13,15,17,19]) % 89 === 0 } },
  AuAcnRecognizer: { validate: (t, r) => { const d = [...sanitize(t, r.replace)].filter((c) => c.trim()).map(Number); return (10 - (weighted(d, [8,7,6,5,4,3,2,1]) % 10)) % 10 === d[d.length - 1] } },
  AuMedicareRecognizer: { validate: (t, r) => { const d = [...sanitize(t, r.replace)].filter((c) => c.trim()).map(Number); return weighted(d, [1,3,7,9,1,3,7,9]) % 10 === d[8] } },
  AuTfnRecognizer: { validate: (t, r) => { const d = [...sanitize(t, r.replace)].filter((c) => c.trim()).map(Number); return weighted(d, [1,4,3,7,5,8,6,9,10]) % 11 === 0 } },
  CaSinRecognizer: { invalidate: (t) => !luhn(digits(t)) },
  CreditCardRecognizer: { validate: (t, r) => { const s = sanitize(t, r.replace); return isDigits(s) && luhn(s) } },
  CryptoRecognizer: { validate: (t) => (/^[13]/.test(t) ? base58check(t) : /^bc1/i.test(t) ? bech32(t) : false) },
  EmailRecognizer: { validate: (t) => /@[^@\s]+\.[a-z]{2,}$/i.test(t) },
  IbanRecognizer: { validate: (t, r) => ibanOk(sanitize(t, r.replace)), groups: true },
  InAadhaarRecognizer: { validate: (t, r) => { const s = sanitize(t, r.replace); return s.length === 12 && isDigits(s) && +s[0] >= 2 && verhoeff(s) && s !== [...s].reverse().join('') } },
  InGstinRecognizer: { validate: (t, r) => {
    const m = t.toUpperCase().match(/\b((?:0[1-9]|[1-3][0-7])[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z])\b/)
    const g = m ? m[1] : sanitize(t.toUpperCase(), r.replace)
    if (g.length !== 15 || !isDigits(g.slice(0, 2)) || +g.slice(0, 2) < 1 || +g.slice(0, 2) > 37) return false
    const pan = g.slice(2, 12)
    if ([...pan.slice(0, 5)].filter((c) => /[A-Z]/.test(c)).length < 3 || !isDigits(pan.slice(5, 9)) || !/[A-Z]/.test(pan[9])) return false
    return /[A-Z0-9]/.test(g[12]) && g[13] === 'Z' && /[A-Z0-9]/.test(g[14])
  } },
  IpRecognizer: { invalidate: (t) => !ipOk(t) },
  MacAddressRecognizer: { invalidate: (t) => { const c = t.replace(/[:.-]/g, ''); return !/^[0-9a-f]{12}$/i.test(c) || /^(f{12}|0{12})$/i.test(c) } },
  MedicalLicenseRecognizer: { validate: (t, r) => {
    const d = [...sanitize(t, r.replace).slice(2)].map(Number)
    if (d.some(isNaN) || !d.length) return false
    let c = -d.pop()
    const rev = d.reverse()
    rev.forEach((x, i) => { c += i % 2 === 0 ? 2 * x : x })
    return c % 10 === 0
  } },
  NgNinRecognizer: { validate: (t) => t.length === 11 && isDigits(t) && verhoeff(t) },
  NhsRecognizer: { validate: (t, r) => { const s = sanitize(t, r.replace); let tot = 0; for (let i = 0; i < Math.min(s.length, 11); i++) tot += +s[i] * (10 - i); return tot % 11 === 0 } },
  PhTinRecognizer: { invalidate: (t, r) => { const s = sanitize(t, r.replace); return !(isDigits(s) && (s.length === 9 || s.length === 12) && weighted(s, [9,8,7,6,5,4,3,2]) % 11 === +s[8]) } },
  UkDrivingLicenceRecognizer: { validate: (t) => { const s = t.toUpperCase().slice(0, 5); return s === '99999' || !/^[A-Z]+9*$/.test(s) ? false : undefined } },
  UkVehicleRegistrationRecognizer: { validate: (t, r) => {
    const s = sanitize(t, r.replace)
    if (s.length === 7 && /^[A-Za-z]{2}/.test(s) && isDigits(s.slice(2, 4))) { const a = +s.slice(2, 4); return (a >= 2 && a <= 29) || (a >= 51 && a <= 79) }
    return undefined
  } },
  UsNpiRecognizer: {
    validate: (t, r) => { const s = sanitize(t, r.replace); return isDigits(s) && luhn('80840' + s) },
    invalidate: (t, r) => { const s = sanitize(t, r.replace), body = s.length > 1 ? s.slice(0, -1) : s; return !!body && new Set(body).size === 1 },
  },
  UsSsnRecognizer: { invalidate: (t) => {
    if (new Set([...t].filter((c) => '.- '.includes(c))).size > 1) return true
    const d = digits(t)
    return new Set(d).size === 1 || d.slice(3, 5) === '00' || d.slice(5) === '0000' || ['000', '666'].includes(d.slice(0, 3)) || ['123456789', '987654320', '078051120'].includes(d)
  } },
  UuidRecognizer: { invalidate: (t, r) => {
    const c = r.consts
    if (t.toLowerCase() === c.NIL_UUID) return true
    const g = t.split('-')
    if (g.length !== 5 || g.some((x) => !x)) return true
    return !c.VALID_VERSIONS.includes(g[2][0].toLowerCase()) || !c.VALID_VARIANT_PREFIXES.includes(g[3][0].toLowerCase())
  } },
  ZaCompanyRegistrationRecognizer: { validate: (t, r) => {
    const s = t.toUpperCase(), p = s.split('/'), yr = new Date().getFullYear()
    if (p.length === 3 && isDigits(p[0])) return p.every(isDigits) && p[0].length === 4 && p[1].length === 6 && p[2].length === 2 && +p[0] >= 1800 && +p[0] <= yr
    if (p.length === 2) {
      if (!isDigits(p[1]) || p[1].length !== 6) return false
      for (const pre of [...r.consts.LEGACY_PREFIXES].sort((a, b) => b.length - a.length)) {
        if (p[0].startsWith(pre)) { const y = p[0].slice(pre.length); return y.length === 4 && isDigits(y) && +y >= 1800 && +y <= yr }
      }
    }
    return false
  } },
  ZaIdNumberRecognizer: { validate: (t, r) => t.length === 13 && isDigits(t) && zaBirth(t.slice(0, 6)) && r.consts.ALLOWED_CITIZENSHIP_VALUES.includes(t[10]) && r.consts.ALLOWED_LEGACY_RACE_VALUES.includes(t[11]) && luhn(t) },
  ZaIncomeTaxNumberRecognizer: { validate: (t, r) => t.length === 10 && isDigits(t) && r.consts.ALLOWED_LEADING_DIGITS.includes(t[0]) },
  ZaPassportRecognizer: { validate: (t, r) => { const s = t.toUpperCase(); return s.length === 9 && r.consts.ALLOWED_PREFIXES.includes(s[0]) && isDigits(s.slice(1)) } },
  ZaVatNumberRecognizer: { validate: (t, r) => t.length === 10 && isDigits(t) && t.startsWith(r.consts.VAT_PREFIX) },
}

const RECS = DATA.map((r) => ({
  ...r,
  v: V[r.cls] || {},
  patterns: r.patterns.map((p) => {
    let re = null
    try { re = new RegExp(p.re, 'gms' + (p.i ? 'i' : '') + 'd') } catch { /* unsupported in JS, skip */ }
    return { ...p, re }
  }).filter((p) => p.re),
  ctx: r.context.map((c) => c.toLowerCase()),
}))

export const ENTITIES = RECS.map((r) => r.entity)

function contextBefore(text, start) {
  const words = text.slice(Math.max(0, start - 200), start).toLowerCase().match(/[\p{L}\p{N}#'_-]+/gu) || []
  return words.slice(-5)
}

function scoreMatch(rec, t) {
  if (rec.v.invalidate?.(t, rec)) return 0
  const v = rec.v.validate ? rec.v.validate(t, rec) : undefined
  return v === undefined ? null : v ? 1 : 0
}

// Returns [{start, end, text, entity, score}] for matches scoring >= threshold.
export function analyze(text, { threshold = 0.4, context = true, dedupe = true } = {}) {
  const res = []
  for (const rec of RECS) {
    const mine = []
    for (const p of rec.patterns) {
      p.re.lastIndex = 0
      for (const m of text.matchAll(p.re)) {
        if (!m[0]) continue
        const start = m.index
        // IbanRecognizer tries the regex groups from last to first (trims trailing junk)
        const ends = rec.v.groups ? [...m.indices.slice(1).reverse().map((ix) => (ix && ix[1] > 0 ? ix[1] : start + m[0].length)), start + m[0].length] : [start + m[0].length]
        for (const end of ends) {
          const t = text.slice(start, end)
          if (!t) continue
          const v = scoreMatch(rec, t)
          if (v === 0) continue
          let score = v ?? p.score
          if (context && score < 1 && rec.ctx.length) {
            const before = contextBefore(text, start)
            if (rec.ctx.some((c) => before.some((w) => w.includes(c)))) score = Math.max(Math.min(1, score + 0.35), 0.4)
          }
          if (score >= threshold) mine.push({ start, end, text: t, entity: rec.entity, score })
          break
        }
      }
    }
    // Presidio drops a recognizer's matches that sit inside a better one of its own
    mine.sort((a, b) => b.score - a.score || (b.end - b.start) - (a.end - a.start))
    for (const r of mine) if (!res.some((k) => k.entity === r.entity && r.start >= k.start && r.end <= k.end)) res.push(r)
  }
  if (!dedupe) return res
  // Like Presidio's result de-duplication: drop matches contained in a better one
  res.sort((a, b) => b.score - a.score || (b.end - b.start) - (a.end - a.start))
  const keep = []
  for (const r of res) if (!keep.some((k) => r.start >= k.start && r.end <= k.end)) keep.push(r)
  return keep.sort((a, b) => a.start - b.start)
}
