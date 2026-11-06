// GLiNER2 PII model (okasi/gliner2-privacy-filter-pii-multi-onnx) in JavaScript.
// A port of gliner2 1.3.1's SchemaTransformer preprocessing and the export's
// span decoding, so the ONNX graph can run with no Python. Works in browsers
// and Node: pass in a tokenizers.js Tokenizer and an onnxruntime InferenceSession.

export const LABELS = ['name', 'address', 'email', 'phone_num', 'id_num', 'url', 'username']
export const SCHEMA_POSITIONS = [1, 6, 8, 10, 12, 16, 21, 24] // baked into the export
const MAX_WIDTH = 8 // longest entity, in words
const CHUNK_WORDS = 256 // words per model call; long texts are processed in overlapping windows
const OVERLAP = 32

// gliner2 WhitespaceTokenSplitter (applied to lowercased text)
const WORD_RE = /(?:https?:\/\/[^\s]+|www\.[^\s]+)|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|@[a-z0-9_]+|[\p{L}\p{N}\p{M}_]+(?:[-_][\p{L}\p{N}\p{M}_]+)*|\S/giu

export function splitWords(text) {
  const words = []
  for (const m of text.toLowerCase().matchAll(WORD_RE)) words.push([m[0], m.index, m.index + m[0].length])
  return words
}

export class Gliner2 {
  constructor(tokenizer, session, ort) {
    this.tok = tokenizer
    this.session = session
    this.ort = ort
    this.cache = new Map()
    const schema = ['(', '[P]', 'entities', '(']
    for (const l of LABELS) schema.push('[E]', l)
    schema.push(')', ')', '[SEP_TEXT]')
    this.prefix = []
    const special = new Set(['[P]', '[E]', '[SEP_TEXT]'])
    for (const t of schema) this.prefix.push(...(special.has(t) ? [this.tok.token_to_id(t)] : this.ids(t)))
    const got = []
    const sp = new Set([this.tok.token_to_id('[P]'), this.tok.token_to_id('[E]')])
    this.prefix.forEach((id, i) => sp.has(id) && got.push(i))
    if (got.join() !== SCHEMA_POSITIONS.join()) throw new Error('GLiNER2 schema mismatch: ' + got.join())
  }

  ids(word) {
    let v = this.cache.get(word)
    if (!v) {
      v = this.tok.encode(word, { add_special_tokens: false }).ids
      if (this.cache.size > 50000) this.cache.clear()
      this.cache.set(word, v)
    }
    return v
  }

  async runChunk(text, words, threshold) {
    const inputIds = [...this.prefix]
    const firstPos = []
    for (const [w] of words) {
      const ids = this.ids(w)
      if (!ids.length) continue
      firstPos.push(inputIds.length)
      inputIds.push(...ids)
    }
    const kept = words.filter(([w]) => this.ids(w).length)
    const n = kept.length
    if (!n) return []
    const T = this.ort.Tensor
    const i64 = (a) => BigInt64Array.from(a, (x) => BigInt(x))
    const out = await this.session.run({
      input_ids: new T('int64', i64(inputIds), [1, inputIds.length]),
      attention_mask: new T('int64', i64(inputIds.map(() => 1)), [1, inputIds.length]),
      text_word_indices: new T('int64', i64(firstPos), [1, n]),
      text_word_counts: new T('int64', i64([n]), [1]),
    })
    const count = out.count_logits.data
    let best = 0
    for (let i = 1; i < count.length; i++) if (count[i] > count[best]) best = i
    if (best <= 0) return []
    const [, L, W, K] = out.span_scores.dims
    const s = out.span_scores.data
    const ents = []
    for (let l = 0; l < L; l++) {
      const spans = []
      for (let st = 0; st < Math.min(n, W); st++) {
        for (let k = 0; k < K; k++) {
          const sc = s[(l * W + st) * K + k]
          if (sc < threshold || st + k >= n) continue
          const cs = kept[st][1], ce = kept[st + k][2]
          if (!text.slice(cs, ce).trim()) continue
          spans.push({ start: cs, end: ce, score: sc })
        }
      }
      spans.sort((a, b) => b.score - a.score)
      const sel = []
      for (const c of spans) if (!sel.some((x) => c.start < x.end && c.end > x.start)) sel.push(c)
      for (const c of sel) ents.push({ ...c, label: LABELS[l], text: text.slice(c.start, c.end) })
    }
    return ents
  }

  // Returns [{start, end, text, label, score}] with character offsets into `text`.
  async predict(text, { threshold = 0.5, onProgress } = {}) {
    // gliner2 appends a period when the text doesn't end with one
    const t = /[.!?]$/.test(text) ? text : text + '.'
    const words = splitWords(t)
    const all = []
    const step = CHUNK_WORDS - OVERLAP
    const total = Math.max(1, Math.ceil(Math.max(0, words.length - OVERLAP) / step))
    for (let i = 0, c = 0; i < words.length; i += step, c++) {
      all.push(...(await this.runChunk(t, words.slice(i, i + CHUNK_WORDS), threshold)))
      onProgress?.(Math.min(1, (c + 1) / total))
      if (i + CHUNK_WORDS >= words.length) break
    }
    // merge chunk overlaps: keep the best-scoring span per region
    all.sort((a, b) => b.score - a.score)
    const keep = []
    for (const e of all) if (!keep.some((k) => e.start < k.end && e.end > k.start)) keep.push(e)
    return keep.filter((e) => e.end <= text.length).sort((a, b) => a.start - b.start)
  }
}

export { MAX_WIDTH }
