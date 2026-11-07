// GLiNER2 PII model (fastino/gliner2-privacy-filter-PII-multi) in JavaScript.
// A port of gliner2 1.3.1's SchemaTransformer preprocessing and span decoding, for the
// export made by scripts/export_gliner2.py, where labels are chosen at run time.
// Works in browsers and Node: pass in a tokenizers.js Tokenizer, an onnxruntime
// InferenceSession and the onnxruntime module.

const CHUNK_WORDS = 200 // words per model call; long texts are processed in overlapping windows
const OVERLAP = 30

// gliner2 WhitespaceTokenSplitter (applied to lowercased text)
const WORD_RE = /(?:https?:\/\/[^\s]+|www\.[^\s]+)|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|@[a-z0-9_]+|[\p{L}\p{N}\p{M}_]+(?:[-_][\p{L}\p{N}\p{M}_]+)*|\S/giu

export function splitWords(text) {
  const words = []
  for (const m of text.toLowerCase().matchAll(WORD_RE)) words.push([m[0], m.index, m.index + m[0].length])
  return words
}

export class Gliner2 {
  constructor(tokenizer, session, ort, labels) {
    this.tok = tokenizer
    this.session = session
    this.ort = ort
    this.cache = new Map()
    this.setLabels(labels)
  }

  // Builds "( [P] entities ( [E] label1 [E] label2 ... ) ) [SEP_TEXT]" exactly as gliner2 does.
  setLabels(labels) {
    this.labels = [...labels]
    const special = (t) => this.tok.token_to_id(t)
    const ids = [...this.ids('('), special('[P]'), ...this.ids('entities'), ...this.ids('(')]
    const positions = [ids.indexOf(special('[P]'))]
    for (const l of this.labels) {
      positions.push(ids.length)
      ids.push(special('[E]'), ...this.ids(l))
    }
    ids.push(...this.ids(')'), ...this.ids(')'), special('[SEP_TEXT]'))
    this.prefix = ids
    this.positions = positions
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
    const kept = []
    for (const w of words) {
      const ids = this.ids(w[0])
      if (!ids.length) continue
      firstPos.push(inputIds.length)
      inputIds.push(...ids)
      kept.push(w)
    }
    const n = kept.length
    if (!n) return []
    const T = this.ort.Tensor
    const i64 = (a) => BigInt64Array.from(a, (x) => BigInt(x))
    const out = await this.session.run({
      input_ids: new T('int64', i64(inputIds), [1, inputIds.length]),
      attention_mask: new T('int64', i64(inputIds.map(() => 1)), [1, inputIds.length]),
      text_word_indices: new T('int64', i64(firstPos), [1, n]),
      schema_positions: new T('int64', i64(this.positions), [1, this.positions.length]),
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
      for (const c of sel) ents.push({ ...c, label: this.labels[l], text: text.slice(c.start, c.end) })
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
    // chunks overlap: keep the best-scoring span per label and region
    all.sort((a, b) => b.score - a.score)
    const keep = []
    for (const e of all) if (!keep.some((k) => k.label === e.label && e.start < k.end && e.end > k.start)) keep.push(e)
    return keep.filter((e) => e.end <= text.length).sort((a, b) => a.start - b.start)
  }
}
