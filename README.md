# PII Redactor

Paste text (or drop a .txt/.csv/.md/.json/.log file) and get a copy with personal information removed.
Live at https://pii.xeej.app.

By default everything runs on your device. The page's Content Security Policy only allows network requests to this
site itself and to `*.modal.run`, which is used only by the optional Cloud GPU scan, after you set it up with your own
Modal account and press **Cloud scan**. See [cloud/README.md](cloud/README.md) for set-up, costs and privacy.

## How detection works

- **AI model (main engine):** [fastino/gliner2-privacy-filter-PII-multi](https://huggingface.co/fastino/gliner2-privacy-filter-PII-multi)
  (Apache-2.0), exported by `scripts/export_gliner2.py` to a 146 MB ONNX model served from `model/` and run with
  onnxruntime-web in a Web Worker. Labels are chosen at run time from the categories you tick (person, organization,
  company, law firm, street_address, city, postal_code, date_of_birth, passport_number, ...). Downloaded once, stored in
  the browser's Cache Storage, then works offline.
- **Rule backstop:** hand-written patterns (cards, SSNs, IBANs, phones, "LLP / P.C. / Inc." company names, ZIPs, ...)
  plus Microsoft Presidio's 52 English recognizers ported to JS (`presidio.js`, data from `scripts/build_presidio.py`).
- **Cloud GPU (optional, off by default):** the full GLiNER2 model plus an open LLM reviewer (Qwen3-14B) on your own
  Modal account. Sends the text to your Modal server and is billed to it; see `cloud/`.
- **Repeats:** once a name or company is found, its other mentions are redacted too, including a person's surname on
  its own (common English words from `common-words.js` are never spread).

## The model export

`scripts/export_gliner2.py` differs from the community okasi ONNX export:
labels are a run-time input (`schema_positions`), the vocabulary is pruned to Latin-script tokens (identical
tokenization for Latin-script text), word embeddings are 4-bit with fp16 group scales, and all weight MatMuls are
4-bit MatMulNBits. 479 MB becomes 142 MB; on our test texts it reproduces 58 of 62 entities found by the original
PyTorch model (the rest are borderline-confidence spans). `gliner2.js` ports gliner2 1.3.1's input preprocessing and
span decoding to JavaScript.

## Files

- `index.html`, `app.js`: page, rules, merging, repeats and redaction.
- `gliner2.js`, `worker.js`: the AI model in a Web Worker (download, checksum check, cache, inference).
- `model/g2pii-v1/`: the exported model in 24 MB pieces, `manifest.json` lists them with a SHA-256.
- `presidio.js`, `presidio-data.js`, `common-words.js` (wordfreq, CC BY-SA 4.0).
- `cloud/`: the optional Modal GPU server (`modal_app.py`, `review.py`, set-up guide).
- `vendor/`: onnxruntime-web 1.30.0 (MIT) and @huggingface/tokenizers 0.2.0 (Apache-2.0).

No build step: it's static files. Detection is never perfect; review the output before sharing.
