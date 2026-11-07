# Cloud scan on your own Modal account (optional)

The website works entirely on your device. This folder adds an optional, stronger second pass that runs on a GPU
you rent from [Modal](https://modal.com):

- the full-precision GLiNER2 PII model (the browser uses a compressed copy), and
- an open LLM, [Qwen3-14B (FP8)](https://huggingface.co/Qwen/Qwen3-14B-FP8) (Apache-2.0), that rereads each part of
  the document and lists every name, company, address, number and other identifier it finds.

Anything the LLM lists that doesn't appear word for word in your text is thrown away, so it can't invent redactions.
The page merges cloud results with the on-device results; cloud finds are highlighted in purple.

## What it costs

Modal bills per second of GPU time. An L40S costs about $0.000542 per second (about $1.95 an hour); check
[modal.com/pricing](https://modal.com/pricing) for current rates.

- A one-off scan: about 5 to 15 cents. Most of that is the GPU starting (1 to 3 minutes) and staying ready for
  2 minutes afterwards in case you scan again.
- More scans while the GPU is warm: about 1 cent each for a few pages.
- Modal's free plan includes monthly credit, which covers a few hundred one-off scans.

Built-in limits: at most one GPU at a time, 120 scans an hour, 300,000 characters per scan, and the GPU shuts down
after 2 idle minutes.

## Set-up (about 10 minutes)

1. Install Modal's command-line tool and log in:

   ```bash
   pip install modal
   ```

   ```bash
   modal setup
   ```

2. Make a random access token and store it in Modal as a secret. Keep a copy; you'll paste it into the website.

   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

   ```bash
   modal secret create pii-redactor-auth PII_TOKEN=paste-the-token-here
   ```

3. Copy the model weights into a Modal volume (about 16 GB, runs on a CPU, takes 5 to 10 minutes):

   ```bash
   cd cloud && modal run modal_app.py::download
   ```

4. Deploy:

   ```bash
   cd cloud && modal deploy modal_app.py
   ```

   It prints a URL ending in `-web.modal.run`, for example `https://your-name--pii-redactor-web.modal.run`.

5. On https://pii.xeej.app tick **Cloud GPU**, paste the URL and token, tick the confirmation box and press
   **Test connection** (free, it doesn't start the GPU). Then use **Cloud scan** under the result.

Optional check from the terminal, which runs one scan of a made-up sample (one GPU start, a few cents):

```bash
cd cloud && modal run modal_app.py
```

If you host the page somewhere else, deploy with `PII_ORIGINS=https://your-site.example modal deploy modal_app.py`
so the server accepts requests from it.

Other settings, as environment variables when deploying: `PII_LLM_MODEL` (another Hugging Face model; run the
download step again), `PII_GPU` (for example `A100-40GB`), `PII_IDLE_SECONDS` (default 120).

## Privacy: what Modal can see

- Your text travels over HTTPS to Modal and is processed in memory on their machines, which run on large cloud
  providers. Modal (and those providers) handle it while it runs, the same as any cloud service.
- This code never prints, logs or saves the text. The GPU container runs with outbound network access blocked
  (`block_network=True`) and loads the models from the volume, so nothing inside it can send your text elsewhere.
  vLLM and Hugging Face usage statistics are turned off.
- Requests pass through Modal's input queue between the web front door and the GPU. Modal says customer data is
  removed after processing; see [Security and privacy at Modal](https://modal.com/docs/guide/security).
- Modal has a SOC 2 Type II report. It does not offer blanket HIPAA certification: for medical records you need
  their Enterprise plan with a signed Business Associate Agreement before sending any.
- Only someone with your token can use the endpoint. Requests without it are rejected by a small CPU container
  before any GPU starts, and only requests from pii.xeej.app are allowed by the browser.

If a document must never leave your device, leave Cloud GPU off. The on-device AI and rules don't send anything.

## Files

- `modal_app.py`: the Modal app (web front door, GPU scanner, weight download, smoke test).
- `review.py`: chunking, the reviewer prompt, and turning model replies into spans. No Modal imports.
- `test_review.py`: quick checks for `review.py` (`python3 cloud/test_review.py`).
