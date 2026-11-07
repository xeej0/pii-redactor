"""Optional cloud scan for PII Redactor, on your own Modal account.

Two parts:
  * `web`: a small CPU-only front door. It checks your secret token and the page's
    origin before anything else, so stray or unauthorised requests never start a GPU.
  * `Scanner`: a GPU container (L40S) running the full-precision GLiNER2 PII model and
    an open LLM (Qwen3-14B, FP8) that reads the text as a careful second reviewer.
    It runs with outbound network access blocked and reads the model weights from a
    Modal Volume, so text can't be sent anywhere from inside it.

Nothing here logs or stores the text. See cloud/README.md for set-up and costs.
"""
import os

import modal

import review

APP_NAME = "pii-redactor"
LLM_MODEL = os.environ.get("PII_LLM_MODEL", "Qwen/Qwen3-14B-FP8")
GLINER_MODEL = "fastino/gliner2-privacy-filter-PII-multi"
GPU = os.environ.get("PII_GPU", "L40S")
ORIGINS = os.environ.get("PII_ORIGINS", "https://pii.xeej.app")
IDLE_SECONDS = int(os.environ.get("PII_IDLE_SECONDS", "120"))  # GPU stays up this long after a scan
MAX_CHARS = 300_000  # about 100 pages per scan
BLOCK_NETWORK = os.environ.get("PII_BLOCK_NETWORK", "1") == "1"

app = modal.App(APP_NAME)
weights = modal.Volume.from_name("pii-redactor-weights", create_if_missing=True)
QUIET = {
    "HF_HOME": "/weights/hf",
    "HF_HUB_DISABLE_TELEMETRY": "1",
    "DO_NOT_TRACK": "1",
    "VLLM_NO_USAGE_STATS": "1",
    "VLLM_LOGGING_LEVEL": "WARNING",
    "TOKENIZERS_PARALLELISM": "false",
}

gpu_image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("vllm==0.30.0", "transformers==5.17.0", "gliner2==1.3.1", "huggingface_hub==1.33.0")
    .env({**QUIET, "HF_HUB_OFFLINE": "1"})  # weights come from the volume, never fetched at scan time
    .add_local_python_source("review")
)
download_image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("huggingface_hub==1.33.0")
    .env(QUIET)
    .add_local_python_source("review")
)
web_image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("fastapi[standard]==0.115.12")
    .env({"PII_ORIGINS": ORIGINS})
    .add_local_python_source("review")
)


@app.function(image=download_image, volumes={"/weights": weights}, timeout=3600)
def download():
    """One-time: copy the model weights into the volume (CPU only, no GPU charges)."""
    from huggingface_hub import snapshot_download

    for repo in (LLM_MODEL, GLINER_MODEL):
        snapshot_download(repo, ignore_patterns=["*.pt", "*.bin", "original/*"] if repo == LLM_MODEL else None)
        print("cached", repo)
    weights.commit()


@app.cls(
    image=gpu_image,
    gpu=GPU,
    volumes={"/weights": weights},
    scaledown_window=IDLE_SECONDS,
    timeout=900,
    max_containers=1,  # caps spending: never more than one GPU at a time
    block_network=BLOCK_NETWORK,
)
class Scanner:
    @modal.enter()
    def load(self):
        from gliner2 import GLiNER2
        from vllm import LLM

        self.llm = LLM(model=LLM_MODEL, max_model_len=12288, gpu_memory_utilization=0.82,
                       enable_prefix_caching=True, disable_log_stats=True)
        self.gliner = GLiNER2.from_pretrained(GLINER_MODEL, device="cuda")

    @modal.method()
    def scan(self, text: str, cats: list, threshold: float = 0.35, use_llm: bool = True) -> dict:
        from vllm import SamplingParams

        params = SamplingParams(temperature=0, max_tokens=3000)

        def chat(convs):
            outs = self.llm.chat(convs, params, use_tqdm=False, chat_template_kwargs={"enable_thinking": False})
            return [o.outputs[0].text for o in outs]

        r = review.scan(text, cats, threshold, self.gliner, chat if use_llm else None)
        r["model"] = LLM_MODEL if use_llm else None
        return r


@app.function(image=web_image, secrets=[modal.Secret.from_name("pii-redactor-auth")], scaledown_window=60, max_containers=1)
@modal.concurrent(max_inputs=8)
@modal.asgi_app()
def web():
    import hmac
    import time

    from fastapi import FastAPI, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware

    token = os.environ["PII_TOKEN"].encode()
    if len(token) < 24:
        raise RuntimeError("PII_TOKEN must be at least 24 characters")
    recent = []  # scan times, for a simple rate limit if the token ever leaks

    api = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    api.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in os.environ["PII_ORIGINS"].split(",") if o.strip()],
                       allow_methods=["POST"], allow_headers=["authorization", "content-type"], max_age=3600)

    def check(req: Request):
        got = req.headers.get("authorization", "").removeprefix("Bearer ").strip().encode()
        if not hmac.compare_digest(got, token):
            raise HTTPException(401, "Wrong or missing access token")

    @api.post("/check")
    async def check_token(req: Request):
        check(req)  # does not start the GPU
        return {"ok": True, "model": LLM_MODEL, "gpu": GPU, "idle_seconds": IDLE_SECONDS}

    @api.post("/scan")
    async def scan(req: Request):
        check(req)
        now = time.time()
        recent[:] = [t for t in recent if now - t < 3600]
        if len(recent) >= 120:
            raise HTTPException(429, "More than 120 scans in the last hour; try again later")
        body = await req.json()
        text, cats = body.get("text"), body.get("cats")
        if not isinstance(text, str) or not text.strip():
            raise HTTPException(400, "No text")
        if len(text) > MAX_CHARS:
            raise HTTPException(413, f"Text is longer than {MAX_CHARS:,} characters")
        if not isinstance(cats, list) or not all(isinstance(c, str) for c in cats):
            raise HTTPException(400, "cats must be a list of category ids")
        threshold = min(0.9, max(0.1, float(body.get("threshold", 0.35))))
        recent.append(now)
        return await Scanner().scan.remote.aio(text, [c for c in cats if c in review.CATEGORIES], threshold, bool(body.get("llm", True)))

    return api


@app.local_entrypoint()
def smoke():
    """`modal run cloud/modal_app.py`: scans a made-up sample once, to check the set-up."""
    sample = ("Defendant Acme Widgets, Inc., by its attorneys, HARTWELL BRENNAN & COLE, LLP, responds. "
              "Information provided by Priya Raman, CFO. Daniel Okafor, Esq., 44 South Broadway, Suite 1100, "
              "White Plains, New York 10601, (914) 555-0142. Ms. Raman confirmed.")
    r = Scanner().scan.remote(sample, list(review.CATEGORIES), 0.35, True)
    for s in r["spans"]:
        print(f'{s["source"]:13} {s["cat"]:8} {s["text"]}')
    print(f'GLiNER2 {r["gliner_ms"]} ms, LLM {r["llm_ms"]} ms')
