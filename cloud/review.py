"""Logic for the optional cloud scan: categories, chunking, the reviewer prompt, and
turning model output into character spans. Kept free of Modal and GPU imports so it
can be tested on any machine (see cloud/test_review.py)."""
import json
import re

# Category ids match app.js. Each has a plain description for the LLM reviewer and the
# GLiNER2 labels used for it (the same labels the in-browser model uses).
CATEGORIES = {
    "name": ("Names of people: full names, first or last names alone, initials with a surname, nicknames, signatures", ["person"]),
    "org": ("Companies and organizations: businesses, law firms, accounting firms, banks, hospitals, schools, agencies, "
            "including short or informal forms such as 'Mei CPA' or 'Acme'", ["organization", "company", "law firm"]),
    "address": ("Street addresses, including building numbers, suite, floor, apartment and PO boxes", ["street_address"]),
    "place": ("Cities, towns, counties, states, provinces and countries", ["city", "state_or_region", "country"]),
    "zip": ("ZIP codes and postcodes", ["postal_code"]),
    "phone": ("Phone and fax numbers", ["phone_number"]),
    "email": ("Email addresses", ["email"]),
    "date": ("Dates of any kind, including dates of birth", ["date", "date_of_birth"]),
    "ssn": ("Social security numbers and national ID numbers", ["national_id_number"]),
    "ids": ("Other identifying numbers: case or docket numbers, account, policy, claim, invoice, employee, patient, "
            "license, passport, tax and bank numbers", ["government_id", "passport_number", "drivers_license_number",
                                                        "tax_id", "account_number", "bank_account"]),
    "card": ("Payment card numbers", ["card_number"]),
    "iban": ("IBANs", ["iban"]),
    "username": ("Usernames and social media handles", ["username"]),
    "secret": ("Passwords, API keys and other secrets", ["password", "api_key"]),
    "ip": ("IP and MAC addresses", ["ip_address"]),
    "url": ("Web addresses (URLs)", ["url"]),
}

GLINER_LABEL_CAT = {lab: cat for cat, (_, labs) in CATEGORIES.items() for lab in labs}

MAX_ITEM_CHARS = 200
# Words the reviewer sometimes lists that should never be redacted on their own.
NEVER = {
    "plaintiff", "plaintiffs", "defendant", "defendants", "court", "the court", "company", "the company",
    "respondent", "petitioner", "claimant", "attorney", "attorneys", "counsel", "esq", "esq.", "inc", "inc.",
    "llc", "llp", "corp", "corp.", "i", "you", "he", "she", "they", "we", "it",
}


def chunks(text, size, overlap):
    """Split text into (start, end) windows of about `size` characters, cut at a line
    break or space where possible, overlapping by `overlap` characters."""
    n = len(text)
    out, start = [], 0
    while start < n:
        end = min(n, start + size)
        if end < n:
            cut = max(text.rfind("\n", start + size // 2, end), text.rfind(" ", start + size // 2, end))
            if cut > start:
                end = cut
        out.append((start, end))
        if end >= n:
            break
        start = max(start + 1, end - overlap)
        while start < end and not text[start - 1].isspace():  # begin on a word boundary
            start += 1
    return out


def system_prompt(cats):
    lines = "\n".join(f"- {c}: {CATEGORIES[c][0]}" for c in cats if c in CATEGORIES)
    return (
        "You find personal and identifying information in documents so it can be redacted before sharing.\n"
        "Be exhaustive: missing an item is far worse than listing an extra one. Read every line, including "
        "headers, signature blocks, captions, addresses and footers.\n"
        "Rules:\n"
        "1. Copy each item exactly as it appears in the text: same spelling, capitals and punctuation. "
        "Never rewrite, expand or fix an item.\n"
        "2. List each distinct string once. If a person also appears by last name only, list that too.\n"
        "3. Do not list generic roles or words such as Plaintiff, Defendant, Court, the Company, Esq.\n"
        "4. Only use these types:\n"
        f"{lines}\n"
        'Reply with JSON only, in this shape: {"items": [{"text": "...", "type": "..."}]}. '
        'If there is nothing, reply {"items": []}.'
    )


def user_prompt(chunk):
    return f"Find every item in this text.\n\n<text>\n{chunk}\n</text>"


_THINK = re.compile(r"<think>.*?</think>", re.S)
_PAIR = re.compile(r'"text"\s*:\s*"((?:[^"\\]|\\.)*)"\s*,\s*"type"\s*:\s*"([a-z_]+)"')


def parse_items(raw):
    """Read [(text, type)] from the model's reply. Tolerates extra prose and a reply
    that was cut off part way through."""
    s = _THINK.sub("", raw or "").strip()
    a, b = s.find("{"), s.rfind("}")
    if a >= 0 and b > a:
        try:
            data = json.loads(s[a:b + 1])
            items = data.get("items", []) if isinstance(data, dict) else data
            out = []
            for it in items if isinstance(items, list) else []:
                if isinstance(it, dict) and isinstance(it.get("text"), str) and isinstance(it.get("type"), str):
                    out.append((it["text"], it["type"].strip().lower()))
            return out
        except (json.JSONDecodeError, AttributeError):
            pass
    out = []
    for m in _PAIR.finditer(s):
        try:
            out.append((json.loads('"' + m.group(1) + '"'), m.group(2)))
        except json.JSONDecodeError:
            pass
    return out


def locate(text, base, items, cats, source):
    """Turn [(string, type)] into spans of `text` (offset by `base`). Strings that do
    not occur in the text are dropped, so the reviewer cannot invent anything."""
    allowed = set(cats)
    spans = []
    for s, typ in items:
        s = s.strip().strip('"').strip()
        if typ not in allowed or not s or len(s) > MAX_ITEM_CHARS or s.lower() in NEVER:
            continue
        if len(s) < 2 and not s.isdigit():
            continue
        pat = re.escape(s).replace(r"\ ", r"\s+")
        pat = (r"(?<![\w])" if s[0].isalnum() else "") + pat + (r"(?![\w])" if s[-1].isalnum() else "")
        found = list(re.finditer(pat, text))
        if not found:  # same words, different capitals or spacing
            found = list(re.finditer(pat, text, re.I))
        for m in found:
            a, b = m.start(), m.end()
            # the reviewer sometimes drops one bracket: "516) 712-4000" -> "(516) 712-4000"
            if a > 0 and text[a - 1] == "(" and text.count(")", a, b) > text.count("(", a, b):
                a -= 1
            if b < len(text) and text[b] == ")" and text.count("(", a, b) > text.count(")", a, b):
                b += 1
            spans.append({"start": base + a, "end": base + b, "cat": typ, "text": text[a:b], "source": source})
    return spans


def dedupe(spans):
    seen, out = set(), []
    for s in sorted(spans, key=lambda x: (x["start"], -x["end"])):
        k = (s["start"], s["end"], s["cat"], s["source"])
        if k not in seen:
            seen.add(k)
            out.append(s)
    return out


def scan(text, cats, threshold, gliner=None, chat=None):
    """Runs both cloud passes. `gliner` is a GLiNER2 model (or None to skip it) and
    `chat` takes a list of conversations and returns one reply string per conversation
    (or None to skip the LLM review). Returns spans plus timings in milliseconds."""
    import time

    t0 = time.perf_counter()
    cats = [c for c in cats if c in CATEGORIES]
    spans = []
    labels = [lab for c in cats for lab in CATEGORIES[c][1]]
    if gliner is not None and labels:
        for a, b in chunks(text, 1100, 150):
            r = gliner.extract_entities(text[a:b], labels, threshold=threshold, include_confidence=True, include_spans=True)
            for lab, vals in r.get("entities", {}).items():
                for v in vals:
                    spans.append({"start": a + v["start"], "end": a + v["end"], "cat": GLINER_LABEL_CAT.get(lab, "ids"),
                                  "text": v["text"], "source": "cloud-gliner", "score": round(float(v["confidence"]), 3)})
    t1 = time.perf_counter()
    if chat is not None and cats:
        parts = chunks(text, 5000, 400)
        sys_p = system_prompt(cats)
        replies = chat([[{"role": "system", "content": sys_p}, {"role": "user", "content": user_prompt(text[a:b])}] for a, b in parts])
        for (a, b), reply in zip(parts, replies):
            spans += locate(text[a:b], a, parse_items(reply), cats, "cloud-llm")
    t2 = time.perf_counter()
    return {"spans": dedupe(spans), "gliner_ms": round((t1 - t0) * 1000), "llm_ms": round((t2 - t1) * 1000)}
