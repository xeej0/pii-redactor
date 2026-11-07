"""Quick checks for review.py: python3 cloud/test_review.py (no GPU or Modal needed)."""
import review

t = 'Call Linda Mei at (516) 712-4000.\nMILBER MAKRIS\nPLOUSADIS & SEIDEN, LLP; Plaintiff Mei.'
items = review.parse_items('<think>x</think> sure: {"items": [{"text": "516) 712-4000", "type": "phone"}, '
                           '{"text": "MILBER MAKRIS PLOUSADIS & SEIDEN, LLP", "type": "org"}, {"text": "Mei", "type": "name"}, '
                           '{"text": "Plaintiff", "type": "name"}, {"text": "Invented Person", "type": "name"}, {"text": "x", "type": "secret"}]}')
spans = review.locate(t, 10, items, ["phone", "org", "name"], "llm")
got = {(s["text"], s["cat"]) for s in spans}
assert ("(516) 712-4000", "phone") in got, got
assert ("MILBER MAKRIS\nPLOUSADIS & SEIDEN, LLP", "org") in got, got
assert sum(1 for s in spans if s["text"] == "Mei") == 2  # every mention
assert not any(s["text"] in ("Plaintiff", "Invented Person", "x") for s in spans)  # roles, inventions, other types
assert all(t[s["start"] - 10:s["end"] - 10] == s["text"] for s in spans)
# a reply cut off mid-way still yields the complete items
assert review.parse_items('{"items": [{"text": "Ann Lee", "type": "name"}, {"text": "Bob') == [("Ann Lee", "name")]
# chunks cover everything, overlap, and start on word boundaries
text = " ".join(f"word{i}" for i in range(3000))
cs = review.chunks(text, 1000, 100)
assert cs[0][0] == 0 and cs[-1][1] == len(text)
assert all(b2 > a2 and a2 < b1 for (a1, b1), (a2, b2) in zip(cs, cs[1:]))
assert all(a == 0 or text[a - 1] == " " for a, _ in cs)
print("review.py ok:", len(spans), "spans,", len(cs), "chunks")
