"""Export fastino/gliner2-privacy-filter-PII-multi to a compact ONNX model for the browser.

    pip install "gliner2==1.3.1" torch onnx onnx_ir onnxruntime regex
    python scripts/export_gliner2.py OUT_DIR

Differences from the ready-made okasi ONNX export:
  * Labels are chosen at run time: the schema prompt is built in JavaScript and the
    positions of its [P]/[E] tokens are a model input (schema_positions).
  * Vocabulary pruned to Latin/common-script tokens (250k -> ~137k). Text in those
    scripts tokenizes exactly as before; other scripts become [UNK].
  * Word embeddings stored as int8 with a per-row scale; other MatMuls 4-bit (MatMulNBits).
Writes model.onnx, tokenizer.json, tokenizer_config.json to OUT_DIR.
"""
import json, os, sys, copy
import regex
import torch
import torch.nn as nn
from gliner2 import GLiNER2

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
REPO = "fastino/gliner2-privacy-filter-PII-multi"
model = GLiNER2.from_pretrained(REPO).eval()
tok = model.processor.tokenizer

# ---- vocabulary pruning ----
from huggingface_hub import hf_hub_download
tj = json.load(open(hf_hub_download(REPO, "tokenizer.json")))
vocab = tj["model"]["vocab"]
ok = regex.compile(r"^[\p{Script=Latin}\p{Script=Common}\p{Script=Inherited}▁]*$")
special_ids = {t["id"] for t in tj["added_tokens"]}
keep = [i for i, (p, _) in enumerate(vocab) if ok.match(p) or i in special_ids]
added = sorted(t["id"] for t in tj["added_tokens"] if t["id"] >= len(vocab))
old_ids = keep + added
remap = {o: n for n, o in enumerate(old_ids)}
new_tj = copy.deepcopy(tj)
new_tj["model"]["vocab"] = [vocab[i] for i in keep]
new_tj["model"]["unk_id"] = remap[tj["model"]["unk_id"]]
for t in new_tj["added_tokens"]:
    t["id"] = remap[t["id"]]
for key in ("post_processor",):
    pp = new_tj.get(key)
    if pp and "special_tokens" in pp:
        for v in pp["special_tokens"].values():
            v["ids"] = [remap[i] for i in v["ids"]]
json.dump(new_tj, open(os.path.join(OUT, "tokenizer.json"), "w"), ensure_ascii=False)
cfg = json.load(open(hf_hub_download(REPO, "tokenizer_config.json")))
json.dump(cfg, open(os.path.join(OUT, "tokenizer_config.json"), "w"), indent=1)
print("vocab", len(vocab) + len(added), "->", len(old_ids))

# ---- 4-bit word embeddings (groups of 32 values share an fp16 scale) ----
EMB_BITS = int(os.environ.get("EMB_BITS", "4"))
W = model.encoder.embeddings.word_embeddings.weight.detach()[torch.tensor(old_ids)].float()
V, D = W.shape
G = 32
Wg = W.view(V, D // G, G)
if EMB_BITS == 4:
    scale = (Wg.abs().amax(dim=2, keepdim=True) / 7).clamp(min=1e-8)
    q = (torch.round(Wg / scale).clamp(-8, 7) + 8).to(torch.uint8).view(V, D)   # 0..15
    packed = (q[:, 0::2] | (q[:, 1::2] << 4)).contiguous()                      # (V, D/2)
else:
    scale = (Wg.abs().amax(dim=2, keepdim=True) / 127).clamp(min=1e-8)
    packed = torch.round(Wg / scale).to(torch.int8).view(V, D)

class QEmbedding(nn.Module):
    def __init__(self, packed, scale):
        super().__init__()
        self.register_buffer("p", packed)
        self.register_buffer("s", scale.squeeze(-1).half())                       # (V, D/G)
    def forward(self, ids):
        flat = ids.reshape(-1)
        n = flat.shape[0]
        sc = self.s.index_select(0, flat).float().unsqueeze(2).expand(n, D // G, G).reshape(n, D)
        if EMB_BITS == 4:
            b = self.p.index_select(0, flat).to(torch.int32)                       # (n, D/2)
            hi = torch.div(b, 16, rounding_mode="floor")
            lo = b - hi * 16
            v = torch.stack([lo, hi], dim=2).reshape(n, D).float() - 8.0
        else:
            v = self.p.index_select(0, flat).float()
        return (v * sc).reshape(ids.shape[0], ids.shape[1], D)

model.encoder.embeddings.word_embeddings = QEmbedding(packed, scale)

# ---- export wrapper (entity extraction only, single sample) ----
class Entities(nn.Module):
    def __init__(self, m):
        super().__init__()
        self.m = m
    def forward(self, input_ids, attention_mask, text_word_indices, schema_positions):
        m = self.m
        h = m.encoder(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state[0]
        words = h.index_select(0, text_word_indices[0])          # (W, D)
        schema = h.index_select(0, schema_positions[0])          # (1+L, D)
        count_logits = m.count_pred(schema[0:1])                 # (1, 20)
        pc = schema[1:]                                          # (L, D)
        L, D = pc.shape
        pos = m.count_embed.pos_embedding.weight[0:1].unsqueeze(1).expand(1, L, D)
        out = m.count_embed.gru(pos, pc)                         # (1, L, D): first count step
        proj = m.count_embed.projector(torch.cat([out, pc.unsqueeze(0).expand_as(out)], dim=-1))
        n = words.shape[0]
        K = m.max_width
        starts = torch.arange(n).unsqueeze(1).expand(-1, K)
        ends = starts + torch.arange(K).unsqueeze(0)
        valid = ends < n
        s = torch.where(valid, starts, torch.zeros_like(starts)).reshape(-1)
        e = torch.where(valid, ends, torch.zeros_like(ends)).reshape(-1)
        spans = torch.stack([s, e], dim=-1).unsqueeze(0)
        span_rep = m.span_rep(words.unsqueeze(0), spans)[0]      # (W, K, D)
        scores = torch.sigmoid(torch.einsum("lkd,bpd->bplk", span_rep, proj))  # (1, L, W, K)
        return count_logits, scores

wrap = Entities(model).eval()
ex = (torch.tensor([[5, 6, 7, 8, 9, 10]]), torch.ones(1, 6, dtype=torch.long), torch.tensor([[3, 4, 5]]), torch.tensor([[1, 2]]))
fp32 = os.path.join(OUT, "model_fp32.onnx")
torch.onnx.export(
    wrap, ex, fp32, opset_version=17, dynamo=False,
    input_names=["input_ids", "attention_mask", "text_word_indices", "schema_positions"],
    output_names=["count_logits", "span_scores"],
    dynamic_axes={"input_ids": {1: "seq"}, "attention_mask": {1: "seq"}, "text_word_indices": {1: "words"},
                  "schema_positions": {1: "labels"}, "span_scores": {1: "labels", 2: "words"}},
)
print("exported fp32")

# ---- 4-bit MatMuls ----
import onnx
from onnx import helper, numpy_helper
from onnxruntime.quantization.matmul_nbits_quantizer import MatMulNBitsQuantizer, DefaultWeightOnlyQuantConfig
m = onnx.load(fp32)
inits = {t.name: t for t in m.graph.initializer}
# Gemm(A, W, b, transB=1) -> MatMul(A, W^T) + b, so the quantizer can handle it
nodes = []
for n in m.graph.node:
    attrs = {a.name: helper.get_attribute_value(a) for a in n.attribute}
    if n.op_type == "Gemm" and n.input[1] in inits and attrs.get("alpha", 1.0) == 1.0 and attrs.get("beta", 1.0) == 1.0 and not attrs.get("transA", 0):
        w = numpy_helper.to_array(inits[n.input[1]])
        if attrs.get("transB", 0):
            w = w.T
        wt = numpy_helper.from_array(w.copy(), n.input[1] + "_mm")
        m.graph.initializer.append(wt); inits[wt.name] = wt
        mid = n.output[0] + "_mm"
        nodes.append(helper.make_node("MatMul", [n.input[0], wt.name], [mid] if len(n.input) > 2 else [n.output[0]]))
        if len(n.input) > 2:
            nodes.append(helper.make_node("Add", [mid, n.input[2]], [n.output[0]]))
    else:
        nodes.append(n)
del m.graph.node[:]
m.graph.node.extend(nodes)
# Shared weights reach some MatMuls through Identity nodes: point those MatMuls at the weight itself
alias = {n.output[0]: n.input[0] for n in m.graph.node if n.op_type == "Identity" and n.input[0] in inits}
for n in m.graph.node:
    for i, x in enumerate(n.input):
        if x in alias:
            n.input[i] = alias[x]
keep_nodes = [n for n in m.graph.node if not (n.op_type == "Identity" and n.output[0] in alias)]
del m.graph.node[:]
m.graph.node.extend(keep_nodes)
# A weight used by several MatMuls is skipped by the quantizer: give each use its own copy
seen = set()
for n in m.graph.node:
    if n.op_type == "MatMul" and n.input[1] in inits:
        name = n.input[1]
        if name in seen:
            t = numpy_helper.from_array(numpy_helper.to_array(inits[name]).copy(), name + "_dup%d" % len(seen))
            m.graph.initializer.append(t); inits[t.name] = t
            n.input[1] = t.name
        seen.add(n.input[1])
q = MatMulNBitsQuantizer(m, algo_config=DefaultWeightOnlyQuantConfig(block_size=32, is_symmetric=True, accuracy_level=4, bits=4))
q.process()
onnx.save(q.model.model, os.path.join(OUT, "model.onnx"))
print("wrote", os.path.getsize(os.path.join(OUT, "model.onnx")) / 1e6, "MB")
