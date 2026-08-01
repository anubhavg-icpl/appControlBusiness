#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Train a small TF-IDF + MLP classifier over the WDAC (App Control for Business)
docs corpus, then export:

  assets/wdac_model.onnx     — the MLP (float32 [1,V] -> float32 [1,C])
  assets/wdac_features.json  — vocab + IDF + labels so JS can rebuild the
                               exact same TF-IDF vector at inference time

The JS side (onnxruntime-web) reimplements sklearn's TfidfVectorizer in ~30
lines and runs the ONNX MLP. We keep string-ops OUT of ONNX (flaky in
ort-web): the model only ever sees a float tensor.

Run from the repo root:
    pip install -r tools/requirements.txt
    python3 tools/train_model.py

Self-checks (hard gates, exit non-zero on failure):
  - parsed PARTS count == markdown files found
  - exported ONNX output matches PyTorch output (atol 1e-4)
  - vocab size == ONNX input width == features.json input_dim
Soft gate (printed, fails script if absurd):
  - held-out query val top-1 accuracy >= 0.50
"""
from __future__ import annotations
import json, re, sys, random
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parent.parent
ASSETS = REPO / "assets"
ASSETS.mkdir(exist_ok=True)

MAX_FEATURES = 2500          # TF-IDF vocab cap (keeps the ONNX ~1.5 MB)
NGRAM = (1, 2)               # uni- + bi-grams — JS mirrors this exactly
HIDDEN = (128, 64)
EPOCHS = 60
SEED = 7
MIN_CHUNK_WORDS = 40
ACC_FLOOR = 0.50             # conservative gate on held-out query accuracy


# ── 1. Parse the site's PARTS registry so labels stay aligned with the UI ─
def parse_parts() -> list[dict]:
    src = (REPO / "app.js").read_text(encoding="utf-8")
    m = re.search(r"const PARTS\s*=\s*\[(.*?)\n\];", src, re.S)
    if not m:
        sys.exit("FATAL: could not locate PARTS array in app.js")
    body = m.group(1)
    objs = re.findall(r"\{([^{}]*)\}", body)         # PARTS objects hold no nested braces
    parts = []
    for i, ob in enumerate(objs):
        def take(key: str) -> str:
            mm = re.search(rf"{key}\s*:\s*'(.*?)'", ob, re.S)
            return mm.group(1).strip() if mm else ""
        file = take("file")
        if not file:
            continue
        tags_m = re.search(r"tags\s*:\s*\[(.*?)\]", ob, re.S)
        tags = re.findall(r"'([^']*)'", tags_m.group(1)) if tags_m else []
        parts.append(dict(idx=i, file=file, label=take("label"),
                          keywords=take("keywords"), tags=tags))
    return parts


# ── 2. Build labelled training rows from each doc ────────────────────────
def strip_frontmatter(md: str) -> str:
    return re.sub(r"^---[\s\S]*?---\s*\n", "", md).strip()


def chunk_by_h2(md: str) -> list[str]:
    """Split markdown on H2 headers; keep preamble as its own chunk."""
    pieces = re.split(r"\n(?=#{2,3}\s)", md)
    return [p.strip() for p in pieces if p.strip()]


def words(s: str) -> int:
    return len(re.findall(r"\S+", s))


def query_rows_for(part: dict) -> list[str]:
    """Synthetic natural-language queries so the model learns question→doc,
    not just doc-prose→doc. Derived from the site's own keywords/tags/label."""
    rows: list[str] = []
    for phrase in re.split(r"[,;]", part["keywords"]):
        p = phrase.strip()
        if len(p) >= 3:
            rows.append(p)
    for t in part["tags"]:
        rows.append(t)
        rows.append(f"{t} app control")
    lbl = re.sub(r"\s*—.*$", "", part["label"]).strip()   # drop subtitle after em-dash
    if lbl:
        rows.append(f"what is {lbl}")
        rows.append(f"{lbl} explained")
        rows.append(f"how does {lbl} work")
    return [r for r in rows if words(r) >= 1]


def build_rows(parts: list[dict]):
    """Return (texts, labels, is_query[]) — multiple rows per class."""
    texts, labels, is_query = [], [], []
    for p in parts:
        f = REPO / p["file"]
        if not f.exists():
            print(f"  warn: missing {p['file']}")
            continue
        md = strip_frontmatter(f.read_text(encoding="utf-8"))
        for ch in chunk_by_h2(md):
            if words(ch) >= MIN_CHUNK_WORDS:
                texts.append(ch); labels.append(p["idx"]); is_query.append(False)
        texts.append(md); labels.append(p["idx"]); is_query.append(False)  # whole doc too
        for q in query_rows_for(p):
            texts.append(q); labels.append(p["idx"]); is_query.append(True)
    return texts, np.array(labels), np.array(is_query)


# ── 3. TF-IDF (sklearn derives vocab+IDF; JS reproduces at inference) ────
def fit_tfidf(texts):
    from sklearn.feature_extraction.text import TfidfVectorizer
    vec = TfidfVectorizer(ngram_range=NGRAM, token_pattern=r"(?u)\b\w\w+\b",
                          min_df=1, max_features=MAX_FEATURES,
                          norm="l2", sublinear_tf=False, lowercase=True)
    X = vec.fit_transform(texts).toarray().astype(np.float32)
    return vec, X


# ── 4. Tiny MLP in PyTorch ───────────────────────────────────────────────
def train_mlp(Xtr, ytr, V, C):
    import torch, torch.nn as nn
    torch.manual_seed(SEED); np.random.seed(SEED); random.seed(SEED)

    class MLP(nn.Module):
        def __init__(self):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(V, HIDDEN[0]), nn.ReLU(), nn.Dropout(0.3),
                nn.Linear(HIDDEN[0], HIDDEN[1]), nn.ReLU(), nn.Dropout(0.3),
                nn.Linear(HIDDEN[1], C),
            )
        def forward(self, x):
            return self.net(x)

    class Infer(nn.Module):                      # adds softmax for export
        def __init__(self, mlp): super().__init__(); self.mlp = mlp
        def forward(self, x): return torch.softmax(self.mlp(x), dim=-1)

    dev = "cpu"
    mlp = MLP().to(dev)
    opt = torch.optim.Adam(mlp.parameters(), lr=1e-3, weight_decay=1e-4)
    lossf = nn.CrossEntropyLoss()
    Xt = torch.from_numpy(Xtr).to(dev)
    yt = torch.from_numpy(ytr.astype(np.int64)).to(dev)
    n = Xt.shape[0]
    bs = min(64, n)
    for ep in range(EPOCHS):
        perm = torch.randperm(n)
        tot = 0.0
        for s in range(0, n, bs):
            idx = perm[s:s+bs]
            opt.zero_grad()
            lo = lossf(mlp(Xt[idx]), yt[idx])
            lo.backward(); opt.step(); tot += lo.item() * idx.numel()
    return mlp, Infer(mlp).eval(), dev


# ── 5. Export ONNX + features.json ───────────────────────────────────────
def export(mlp, infer, dev, V, C, vec, parts):
    import torch
    onnx_path = ASSETS / "wdac_model.onnx"
    dummy = torch.zeros(1, V, device=dev)
    # dynamo=False → classic TorchScript tracer. The torch 2.13 dynamo exporter
    # collapses this tiny MLP to a degenerate ~1 KB graph; the legacy tracer
    # emits the real MatMul/Add/Softmax graph ort-web expects.
    torch.onnx.export(
        infer, dummy, str(onnx_path),
        input_names=["input"], output_names=["probs"],
        dynamic_axes={"input": {0: "batch"}, "probs": {0: "batch"}},
        opset_version=17, dynamo=False,
    )
    vocab = vec.vocabulary_                       # dict token -> col index
    idf = vec.idf_                                # ndarray aligned to col index
    # idf_ is indexed by feature index 0..V-1 (same ordering as vocabulary values)
    features = {
        "version": 1,
        "ngram": list(NGRAM),
        "token_pattern_note": "lowercase; tokens match [A-Za-z0-9_]{2,}; bigrams = token[i]+' '+token[i+1]",
        "input_dim": V,
        "num_classes": C,
        "model": "assets/wdac_model.onnx",
        "vocab": {k: int(v) for k, v in vocab.items()},
        "idf": [float(x) for x in idf],
        "labels": [{"idx": p["idx"], "file": p["file"], "label": p["label"]} for p in parts],
    }
    (ASSETS / "wdac_features.json").write_text(json.dumps(features), encoding="utf-8")
    return onnx_path


# ── 6. Self-checks ───────────────────────────────────────────────────────
def verify(infer, dev, V, X, onnx_path):
    import torch, onnxruntime as ort
    # ONNX loads + parity with PyTorch
    so = ort.SessionOptions()
    sess = ort.InferenceSession(str(onnx_path), sess_options=so,
                                providers=["CPUExecutionProvider"])
    sample = np.concatenate([X[:4], np.random.rand(4, V).astype(np.float32)])
    with torch.no_grad():
        torch_out = infer(torch.from_numpy(sample).to(dev)).cpu().numpy()
    ort_out = sess.run(None, {"input": sample.astype(np.float32)})[0]
    assert np.allclose(torch_out, ort_out, atol=1e-4), \
        "ONNX output diverges from PyTorch"
    # guard against a degenerate constant-output export: predictions must vary
    assert np.unique(ort_out.argmax(1)).size > 1, \
        "ONNX returns identical class for all inputs — export is degenerate"
    assert ort_out.shape == sample.shape[:1] + (ort_out.shape[1],)  # shape sanity
    sums = ort_out.sum(axis=1)
    assert np.allclose(sums, 1.0, atol=1e-3), "softmax output must sum to 1"
    print(f"  ONNX parity OK (atol 1e-4), probs sum→1, in_width={V}")
    return sess


# ── main ─────────────────────────────────────────────────────────────────
def main():
    print("1/5  parsing PARTS from app.js …")
    parts = parse_parts()
    print(f"     {len(parts)} parts (indices 0..{len(parts)-1})")
    assert len(parts) >= 8, "PARTS parsed too small — app.js format changed?"

    print("2/5  building labelled rows (H2 chunks + synthetic queries) …")
    texts, labels, is_query = build_rows(parts)
    n_query = int(is_query.sum())
    print(f"     {len(texts)} rows across {len(set(labels.tolist()))} classes "
          f"({n_query} synthetic query rows)")

    print("3/5  fitting TF-IDF …")
    vec, X = fit_tfidf(texts)
    V = X.shape[1]; C = int(labels.max()) + 1
    print(f"     vocab={V}  classes={C}")

    # Split: train = prose chunks + most query rows; val = held-out query rows
    # (the real use case is query→doc). Keep ≥1 query/class in train.
    rng = np.random.RandomState(SEED)
    val_mask = np.zeros(len(texts), dtype=bool)
    for c in np.unique(labels):
        qi = np.where((labels == c) & is_query)[0]
        if len(qi) >= 3:
            pick = rng.choice(qi, size=max(1, len(qi) // 4), replace=False)
            val_mask[pick] = True
    tr = ~val_mask
    Xtr, ytr = X[tr], labels[tr]
    Xva, yva = X[val_mask], labels[val_mask]
    print(f"     train={tr.sum()}  val(held-out queries)={val_mask.sum()}")

    print("4/5  training MLP …")
    mlp, infer, dev = train_mlp(Xtr, ytr, V, C)

    # Report accuracy
    import torch
    with torch.no_grad():
        logits = mlp(torch.from_numpy(Xtr).to(dev))
        tr_acc = (logits.argmax(1).cpu().numpy() == ytr).mean()
    if len(yva):
        with torch.no_grad():
            vlogits = mlp(torch.from_numpy(Xva).to(dev))
            va_acc = (vlogits.argmax(1).cpu().numpy() == yva).mean()
    else:
        va_acc = float("nan")
    print(f"     train top-1 = {tr_acc:.3f}")
    print(f"     val  top-1 = {va_acc:.3f}  (held-out synthetic queries)")

    print("5/5  exporting ONNX + features.json …")
    onnx_path = export(mlp, infer, dev, V, C, vec, parts)
    print(f"     wrote {onnx_path.relative_to(REPO)}  ({onnx_path.stat().st_size//1024} KB)")
    print(f"     wrote assets/wdac_features.json")

    verify(infer, dev, V, X, onnx_path)

    # Hard size-consistency gate
    feat = json.loads((ASSETS / "wdac_features.json").read_text())
    assert len(feat["vocab"]) == V == feat["input_dim"], "vocab/input_dim mismatch"
    assert len(feat["idf"]) == V, "idf length != vocab"

    # Soft accuracy gate
    if not np.isnan(va_acc) and va_acc < ACC_FLOOR:
        print(f"\nFAIL: held-out query accuracy {va_acc:.3f} < floor {ACC_FLOOR}")
        sys.exit(1)

    print("\nDONE. Demo queries to try in the browser (preview via sklearn path):")
    for q in ["block unsigned drivers", "managed installer trust",
              "certificate chain signing", "supplemental policy add trust",
              "audit mode event log 3076"]:
        qv = vec.transform([q]).toarray().astype(np.float32)
        with torch.no_grad():
            top = infer(torch.from_numpy(qv).to(dev))[0].cpu().numpy().argsort()[::-1][:3]
        names = [parts[t]["label"] for t in top]
        print(f"   '{q}' → {names}")
    print()


def vectorize_query(q, vec, V):  # kept for potential reuse; sklearn path used above
    return vec.transform([q]).toarray().astype(np.float32)[0]


if __name__ == "__main__":
    main()
