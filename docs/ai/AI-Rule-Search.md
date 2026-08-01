<!-- Author: Anubhav Gain | Category: Interactive Tool | Topic: AI Rule Search -->
# AI Rule Search — On-Device ONNX Inference

Ask a question in plain English and a **small neural network runs entirely in your
browser** (via Microsoft's **ONNX Runtime Web**) to find the most relevant App Control
for Business / WDAC reference page. No server, no API key — the model downloads once
and all inference happens locally on this device.

> **How it works:** every reference page in this guide was chunked into labelled
> training rows, a TF-IDF + MLP classifier was trained on that corpus, then exported
> to the ONNX format. The same TF-IDF vectorizer is reimplemented in ~30 lines of
> JavaScript so the ONNX model only ever receives a float tensor — keeping string
> ops (which are unreliable in `ort-web`) out of the graph.

## Try it

<div id="ai-search-root"></div>

### Example questions

- `block unsigned drivers`
- `how does managed installer trust work`
- `treat revoked or expired certificates as unsigned`
- `powerShell constrained language mode scripts`
- `which file rule level should I use for unsigned files`
- `allow supplemental policies to extend the base policy`

## What's under the hood

| Component | Detail |
|---|---|
| **Corpus** | 43 reference pages (8-part guide + 22 rule options + 12 file rule levels + Notes & Tips), chunked by H2 section |
| **Features** | TF-IDF, unigrams + bigrams, 2 500-term vocabulary, L2-normalized |
| **Model** | MLP `2500 → 128 → 64 → 43`, ReLU + dropout, trained 60 epochs (PyTorch) |
| **Runtime** | Exported to ONNX (opset 17), executed in-browser by `onnxruntime-web` (WASM) |
| **Reproduce** | `python3 tools/train_model.py` — regenerates `assets/wdac_model.onnx` + `assets/wdac_features.json` |

The classifier predicts **which page** best answers your query; click a result to open
it. Ranked confidence bars show the model's top-5 matches.
