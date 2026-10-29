# PrivacyLens

A Chrome (MV3) extension that lets an AI agent operate web pages while **sensitive data is computed on-device and only sanitised data can reach a model**.

> Compute what is sensitive locally. Reason globally only on sanitised data.

## 1. Architecture and data flow

```
 Web page (untrusted)                 Content script (local)                Service worker (local)              Model
 ┌───────────────┐   DOM    ┌────────────────────────────────────┐   ┌────────────────────────────────┐
 │ forms, text,  │ ───────► │ dom-sanitizer: structural analysis │   │ agent-core.runAgent loop        │
 │ chat, video   │          │ + pattern/checksum detection       │   │  1 outbound guard (fail closed)│
 └───────────────┘          │ → sanitised outline + action meta  │──►│  2 LLM call (only send path)   │──► Ollama / OpenAI-compat /
        ▲                   │ → raw values stay in memory (known)│   │  3 validateAction              │    Anthropic
        │ execute           └────────────────────────────────────┘   │  4 approval overlay (closed    │
        │ (re-checks target, resolves {{vault:key}} locally)  ◄───────│    shadow DOM, isTrusted only) │
        └─────────────────────────────────────────────────────────────┴────────────────────────────────┘
```
Trust boundary: everything left of the model is on the device. The model sees only the sanitised outline, the task (also sanitised) and vault key *names*.

Files: `src/detector.js` (detection, redaction, outbound guard) · `src/dom-sanitizer.js` (DOM analysis, screenshot regions, executor) · `src/agent-core.js` (prompt, action validation, agent loop, offline agent) · `src/background.js` (transport, screenshots, vault) · `popup/` (UI).

## 2. Setup

1. `chrome://extensions` → Developer mode → **Load unpacked** → select this folder. Reload any open tab once.
2. Open the popup → Settings. Default is the **offline demo agent** (no model, no network).
3. Local model: install Ollama, run `OLLAMA_ORIGINS="chrome-extension://*" ollama serve`, pull a model (e.g. `llama3.2`), choose provider *Ollama*. Keep **Local-only mode** on to block any non-loopback endpoint.
4. Cloud model: choose *OpenAI-compatible* or *Anthropic*, set endpoint/model/key, turn Local-only off.
5. Vault (JSON), e.g. `{"email":"demo@example.com","card_number":{"value":"4242 4242 4242 4242","origins":["localhost"]}}`.
6. Demo pages: `npm run build:pages`, then `cd test/pages && python3 -m http.server 8000` and open `http://localhost:8000/checkout.html`.

Demo flow (for the 2–3 min video): open checkout → *Preview sanitised page* (before/after, with screenshot) → run "fill the checkout form and place the order" → approve the prompts → *Try sending raw page* shows the blocked payload → Audit log.

## 3. Detection and sanitisation

Layers (defence in depth):
- **Patterns + validators:** Aadhaar (Verhoeff), PAN structure, cards (Luhn, 13–19 digits), email, UPI, Indian/intl phones, OTP/CVV/password/DOB/account (context-anchored), JWT, API key prefixes (Stripe, AWS, GitHub, Slack, Google…), Bearer, PEM private keys, IPv4/IPv6, SSN, IFSC, MRN/diagnosis, high-entropy secrets. User regex rules too.
- **Structure:** `type=password`, `autocomplete` tokens, name/label/aria/placeholder heuristics, `data-sensitive`, participant-name and chat-message selectors, `code/pre` secrets, user CSS selectors. Input values of sensitive fields are never read into the outline.
- **Media:** `video/canvas/iframe/avatar images` are replaced by markers and blacked out in screenshots.
- **Evasion handling:** NFKC normalisation, zero-width/soft-hyphen stripping, spaced digits.
- **Hidden content:** `display:none`, `opacity:0`, `font-size:0`, off-screen text is dropped (main prompt-injection carrier).

Sanitisation: semantic placeholders `[REDACTED:CARD_1]` (numbering only tells "same value again"; no hash, so nothing to brute-force), URL query/hash stripped, screenshots get opaque black boxes then are re-encoded as JPEG (pixels are replaced, not overlaid).

## 4. AI integration and action validation

The model replies with one JSON action. Before execution `validateAction` rejects: unknown action/fields, targets not in the current snapshot, wrong element kinds, plain text into sensitive fields (only `{{vault:KEY}}` or `ask_user`), typed placeholders (reconstruction attempts), literal PII, vault refs mixed into text, injection into forms that post to another origin, and per-origin vault violations. **Human approval** (overlay in a closed shadow root, trusted clicks only, 90 s timeout = deny) is required for irreversible clicks (pay/submit/delete/sign-in…), cross-origin navigation and every secret injection. The executor re-classifies the field at run time (TOCTOU). Secrets are resolved only inside the content script at execution; the model never sees them. Page content is wrapped as `<untrusted_page_content>`, known injection phrases are replaced with `[REMOVED:INJECTION]`.

## 5. Security assumptions and known limitations

- Trusted: the browser, the extension, the user's machine. Untrusted: pages and the model endpoint.
- Outbound guard runs twice (loop and final serialised body), checks patterns *and* every raw value ever seen (also URL-decoded, JSON-leaf and base64 variants). Any error blocks the request.
- **Zero-leakage results apply only to the tested pages and the one transmission path (model request body).** The API key header is not scanned (it is the user's own key).
- Screenshots: redaction is DOM-driven; text rendered inside images/canvas/video is **not** detected (no OCR/face detection included). Keep screenshots off for such pages.
- Free-form private information with no pattern or structural cue (e.g. a name in plain prose) can be missed; strict-message mode and user rules mitigate this. Optional NER/OCR (e.g. a local model) is a natural extension.
- Vault is stored unencrypted in `chrome.storage.local`.
- Cross-origin iframes are not inspected. MV3 service workers can be suspended during very long tasks.
- Over-redaction occurs (see precision); generic 32+ char tokens and 13–19 digit Luhn-valid numbers are redacted even if benign.
- The test "cloud model" is a deterministic stand-in policy; leakage is measured on the bytes handed to the transport, not on a real vendor.

## 6. Evaluation (reproducible)

```
npm install            # playwright (Chromium)
npm run build:pages    # seeded synthetic pages + ground truth
npm run eval           # writes test/results.json
```
Measured on this repository (seeded, Chromium via Playwright, one run):

| Metric | Result |
|---|---|
| Text corpus: PII recall (50 labelled values incl. 5 evasions) | 100% |
| Text corpus: span precision / false positives on 27 benign strings | 100% / 0 |
| 5 scenario pages: recall (35 annotated values) | 100% (patterns alone: 77%, so structure matters) |
| 5 scenario pages: redaction precision (changed lines that held a secret) | 92% |
| Context preservation (required UI strings still present) | 100% (41/41) |
| Screenshot regions covering located secrets | 100% (30/30) |
| Outbound guard vs encoded smuggling (URL, base64, zero-width, plain) | 6/6 blocked |
| Leakage: 17 requests, 41 ground-truth/vault values, 25 fresh canaries over 10 pathways | 0 leaked |
| Fail-closed: sanitiser bypassed / snapshot error / model down | blocked, 0 requests sent |
| Injection page: planted phrases in payload / hostile actions executed | 0 / 0 |
| Action validator table | 20/20 |
| Task success: checkout (vault injection, approvals, submit) / login (stops for OTP) | pass / pass |
| Latency: snapshot median / p95; detection | 0.8 ms / 2.1 ms; ~47 ms per 100 KB |

The corpus is small and written by the same author as the detectors, so these numbers show the pipeline works on the tested scenarios; they are not a general accuracy claim.
