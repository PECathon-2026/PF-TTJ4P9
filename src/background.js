/* PrivacyLens – background.js (MV3 service worker). The ONLY place that talks to a model. */
importScripts('detector.js', 'agent-core.js');
const PL = self.PL;

const DEFAULTS = {
  provider: 'mock',               // mock | ollama | openai | anthropic
  endpoint: 'http://localhost:11434',
  model: 'llama3.2',
  apiKey: '',
  localOnly: true,                // refuse any non-loopback endpoint
  sendScreenshots: false,         // vision input (redacted); off by default
  strictMessages: true,
  maxSteps: 10,
  rules: { selectors: [], patterns: [] },
  vault: {},                      // { key: "value" | {value, origins:[hostnames]} }
};
const getSettings = async () => Object.assign({}, DEFAULTS, await chrome.storage.local.get(Object.keys(DEFAULTS)));
const runs = new Map();
let AUDIT = []; // in-memory only; contains types/counts, never values

function audit(e, d = {}) {
  AUDIT.push({ t: new Date().toISOString(), e, ...d });
  if (AUDIT.length > 300) AUDIT.shift();
  chrome.storage.session.set({ plAudit: AUDIT }).catch(() => {});
}
const status = (text) => chrome.runtime.sendMessage({ type: 'PL_STATUS', text }).catch(() => {});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const secretOf = (e) => (typeof e === 'string' ? e : e && e.value);

function tabSend(tabId, msg) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, msg, (res) => {
      if (chrome.runtime.lastError) return reject(new Error('Cannot reach page (reload the tab once after installing).'));
      if (res && res.error) return reject(new Error(res.error));
      resolve(res);
    });
  });
}

/* ---------- screenshot: capture -> black out -> re-encode (fail closed) ---------- */
const blobToDataURL = (blob) => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = rej; r.readAsDataURL(blob); });
async function redactedScreenshot(tabId, s) {
  const tab = await chrome.tabs.get(tabId);
  const before = await chrome.tabs.captureVisibleTab(tab.windowId, { format: 'png' });
  const { regions, viewportWidth } = await tabSend(tabId, { type: 'PL_REGIONS', rules: s.rules, strict: s.strictMessages });
  const bmp = await createImageBitmap(await (await fetch(before)).blob());
  const k = bmp.width / viewportWidth, pad = 4;
  const c = new OffscreenCanvas(bmp.width, bmp.height), g = c.getContext('2d');
  g.drawImage(bmp, 0, 0); g.fillStyle = '#000';
  for (const r of regions) g.fillRect((r.x - pad) * k, (r.y - pad) * k, (r.w + 2 * pad) * k, (r.h + 2 * pad) * k);
  const after = await blobToDataURL(await c.convertToBlob({ type: 'image/jpeg', quality: 0.8 })); // re-encode strips metadata
  return { before, after, regions: regions.length };
}

/* ---------- LLM transport: exactly one send path, guarded on the final serialised body ---------- */
const LOOPBACK = ['localhost', '127.0.0.1', '[::1]'];
function stripImages(body) {
  return JSON.stringify(body, function (k, v) {
    if (typeof v === 'string' && v.startsWith('data:image')) return '<image>';
    if (k === 'images' && Array.isArray(v)) return v.map(() => '<image>');
    if (k === 'data' && this && this.type === 'base64') return '<image>';
    return v;
  });
}
async function send(s, url, headers, body, known) {
  const u = new URL(url);
  if (s.localOnly && !LOOPBACK.includes(u.hostname)) throw new Error('Local-only mode: ' + u.hostname + ' is not a loopback address.');
  const g = PL.validateOutbound(stripImages(body), known, { extra: PL.compileRules(s.rules) });
  if (!g.ok) { audit('outbound_blocked_final', { violations: g.violations }); throw new Error('Final request body failed privacy validation.'); }
  const r = await fetch(url, { method: 'POST', headers: Object.assign({ 'Content-Type': 'application/json' }, headers), body: JSON.stringify(body), credentials: 'omit', referrerPolicy: 'no-referrer' });
  if (!r.ok) throw new Error('Model endpoint returned HTTP ' + r.status);
  return r.json();
}
async function callLLM(s, messages, image, known) {
  const base = s.endpoint.replace(/\/$/, '');
  const img64 = image ? image.split(',')[1] : null;
  if (s.provider === 'ollama') {
    const msgs = messages.map((m) => ({ ...m })); if (img64) msgs[msgs.length - 1].images = [img64];
    return (await send(s, base + '/api/chat', {}, { model: s.model, messages: msgs, stream: false, format: 'json', options: { temperature: 0 } }, known)).message.content;
  }
  if (s.provider === 'openai') {
    const msgs = messages.map((m) => ({ ...m }));
    if (image) msgs[msgs.length - 1].content = [{ type: 'text', text: msgs[msgs.length - 1].content }, { type: 'image_url', image_url: { url: image } }];
    const j = await send(s, base + '/chat/completions', { Authorization: 'Bearer ' + s.apiKey }, { model: s.model, messages: msgs, temperature: 0, response_format: { type: 'json_object' } }, known);
    return j.choices[0].message.content;
  }
  if (s.provider === 'anthropic') {
    const user = [{ type: 'text', text: messages[1].content }];
    if (img64) user.push({ type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: img64 } });
    const j = await send(s, base + '/v1/messages', { 'x-api-key': s.apiKey, 'anthropic-version': '2023-06-01' }, { model: s.model, max_tokens: 400, system: messages[0].content, messages: [{ role: 'user', content: user }] }, known);
    return j.content.filter((c) => c.type === 'text').map((c) => c.text).join('');
  }
  throw new Error('Unknown provider');
}

/* ---------- orchestration ---------- */
async function runTask(tabId, task) {
  const s = await getSettings();
  const run = { stop: false }; runs.set(tabId, run);
  audit('task_start', { provider: s.provider, localOnly: s.localOnly });
  const io = {
    stopped: () => run.stop,
    log: (e, d) => audit(e, d),
    status,
    snapshot: () => tabSend(tabId, { type: 'PL_SNAPSHOT', rules: s.rules, strict: s.strictMessages }),
    execute: (action) => tabSend(tabId, { type: 'PL_EXEC', action }),
    confirm: (text) => tabSend(tabId, { type: 'PL_CONFIRM', text }),
    screenshot: async () => (await redactedScreenshot(tabId, s)).after,
    llm: (messages, image, known) => callLLM(s, messages, image, known),
  };
  try {
    const r = await runAgent({ task, settings: s, vault: s.vault, io });
    status(`Finished: ${r.outcome}${r.message ? ' — ' + r.message : ''}`);
    audit('task_end', { outcome: r.outcome, transmissions: r.transmissions });
  } catch (e) {
    audit('fail_closed', { why: String(e.message || e) });
    status('Stopped (fail-closed): ' + (e.message || e));
  } finally { runs.delete(tabId); }
}

const { runAgent } = PL;

chrome.runtime.onMessage.addListener((msg, sender, send_) => {
  (async () => {
    const s = await getSettings();
    switch (msg.type) {
      case 'PL_RUN': runTask(msg.tabId, msg.task); send_({ ok: true }); break;
      case 'PL_STOP': { const r = runs.get(msg.tabId); if (r) r.stop = true; send_({ ok: true }); break; }
      case 'PL_VAULT_GET': { // called by the content script at execution time, after validation + approval
        const e = s.vault[msg.key]; let host = '';
        try { host = new URL(sender.tab.url).hostname; } catch (x) { /* ignore */ }
        if (e == null || (typeof e === 'object' && e.origins && !e.origins.includes(host))) return send_({ ok: false });
        send_({ ok: true, value: secretOf(e) }); break;
      }
      case 'PL_PREVIEW': {
        const snap = await tabSend(msg.tabId, { type: 'PL_SNAPSHOT', rules: s.rules, strict: s.strictMessages, preview: true });
        let shots = null;
        if (msg.screenshot) { try { shots = await redactedScreenshot(msg.tabId, s); } catch (e) { shots = { error: e.message }; } }
        send_({ lines: snap.lines, stats: snap.stats, shots }); break;
      }
      case 'PL_UNSAFE_DEMO': { // simulate a buggy/compromised pipeline sending RAW page text: the guard must stop it
        const snap = await tabSend(msg.tabId, { type: 'PL_SNAPSHOT', rules: s.rules, strict: s.strictMessages, preview: true });
        const rawPayload = JSON.stringify([{ role: 'user', content: snap.lines.map((l) => l.raw).join('\n') }]);
        const g = PL.validateOutbound(rawPayload, new Map(snap.known), { extra: PL.compileRules(s.rules) });
        audit(g.ok ? 'unsafe_demo_passed' : 'unsafe_demo_blocked', { violations: g.violations.length });
        const byType = {}; g.violations.forEach((v) => { byType[v.type] = (byType[v.type] || 0) + 1; });
        send_({ blocked: !g.ok, byType, bytes: rawPayload.length }); break;
      }
      case 'PL_LOG_GET': send_({ log: AUDIT }); break;
      case 'PL_LOG_CLEAR': AUDIT = []; await chrome.storage.session.remove('plAudit'); send_({ ok: true }); break;
      default: send_({ ok: false });
    }
  })().catch((e) => send_({ error: String(e.message || e) }));
  return true;
});
