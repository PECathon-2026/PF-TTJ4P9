/*
 * PrivacyLens – detector.js
 * Pure, dependency-free. Pattern + checksum detection, redaction, injection neutralisation,
 * and the outbound guard. Loaded as a classic script in the extension (globalThis.PL)
 * and via require() in Node tests.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PL = Object.assign(root.PL || {}, api);
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  /* ---------- helpers & validators ---------- */
  const PLACEHOLDER_RE = /\[REDACTED:[A-Z_0-9]+\]/g;
  const prep = (t) =>
    String(t).normalize('NFKC').replace(/[\u200B-\u200F\u2060\uFEFF\u00AD\u202A-\u202E]/g, '');
  const alnum = (s) => String(s).toLowerCase().replace(/[^a-z0-9]/g, '');
  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  function entropy(s) {
    const m = {};
    for (const c of s) m[c] = (m[c] || 0) + 1;
    let h = 0;
    for (const k in m) { const p = m[k] / s.length; h -= p * Math.log2(p); }
    return h;
  }
  function luhn(num) {
    let sum = 0, alt = false;
    for (let i = num.length - 1; i >= 0; i--) {
      let n = +num[i];
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  }
  // Verhoeff checksum (used by Aadhaar)
  const VD = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
  const VP = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
  const VINV = [0,4,3,2,1,5,6,7,8,9];
  function verhoeff(num) {
    let c = 0;
    const a = num.split('').reverse().map(Number);
    for (let i = 0; i < a.length; i++) c = VD[c][VP[i % 8][a[i]]];
    return c === 0;
  }
  function verhoeffCheckDigit(payload) { // for generating synthetic test Aadhaar numbers
    let c = 0;
    const a = payload.split('').reverse().map(Number);
    for (let i = 0; i < a.length; i++) c = VD[c][VP[(i + 1) % 8][a[i]]];
    return VINV[c];
  }
  const digitsOf = (s) => s.replace(/\D/g, '');

  /* ---------- pattern catalogue ---------- */
  const P = (type, re, o = {}) => ({ type, re, group: o.group || 0, prio: o.prio || 50, ok: o.ok || null });
  const notEntropyLow = (v) => entropy(v) >= 2.8;

  const PATTERNS = [
    P('PRIVATE_KEY', /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/gd, { prio: 100 }),
    P('JWT', /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/gd, { prio: 95 }),
    P('API_KEY', /(?<![A-Za-z0-9_-])(?:sk-(?:live-|proj-|ant-|or-)?[A-Za-z0-9_-]{16,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|pk_live_[A-Za-z0-9]{16,}|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{30,})(?![A-Za-z0-9_-])/gd, { prio: 90 }),
    P('API_KEY', /\bBearer\s+([A-Za-z0-9._~+\/-]{16,}=*)/gid, { group: 1, prio: 88 }),
    P('API_KEY', /\b(?:api[_\- ]?key|apikey|secret(?:[_\- ]?key)?|(?:access|auth|bearer|refresh|session)?[_\- ]?token|client[_\- ]?secret|private[_\- ]?key)\b["']?\s*[:=]\s*["']?([A-Za-z0-9_\-\/+=.]{12,})/gid, { group: 1, prio: 85, ok: notEntropyLow }),
    P('PASSWORD', /\b(?:pass(?:word|wd)?|pwd)\b["']?\s*(?:[:=]|\bis\b)\s*["']?([^\s"'<>]{4,})/gid, { group: 1, prio: 70, ok: (v) => !/^(required|invalid|incorrect|wrong|empty|hidden|saved|changed|reset|expired|valid|too|must|should|at|not|and|or|to|for|manager|policy|field)$/i.test(v) }),
    P('OTP', /\b(?:otp|one[-\s]?time(?:\s+(?:password|passcode|code|pin))?|verification\s+code|security\s+code|auth(?:entication)?\s+code|2fa\s+code|login\s+code|passcode)\b[^\d\n]{0,30}?(?<![\d])(\d{4,8})(?!\d)/gid, { group: 1, prio: 72 }),
    P('OTP', /(?<![\d])(\d{4,8})\s+is\s+(?:your|the)\s+(?:one[-\s]?time|otp|verification|security|login|authentication)/gid, { group: 1, prio: 72 }),
    P('CVV', /\b(?:cvv2?|cvc2?|csc)\b[^\d\n]{0,12}?(?<![\d])(\d{3,4})(?!\d)/gid, { group: 1, prio: 78 }),
    P('CARD_EXP', /\b(?:exp(?:ir(?:y|es|ation))?(?:\s*date)?|valid\s*(?:thru|till|until))\b[^\d\n]{0,10}?((?:0[1-9]|1[0-2])\s*\/\s*(?:\d{4}|\d{2}))(?!\d)/gid, { group: 1, prio: 60 }),
    P('CARD', /(?<![\d])((?:\d[ -]?){12,18}\d)(?!\d)/gd, { group: 1, prio: 80, ok: (v) => { const d = digitsOf(v); return d.length >= 13 && d.length <= 19 && luhn(d); } }),
    P('CARD', /\b(?:card(?:\s*(?:number|no\.?|#))?|cc)\b[^\d\n]{0,15}?((?:\d[ -]?){12,18}\d)(?!\d)/gid, { group: 1, prio: 79 }),
    P('AADHAAR', /(?<![\d])([2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4})(?![\d])/gd, { group: 1, prio: 76, ok: (v) => verhoeff(digitsOf(v)) }),
    P('AADHAAR', /\b(?:aadhaar|aadhar|uidai|uid)\b[^\d\n]{0,20}?(\d{4}[\s-]?\d{4}[\s-]?\d{4})(?!\d)/gid, { group: 1, prio: 75 }),
    P('PAN', /(?<![A-Za-z0-9])([A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z])(?![A-Za-z0-9])/gd, { group: 1, prio: 75 }),
    P('SSN', /(?<![\d-])(\d{3}-\d{2}-\d{4})(?![\d-])/gd, { group: 1, prio: 70 }),
    P('IFSC', /(?<![A-Za-z0-9])([A-Z]{4}0[A-Z0-9]{6})(?![A-Za-z0-9])/gd, { group: 1, prio: 60 }),
    P('ACCOUNT', /\b(?:a\/c|account)(?:\s*(?:no\.?|number|#))?\b[^\d\n]{0,12}?(\d{9,18})(?!\d)/gid, { group: 1, prio: 65 }),
    P('UPI', /(?<![A-Za-z0-9._-])[a-z0-9._-]{2,}@(?:ok(?:axis|hdfcbank|icici|sbi)|ybl|paytm|upi|apl|ibl|axl|sbi|icici|hdfcbank)\b/gid, { prio: 62 }),
    P('EMAIL', /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/gd, { prio: 60 }),
    P('PHONE', /(?<![\d])(?:\+91[\s-]?|91[\s-]?|0)?([6-9]\d{9}|[6-9]\d{4}[\s-]\d{5})(?!\d)/gd, { prio: 50 }),
    P('PHONE', /(?<![\w])\+(?!91)\d{1,3}[\s-]?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}(?!\d)/gd, { prio: 48 }),
    P('PHONE', /(?<![\d(])\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)/gd, { prio: 45 }),
    P('IP', /(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])/gd, { group: 1, prio: 40 }),
    P('IP', /(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}(?![A-Fa-f0-9:])/gd, { prio: 40 }),
    P('IP', /(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{1,4}:){1,6}:(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){0,5})?(?![A-Fa-f0-9:])/gd, { prio: 40 }),
    P('DOB', /\b(?:dob|date\s+of\s+birth|born(?:\s+on)?)\b[^\d\n]{0,10}?(\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4})/gid, { group: 1, prio: 55 }),
    P('MEDICAL', /\b(?:mrn|patient\s*id|medical\s+record(?:\s*(?:no|number))?)\b[^\w\n]{0,6}([A-Z0-9-]{5,})/gid, { group: 1, prio: 55 }),
    P('MEDICAL', /\b(?:diagnos(?:is|ed\s+with)|prescribed|prescription)\s*[:\-]?\s*([^.\n]{3,60})/gid, { group: 1, prio: 52 }),
    P('NAME', /\b(?:my\s+name\s+is|name\s*[:=]|[Dd]ear|Mr\.|Mrs\.|Ms\.|Dr\.|Shri|Smt\.?)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})/gd, { group: 1, prio: 35 }),
    P('SECRET', /(?<![A-Za-z0-9_-])[A-Za-z0-9_\-]{32,}(?![A-Za-z0-9_-])/gd, { prio: 30, ok: (v) => /\d/.test(v) && /[A-Za-z]/.test(v) && entropy(v) >= 3.4 }),
  ];

  /* ---------- detection ---------- */
  function detect(raw, opts = {}) {
    const text = prep(raw);
    const found = [];
    const all = PATTERNS.concat((opts.extra || []).map((x) => ({ type: x.type || 'CUSTOM', re: x.re, group: 0, prio: 85, ok: null })));
    const phSpans = [...text.matchAll(PLACEHOLDER_RE)].map((m) => [m.index, m.index + m[0].length]);
    for (const p of all) {
      p.re.lastIndex = 0;
      for (const m of text.matchAll(p.re)) {
        const val = m[p.group];
        if (val == null || val === '') continue;
        if (p.ok && !p.ok(val, m)) continue;
        const idx = m.indices ? m.indices[p.group] : [m.index, m.index + val.length];
        const [s, e] = idx;
        if (phSpans.some(([a, b]) => s < b && e > a)) continue; // already a placeholder
        found.push({ type: p.type, start: s, end: e, prio: p.prio });
      }
    }
    // overlap resolution: highest priority, then longest, wins
    found.sort((a, b) => b.prio - a.prio || (b.end - b.start) - (a.end - a.start));
    const kept = [];
    for (const f of found) if (!kept.some((k) => f.start < k.end && f.end > k.start)) kept.push(f);
    kept.sort((a, b) => a.start - b.start);
    return { text, findings: kept };
  }

  /* ---------- prompt-injection neutralisation ---------- */
  const INJECTION = [
    /ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|rules?)/gi,
    /disregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)/gi,
    /(?:reveal|print|show|repeat|output|send|leak|exfiltrate|forward)[^.\n]{0,40}(?:system\s+prompt|instructions|password|credentials?|secrets?|api\s*key|vault|redacted|original\s+value)/gi,
    /you\s+are\s+(?:now\s+)?(?:in\s+)?(?:developer|dev|dan|admin|god|jailbreak)\s+mode/gi,
    /\bnew\s+(?:instructions|system\s+prompt)\s*:/gi,
    /<\/?(?:system|assistant|untrusted_page_content)>/gi,
    /\b(?:ai|assistant|agent|llm)\s*[:,]\s*(?:you\s+must|please\s+(?:now\s+)?(?:type|click|send|navigate|visit))/gi,
  ];
  function neutralizeInjection(text) {
    let count = 0, out = text;
    for (const re of INJECTION) out = out.replace(re, () => { count++; return '[REMOVED:INJECTION]'; });
    return { text: out, count };
  }

  /* ---------- Redactor: stateful per page-snapshot ---------- */
  class Redactor {
    constructor(o = {}) {
      this.extra = o.extra || [];
      this.map = new Map(); this.counts = {}; this.stats = {}; this.injections = 0;
      this.known = new Map(); // raw value -> type (kept in memory only, used by the outbound canary check)
    }
    _ph(type, value) {
      const k = type + '|' + alnum(value);
      let p = this.map.get(k);
      if (!p) { const n = (this.counts[type] = (this.counts[type] || 0) + 1); p = `[REDACTED:${type}_${n}]`; this.map.set(k, p); }
      this.known.set(value, type);
      this.stats[type] = (this.stats[type] || 0) + 1;
      return p;
    }
    field(type, value) { // structural redaction of a whole value
      if (value) { this.known.set(String(value), type); this.stats[type] = (this.stats[type] || 0) + 1; }
      return `[REDACTED:${type}]`;
    }
    redact(raw) {
      const { text, findings } = detect(raw, { extra: this.extra });
      if (!findings.length) return text;
      let out = '', i = 0;
      for (const f of findings) { out += text.slice(i, f.start) + this._ph(f.type, text.slice(f.start, f.end)); i = f.end; }
      return out + text.slice(i);
    }
    sanitize(raw) {
      const r = neutralizeInjection(this.redact(raw));
      this.injections += r.count;
      return r.text;
    }
  }

  function compileRules(rules) {
    const out = [];
    for (const p of (rules && rules.patterns) || []) {
      try { out.push({ type: (p.type || 'CUSTOM').toUpperCase().replace(/[^A-Z_]/g, ''), re: new RegExp(p.pattern, 'gd') }); } catch (e) { /* bad user regex ignored */ }
    }
    return out;
  }

  /* ---------- outbound guard ---------- */
  function variantsOf(payload) {
    const v = [payload];
    try { const d = decodeURIComponent(payload.replace(/\+/g, ' ')); if (d !== payload) v.push(d); } catch (e) { /* not url-encoded */ }
    try { const j = JSON.parse(payload); const leaves = []; (function w(x) { if (typeof x === 'string') leaves.push(x); else if (x && typeof x === 'object') Object.values(x).forEach(w); })(j); v.push(leaves.join('\n')); } catch (e) { /* not json */ }
    for (const m of payload.matchAll(/[A-Za-z0-9+\/]{24,}={0,2}/g)) {
      try { const d = (typeof atob === 'function' ? atob(m[0]) : Buffer.from(m[0], 'base64').toString('latin1')); if (/[\x20-\x7e]{6,}/.test(d)) v.push(d); } catch (e) { /* ignore */ }
    }
    return v;
  }
  function leaks(raws, alns, val) {
    const v = String(val);
    if (v.length < 3) return false;
    const a = alnum(v);
    if (v.length >= 6) return raws.some((t) => t.includes(v)) || (a.length >= 6 && alns.some((t) => t.includes(a)));
    const re = new RegExp('(?<![A-Za-z0-9])' + escapeRe(v) + '(?![A-Za-z0-9])');
    return raws.some((t) => re.test(t));
  }
  /**
   * validateOutbound(textPayload, known) -> {ok, violations}
   * Violations never contain the offending value, only its type.
   */
  function validateOutbound(payload, known, opts = {}) {
    const violations = [];
    const raws = variantsOf(String(payload)).map((s) => prep(s).replace(PLACEHOLDER_RE, ' '));
    const alns = raws.map((s) => s.toLowerCase().replace(/[^a-z0-9]/g, ''));
    for (const r of raws) {
      for (const f of detect(r, { extra: opts.extra }).findings) violations.push({ kind: 'pattern', type: f.type });
    }
    for (const [val, type] of known || []) if (leaks(raws, alns, val)) violations.push({ kind: 'known_value', type });
    return { ok: violations.length === 0, violations };
  }

  return { PATTERNS, detect, Redactor, compileRules, neutralizeInjection, validateOutbound, luhn, verhoeff, verhoeffCheckDigit, entropy, prep, alnum, PLACEHOLDER_RE };
});
