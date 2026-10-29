/*
 * PrivacyLens – dom-sanitizer.js
 * Structural analysis of the live DOM. Produces (a) a sanitised text outline the LLM may see,
 * (b) a metadata table used to validate actions, (c) pixel regions to black out in screenshots,
 * and (d) a guarded action executor. Runs in the content script (and in Playwright for tests).
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PL = Object.assign(root.PL || {}, api);
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';
  const D = (typeof module === 'object' && module.exports) ? require('./detector.js') : globalThis.PL;

  const AUTOCOMPLETE = { 'cc-number': 'CARD', 'cc-csc': 'CVV', 'cc-exp': 'CARD_EXP', 'cc-exp-month': 'CARD_EXP', 'cc-exp-year': 'CARD_EXP', 'cc-name': 'NAME', 'one-time-code': 'OTP', 'current-password': 'PASSWORD', 'new-password': 'PASSWORD', email: 'EMAIL', username: 'USERNAME', tel: 'PHONE', name: 'NAME', 'given-name': 'NAME', 'family-name': 'NAME', 'street-address': 'ADDRESS', 'address-line1': 'ADDRESS', 'address-line2': 'ADDRESS', 'postal-code': 'ADDRESS', bday: 'DOB' };
  const LABEL_RULES = [
    [/pass(word|wd|code)?\b|\bpwd\b/i, 'PASSWORD'],
    [/\botp\b|one[- ]?time|verification code|\b2fa\b|\bmfa\b|auth(entication)? code/i, 'OTP'],
    [/\bcvv2?\b|\bcvc\b|\bcsc\b|security code/i, 'CVV'],
    [/expir|valid (thru|till)|mm\s*\/\s*yy/i, 'CARD_EXP'],
    [/card\s*(number|no|#)|credit card|debit card|cc[- ]?num/i, 'CARD'],
    [/aadhaar|aadhar|uidai/i, 'AADHAAR'],
    [/\bpan\b|permanent account/i, 'PAN'],
    [/\bssn\b|social security/i, 'SSN'],
    [/api[ _-]?key|secret|token|access key|private key/i, 'API_KEY'],
    [/account\s*(number|no)|\bifsc\b/i, 'ACCOUNT'],
    [/user ?name|login id/i, 'USERNAME'],
    [/e-?mail/i, 'EMAIL'],
    [/phone|mobile|\btel(ephone)?\b|contact no/i, 'PHONE'],
    [/(full|first|last|given|family|card ?holder|your) ?name/i, 'NAME'],
    [/address|street|pin ?code|postal|zip|\bcity\b/i, 'ADDRESS'],
    [/birth|\bdob\b/i, 'DOB'],
    [/diagnos|symptom|medical|prescription|allerg/i, 'MEDICAL'],
    [/\bip( address)?\b/i, 'IP'],
  ];
  const NAME_SELECTORS = ['.participant-name', '[data-participant-name]', '[class*="participant-name" i]', '[class*="attendee-name" i]', '[data-participant]'];
  const MESSAGE_SELECTORS = ['[data-private]', '.message-body', '[class*="chat-msg" i]', '[data-role="message"]'];
  const SKIP = new Set(['script', 'style', 'noscript', 'template', 'head', 'meta', 'link', 'svg', 'path']);
  const FREE_TYPES = new Set(['checkbox', 'radio', 'submit', 'button', 'image', 'reset', 'range', 'color', 'file']);
  const RISKY_LABEL = /\b(pay|payment|purchase|buy now|place (your )?order|complete order|confirm|submit|send|delete|remove account|transfer|withdraw|sign[ -]?in|log[ -]?in|authori[sz]e|approve|donate|subscribe|cancel (order|subscription))\b/i;

  const collapse = (s) => String(s || '').replace(/\s+/g, ' ').trim();
  const lc = (s) => (s || '').toLowerCase();

  function isHidden(el, win) {
    if (el.hidden) return true;
    const cs = win.getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.visibility === 'collapse') return true;
    if (parseFloat(cs.opacity) === 0 || parseFloat(cs.fontSize) === 0) return true;
    if (cs.position === 'absolute' || cs.position === 'fixed') {
      if (parseInt(cs.left, 10) <= -1000 || parseInt(cs.top, 10) <= -1000) return true;
    }
    if (parseInt(cs.textIndent, 10) <= -1000) return true;
    return false;
  }

  function classifyField(el, labelText) {
    const t = lc(el.getAttribute('type'));
    if (t === 'password') return 'PASSWORD';
    for (const tok of lc(el.getAttribute('autocomplete')).split(/\s+/)) if (AUTOCOMPLETE[tok]) return AUTOCOMPLETE[tok];
    if (el.hasAttribute('data-sensitive') || el.hasAttribute('data-pl-sensitive')) return 'USER_RULE';
    if (t === 'email') return 'EMAIL';
    if (t === 'tel') return 'PHONE';
    const hay = [el.getAttribute('name'), el.id, el.getAttribute('placeholder'), el.getAttribute('aria-label'), labelText].filter(Boolean).join(' ');
    for (const [re, type] of LABEL_RULES) if (re.test(hay)) return type;
    return null;
  }

  function matchRule(el, ctx) {
    const tryMatch = (sels) => sels.some((s) => { try { return el.matches(s); } catch (e) { return false; } });
    if (tryMatch(ctx.userSelectors)) return 'USER_RULE';
    if (tryMatch(NAME_SELECTORS)) return 'NAME';
    if (ctx.strictMessages && tryMatch(MESSAGE_SELECTORS)) return 'PRIVATE_MESSAGE';
    return null;
  }

  const looksSecret = (t) => t.length >= 16 && t.length <= 400 && !/\s/.test(t) && D.entropy(t) >= 3.0;

  function safeHref(href, base) {
    try { const u = new URL(href, base); return { text: u.origin + u.pathname, origin: u.origin }; } catch (e) { return { text: '', origin: '' }; }
  }

  function makeCtx(doc, opts) {
    return { userSelectors: (opts.rules && opts.rules.selectors) || [], strictMessages: opts.strictMessages !== false };
  }

  /* ---------- snapshot ---------- */
  function snapshot(doc, opts = {}) {
    const win = doc.defaultView;
    const R = opts.redactor || new D.Redactor({ extra: D.compileRules(opts.rules) });
    const ctx = makeCtx(doc, opts);
    const lines = [], meta = {}, registry = new Map();
    const stats = { hiddenSkipped: 0, hiddenInjection: 0, truncated: false };
    let n = 0, chars = 0;
    const MAX = opts.maxChars || 15000;

    const labelMap = new Map();
    for (const l of doc.getElementsByTagName('label')) { const f = l.getAttribute('for'); if (f) labelMap.set(f, (labelMap.get(f) || '') + ' ' + l.textContent); }
    const labelFor = (el) => {
      const parts = [el.getAttribute('aria-label')];
      const lb = el.getAttribute('aria-labelledby');
      if (lb) lb.split(/\s+/).forEach((id) => { const x = doc.getElementById(id); if (x) parts.push(x.textContent); });
      if (el.id && labelMap.has(el.id)) parts.push(labelMap.get(el.id));
      const wrap = el.closest && el.closest('label'); if (wrap) parts.push(wrap.textContent);
      return collapse(parts.filter(Boolean).join(' '));
    };

    const push = (raw, safe) => {
      if (chars > MAX) { stats.truncated = true; return; }
      lines.push({ raw, safe }); chars += safe.length;
    };
    const text = (t) => push(t, R.sanitize(t));
    const structural = (t, type) => { push(t, R.field(type, t)); };

    function walk(node) {
      if (node.nodeType === 3) { const t = collapse(node.nodeValue); if (t) text(t); return; }
      if (node.nodeType !== 1) return;
      const el = node, tag = el.tagName.toLowerCase();
      if (SKIP.has(tag)) return;
      if (isHidden(el, win)) {
        const t = collapse(el.textContent);
        if (t) { stats.hiddenSkipped++; if (D.neutralizeInjection(t).count) stats.hiddenInjection++; }
        return;
      }
      if (tag === 'video' || tag === 'canvas' || tag === 'iframe' || tag === 'object' || tag === 'embed') { push(`[${tag}]`, `[MEDIA:${tag} content hidden]`); return; }
      if (tag === 'img') {
        const alt = collapse(el.getAttribute('alt')); const hint = lc(alt + ' ' + el.className + ' ' + el.getAttribute('src'));
        if (/avatar|profile|photo|face|selfie|portrait/.test(hint)) push(`[IMG ${alt}]`, '[IMG:person/avatar hidden]'); else push(`[IMG ${alt}]`, `[IMG alt="${R.sanitize(alt)}"]`);
        return;
      }
      const rule = matchRule(el, ctx);
      if (rule && !el.matches('input,textarea,select,button')) { structural(collapse(el.textContent).slice(0, 300) || '(empty)', rule); return; }

      const role = lc(el.getAttribute('role'));
      const isInput = tag === 'input' || tag === 'textarea' || tag === 'select';
      const interactive = isInput || tag === 'button' || (tag === 'a' && el.hasAttribute('href')) ||
        ['button', 'link', 'checkbox', 'radio', 'tab', 'menuitem', 'switch', 'textbox', 'combobox'].includes(role) ||
        el.getAttribute('contenteditable') === 'true';
      if (interactive) {
        const typ = tag === 'input' ? (lc(el.getAttribute('type')) || 'text') : '';
        if (typ === 'hidden') return;
        const id = 'e' + (++n);
        registry.set(id, el);
        const lab = isInput ? labelFor(el) : collapse(el.textContent || el.getAttribute('aria-label') || el.value);
        const cls = (isInput || el.getAttribute('contenteditable') === 'true') && !FREE_TYPES.has(typ) ? (matchRule(el, ctx) || classifyField(el, lab)) : null;
        const m = { tag, type: typ, role, label: R.sanitize(lab).slice(0, 120), sensitive: cls, disabled: !!el.disabled, href: '', crossOrigin: false, formCrossOrigin: false, formSensitive: false, options: null };
        let rawLine = `[${id}] ${tag}${typ ? `[type=${typ}]` : ''}`, safeLine = rawLine;
        if (tag === 'a') { const h = safeHref(el.getAttribute('href'), doc.baseURI); m.href = R.sanitize(h.text); m.crossOrigin = !!h.origin && h.origin !== win.location.origin; }
        const lblRaw = lab.slice(0, 120);
        rawLine += ` label="${lblRaw}"`; safeLine += ` label="${m.label}"`;
        const ph = el.getAttribute('placeholder');
        if (ph) { rawLine += ` placeholder="${ph}"`; safeLine += ` placeholder="${R.sanitize(ph)}"`; }
        if (m.href) { safeLine += ` href="${m.href}"`; rawLine += ` href="${el.getAttribute('href')}"`; }
        if (m.crossOrigin) safeLine += ' external=true';
        if (cls) { safeLine += ` sensitive="${cls}"`; rawLine += ` sensitive="${cls}"`; }
        if (m.disabled) safeLine += ' disabled=true';
        if (typ === 'checkbox' || typ === 'radio') { const c = el.checked ? 'checked' : 'unchecked'; rawLine += ` ${c}`; safeLine += ` ${c}`; }
        else if (tag === 'select') {
          m.options = [...el.options].slice(0, 40).map((o) => R.sanitize(collapse(o.text)));
          const sel = el.selectedOptions[0] ? collapse(el.selectedOptions[0].text) : '';
          rawLine += ` value="${sel}"`; safeLine += ` value="${R.sanitize(sel)}" options=[${m.options.join(' | ')}]`;
        } else if (isInput || el.getAttribute('contenteditable') === 'true') {
          const v = tag === 'input' || tag === 'textarea' ? el.value : collapse(el.textContent);
          rawLine += ` value="${v}"`;
          safeLine += v ? (cls ? ` value="${R.field(cls, v)}"` : ` value="${R.sanitize(v)}"`) : ' value=""';
        }
        const f = el.form;
        if (f) {
          const fa = safeHref(f.getAttribute('action') || '', doc.baseURI);
          m.formCrossOrigin = !!fa.origin && fa.origin !== win.location.origin;
          m.formSensitive = [...f.elements].some((c) => c.tagName !== 'BUTTON' && !FREE_TYPES.has(lc(c.getAttribute('type'))) && lc(c.getAttribute('type')) !== 'hidden' && classifyField(c, ''));
        }
        m.risky = RISKY_LABEL.test(m.label) || (m.tag === 'button' || typ === 'submit') && m.formSensitive;
        meta[id] = m; push(rawLine, safeLine);
        return;
      }
      if (/^h[1-6]$/.test(tag)) { const t = collapse(el.textContent); if (t) push('# ' + t, '# ' + R.sanitize(t)); return; }
      if (['code', 'pre', 'kbd', 'samp'].includes(tag)) {
        const t = collapse(el.textContent);
        if (looksSecret(t)) { structural(t, 'SECRET'); return; }
      }
      for (const c of el.childNodes) walk(c);
      if (el.shadowRoot) for (const c of el.shadowRoot.childNodes) walk(c);
    }
    walk(doc.body);

    const u = safeHref(win.location.href, win.location.href);
    return {
      url: R.sanitize(u.text || 'about:blank'), title: R.sanitize(collapse(doc.title)),
      text: lines.map((l) => l.safe).join('\n'), rawText: lines.map((l) => l.raw).join('\n'),
      lines, meta, registry, stats: Object.assign(stats, { redactions: R.stats, injections: R.injections }),
      known: [...R.known.entries()],
    };
  }

  /* ---------- screenshot regions (viewport CSS px) ---------- */
  function collectRegions(doc, opts = {}) {
    const win = doc.defaultView, out = [], ctx = makeCtx(doc, opts);
    const vw = win.innerWidth, vh = win.innerHeight;
    const add = (r) => { if (r.width > 0 && r.height > 0 && r.bottom > 0 && r.right > 0 && r.top < vh && r.left < vw) out.push({ x: r.left, y: r.top, w: r.width, h: r.height }); };
    const labelText = (el) => collapse((el.getAttribute('aria-label') || '') + ' ' + ((el.closest && el.closest('label')) ? el.closest('label').textContent : ''));
    for (const el of doc.querySelectorAll('input,textarea,select,[contenteditable="true"]')) {
      const t = lc(el.getAttribute('type'));
      if (t === 'hidden' || FREE_TYPES.has(t)) continue;
      if (matchRule(el, ctx) || classifyField(el, labelText(el))) add(el.getBoundingClientRect());
    }
    for (const el of doc.querySelectorAll('video,canvas,iframe,img')) {
      const hint = lc(el.getAttribute('alt') + ' ' + el.className + ' ' + el.getAttribute('src'));
      if (el.tagName !== 'IMG' || /avatar|profile|photo|face|selfie|portrait/.test(hint)) add(el.getBoundingClientRect());
    }
    for (const el of doc.querySelectorAll('*')) {
      if (el.matches('input,textarea,select,script,style')) continue;
      const hit = matchRule(el, ctx) || (['CODE', 'PRE', 'KBD', 'SAMP'].includes(el.tagName) && looksSecret(collapse(el.textContent)));
      if (hit) add(el.getBoundingClientRect());
    }
    const tw = doc.createTreeWalker(doc.body, 4);
    const extra = D.compileRules(opts.rules);
    for (let nd = tw.nextNode(); nd; nd = tw.nextNode()) {
      const par = nd.parentElement;
      if (!par || SKIP.has(par.tagName.toLowerCase()) || isHidden(par, win)) continue;
      const data = nd.nodeValue; if (!data || !data.trim()) continue;
      const { text: pt, findings } = D.detect(data, { extra });
      if (!findings.length) continue;
      if (pt !== data) { add(par.getBoundingClientRect()); continue; } // offsets unreliable after normalisation
      for (const f of findings) {
        const r = doc.createRange(); r.setStart(nd, f.start); r.setEnd(nd, f.end);
        for (const rc of r.getClientRects()) add(rc);
      }
    }
    return { regions: out, viewportWidth: vw, viewportHeight: vh };
  }

  /* ---------- guarded executor ---------- */
  const setNative = (el, v) => {
    const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const d = Object.getOwnPropertyDescriptor(proto, 'value'); d && d.set ? d.set.call(el, v) : (el.value = v);
  };
  async function execute(doc, registry, action, resolveSecret, opts = {}) {
    const win = doc.defaultView, ctx = makeCtx(doc, opts);
    if (action.action === 'scroll') { win.scrollBy(0, (action.direction === 'up' ? -1 : 1) * Math.round(win.innerHeight * 0.8)); return { ok: true }; }
    if (action.action === 'wait') return { ok: true };
    const el = registry.get(action.target);
    if (!el || !el.isConnected) return { ok: false, msg: 'target no longer in DOM' };
    if (isHidden(el, win) || el.disabled) return { ok: false, msg: 'target hidden or disabled at execution time' };
    if (action.action === 'click') { el.click(); return { ok: true }; }
    if (action.action === 'select') {
      const o = [...el.options].find((x) => collapse(x.text) === action.value);
      if (!o) return { ok: false, msg: 'option not found' };
      el.value = o.value; el.dispatchEvent(new Event('change', { bubbles: true })); return { ok: true };
    }
    if (action.action === 'type') {
      // TOCTOU re-check: classify again at execution time
      const lab = collapse((el.getAttribute('aria-label') || '') + ' ' + (el.closest('label') ? el.closest('label').textContent : ''));
      const cls = matchRule(el, ctx) || classifyField(el, lab);
      const ref = /^\{\{vault:([a-z0-9_]{1,40})\}\}$/i.exec(action.value);
      let value = action.value;
      if (ref) {
        value = await resolveSecret(ref[1]);
        if (value == null) return { ok: false, msg: 'vault key unavailable for this origin' };
      } else if (cls) return { ok: false, msg: 'sensitive field requires vault reference' };
      el.focus();
      if (el.getAttribute('contenteditable') === 'true') el.textContent = value; else setNative(el, value);
      el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true }));
      return { ok: true };
    }
    return { ok: false, msg: 'unsupported action' };
  }

  return { snapshot, collectRegions, execute, classifyField, isHidden };
});
