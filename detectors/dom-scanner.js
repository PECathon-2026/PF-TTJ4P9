import { detectText } from "./text-detector.js";
import { classifyField, matchHint } from "./dom-rules.js";

const SKIP = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE"]);
const ATTRS = ["value", "title", "alt", "aria-label", "href", "content"];
const FIELD_TAGS = new Set(["INPUT", "TEXTAREA", "SELECT"]);

// Walks light DOM + open shadow roots + same-origin iframes
function* walk(root) {
  const stack = [root];
  while (stack.length) {
    const node = stack.pop();
    yield node;
    if (node.nodeType === 1) {
      if (node.shadowRoot) stack.push(node.shadowRoot);
      if (node.tagName === "IFRAME") {
        try {
          if (node.contentDocument) stack.push(node.contentDocument);
        } catch {
          /* cross-origin */
        }
      }
    }
    const kids = node.childNodes;
    for (let i = kids.length - 1; i >= 0; i--) stack.push(kids[i]);
  }
}

function looksLikeValue(type, v) {
  if (!v || v.length > 60 || matchHint(v)) return false;
  if (type === "ADDRESS") return true;
  return /[\d@]/.test(v) || /^\S{8,}$/.test(v);
}

// Label-proximity: "CVV: 123"  or  <span>CVV</span><span>123</span>
function contextual(node, text) {
  const m = text.match(/^\s*([^:\n]{2,30}):\s*(\S.{0,59})$/);
  if (m) {
    const type = matchHint(m[1]);
    const value = m[2].trimEnd();
    if (type && looksLikeValue(type, value)) {
      const start = text.length - m[2].length;
      return {
        type,
        start,
        end: start + value.length,
        confidence: 0.75,
        reason: `label hint (${type.toLowerCase()}) before value`,
      };
    }
  }
  const label = (
    node.parentElement.previousElementSibling?.textContent || ""
  ).trim();
  if (label && label.length <= 40) {
    const type = matchHint(label);
    const value = text.trim();
    if (type && looksLikeValue(type, value)) {
      const start = text.indexOf(value);
      return {
        type,
        start,
        end: start + value.length,
        confidence: 0.7,
        reason: `adjacent label hint (${type.toLowerCase()})`,
      };
    }
  }
  return null;
}

function scanTextNode(node, push, opts) {
  const p = node.parentElement;
  if (!p || SKIP.has(p.tagName) || p.tagName === "TEXTAREA") return;
  const text = node.nodeValue;
  if (!text || !text.trim()) return;

  const hits = detectText(text, opts);
  for (const h of hits) push({ ...h, kind: "text", node, element: p });
  if (hits.length) return;

  const c = contextual(node, text);
  if (c) push({ ...c, layer: "context", kind: "text", node, element: p });
}

function scanElement(el, push, opts) {
  if (SKIP.has(el.tagName)) return;

  for (const sel of opts.selectors || []) {
    // user-defined CSS selectors
    try {
      if (el.matches(sel))
        push({
          type: "USER_RULE",
          confidence: 1,
          reason: "user selector rule",
          layer: "dom",
          kind: "element",
          element: el,
        });
    } catch {
      /* bad selector */
    }
  }

  const isField = FIELD_TAGS.has(el.tagName);
  const cls = classifyField(el);
  if (cls) {
    const v = String(el.value ?? "");
    push({
      ...cls,
      kind: "field",
      element: el,
      empty: v === "",
      length: v.length,
    });
  } else if (isField && el.tagName !== "SELECT") {
    for (const h of detectText(String(el.value || ""), opts))
      push({ ...h, kind: "field-value", element: el });
  }

  for (const a of ATTRS) {
    if (a === "value" && isField) continue;
    const v = el.getAttribute(a);
    if (!v || v.length > 2000 || v.startsWith("data:")) continue;
    for (const h of detectText(v, opts))
      push({ ...h, kind: "attr", attr: a, element: el });
  }
}

export function scanDom(root = document, opts = {}) {
  const t0 = performance.now();
  const findings = [];
  const push = (f) => findings.push({ id: findings.length, ...f });

  for (const node of walk(root)) {
    if (node.nodeType === 3) scanTextNode(node, push, opts);
    else if (node.nodeType === 1) scanElement(node, push, opts);
  }
  return { findings, ms: Math.round((performance.now() - t0) * 10) / 10 };
}

function cssPath(el) {
  const parts = [];
  for (
    let n = el;
    n && n.nodeType === 1 && parts.length < 4;
    n = n.parentElement
  ) {
    let s = n.tagName.toLowerCase();
    if (n.id) {
      parts.unshift(s + "#" + CSS.escape(n.id));
      break;
    }
    const same = n.parentElement
      ? [...n.parentElement.children].filter((c) => c.tagName === n.tagName)
      : [];
    if (same.length > 1) s += `:nth-of-type(${same.indexOf(n) + 1})`;
    parts.unshift(s);
  }
  return parts.join(" > ");
}

// Safe-to-send-to-popup/log version: no DOM refs, no values
export function toReport(findings) {
  return findings.map((f) => ({
    id: f.id,
    type: f.type,
    kind: f.kind,
    layer: f.layer,
    confidence: f.confidence,
    reason: f.reason,
    attr: f.attr,
    empty: f.empty,
    length: f.length ?? f.end - f.start,
    where: f.element ? cssPath(f.element) : null,
  }));
}

export function summarize(findings) {
  const byType = {},
    byLayer = {};
  for (const f of findings) {
    byType[f.type] = (byType[f.type] || 0) + 1;
    byLayer[f.layer] = (byLayer[f.layer] || 0) + 1;
  }
  return { total: findings.length, byType, byLayer };
}
