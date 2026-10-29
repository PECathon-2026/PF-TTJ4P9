import { PATTERNS } from "./patterns.js";
import { looksLikeSecret } from "./validators.js";

function resolveOverlaps(items) {
  items.sort(
    (a, b) =>
      b.priority - a.priority ||
      b.end - b.start - (a.end - a.start) ||
      a.start - b.start,
  );
  const kept = [];
  for (const it of items) {
    if (!kept.some((k) => it.start < k.end && k.start < it.end)) kept.push(it);
  }
  return kept.sort((a, b) => a.start - b.start);
}

/**
 * opts.customRules: [{ type, pattern, flags }]  (user-defined rules)
 * Returns findings WITHOUT raw values: { type, start, end, confidence, reason, layer }
 */
export function detectText(text, opts = {}) {
  if (!text || typeof text !== "string") return [];
  const raw = [];

  for (const p of PATTERNS) {
    for (const m of text.matchAll(p.re)) {
      const value = p.group ? m[p.group] : m[0];
      if (!value) continue;
      if (p.validate && !p.validate(value)) continue;
      const start = p.group ? m.index + m[0].lastIndexOf(value) : m.index;
      raw.push({
        type: p.type,
        start,
        end: start + value.length,
        confidence: p.confidence,
        priority: p.priority,
        reason: p.reason,
        layer: "pattern",
      });
    }
  }

  // High-entropy fallback (unknown secret formats)
  for (const m of text.matchAll(/[A-Za-z0-9+\/_=-]{24,}/g)) {
    if (looksLikeSecret(m[0])) {
      raw.push({
        type: "SECRET",
        start: m.index,
        end: m.index + m[0].length,
        confidence: 0.6,
        priority: 40,
        reason: "high-entropy string",
        layer: "pattern",
      });
    }
  }

  // User-defined rules
  for (const r of opts.customRules || []) {
    try {
      const re = new RegExp(
        r.pattern,
        (r.flags || "g").includes("g") ? r.flags : (r.flags || "") + "g",
      );
      for (const m of text.matchAll(re)) {
        raw.push({
          type: r.type || "CUSTOM",
          start: m.index,
          end: m.index + m[0].length,
          confidence: 1,
          priority: 100,
          reason: "user-defined rule",
          layer: "pattern",
        });
      }
    } catch {
      /* ignore invalid user regex */
    }
  }

  return resolveOverlaps(raw).map(({ priority, ...f }) => f);
}

// Preview of Step 3: replace spans with placeholders
export function redactText(text, findings) {
  let out = text;
  for (const f of [...findings].sort((a, b) => b.start - a.start)) {
    out = out.slice(0, f.start) + `[REDACTED:${f.type}]` + out.slice(f.end);
  }
  return out;
}
