// Task A: Sensitive Detection - Defense in Depth - JS version
class SensitiveDetector {
  constructor() {
    this.patterns = {
      AADHAAR: /\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b/g,
      PAN: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
      EMAIL: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
      PHONE_INDIA: /(?:\+91[\s-]?)?[6-9]\d{9}\b/g,
      CARD: /\b(?:\d[ -]*?){13,19}\b/g,
      OTP: /\b\d{4,8}\b/g,
      API_KEY:
        /\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b/g,
      IP: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    };
  }
  luhnCheck(card) {
    const digits = card.replace(/\D/g, "").split("").map(Number);
    if (digits.length < 13) return false;
    let sum = 0,
      dbl = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let d = digits[i];
      if (dbl) {
        d *= 2;
        if (d > 9) d -= 9;
      }
      sum += d;
      dbl = !dbl;
    }
    return sum % 10 === 0;
  }
  detectPatterns(text) {
    const findings = [];
    for (const [type, regex] of Object.entries(this.patterns)) {
      regex.lastIndex = 0;
      let m;
      while ((m = regex.exec(text)) !== null) {
        const val = m[0];
        if (type === "CARD" && !this.luhnCheck(val)) continue;
        if (type === "OTP") {
          const ctx = text
            .substring(Math.max(0, m.index - 30), m.index + 30)
            .toLowerCase();
          if (
            !ctx.includes("otp") &&
            !ctx.includes("code") &&
            !ctx.includes("verification")
          )
            continue;
        }
        findings.push({
          type,
          value: val,
          index: m.index,
          confidence: 0.95,
          layer: "L1-Pattern",
        });
      }
    }
    return findings;
  }
  detectStructural() {
    const findings = [];
    const els = document.querySelectorAll("input, textarea, [contenteditable]");
    const keywords = [
      "aadhaar",
      "pan",
      "card",
      "cc-number",
      "otp",
      "password",
      "api",
      "secret",
      "token",
      "cvv",
    ];
    els.forEach((el) => {
      const combined = [
        el.name,
        el.id,
        el.autocomplete,
        el.getAttribute("aria-label"),
        el.placeholder,
        el.type,
      ]
        .join(" ")
        .toLowerCase();
      keywords.forEach((kw) => {
        if (combined.includes(kw)) {
          findings.push({
            type: `FIELD:${kw.toUpperCase()}`,
            value: el.value || "",
            element: el,
            selector: this.getSelector(el),
            confidence: 0.9,
            layer: "L2-Structural",
            bbox: el.getBoundingClientRect(),
          });
        }
      });
    });
    return findings;
  }
  getSelector(el) {
    if (el.id) return `#${el.id}`;
    if (el.name) return `[name="${el.name}"]`;
    return el.tagName.toLowerCase();
  }
  // L3: AI-based mock - in production use Transformers.js Presidio
  detectAIContextual(text) {
    const findings = [];
    if (/my address is|residing at|permanent address/i.test(text)) {
      findings.push({
        type: "ADDRESS",
        value: text.slice(0, 100),
        confidence: 0.75,
        layer: "L3-AI",
      });
    }
    // Face detection would use MediaPipe here for video conferencing scenario
    return findings;
  }
  ensemble(text) {
    const p = this.detectPatterns(text);
    const s = this.detectStructural();
    const ai = this.detectAIContextual(text);
    const all = [...p, ...s, ...ai];
    // deduplicate
    const seen = new Set();
    const uniq = [];
    for (const f of all) {
      const key = `${f.type}:${(f.value || "").slice(0, 20)}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniq.push(f);
      }
    }
    return uniq;
  }
}
if (typeof self !== "undefined") self.SensitiveDetector = SensitiveDetector;
if (typeof window !== "undefined") window.SensitiveDetector = SensitiveDetector;
