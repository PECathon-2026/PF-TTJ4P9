// (?<![a-z]) / (?![a-z]) so "otp" matches "user_otp" but not "footprint"
const w = (alts) => new RegExp(`(?<![a-z])(?:${alts})(?![a-z])`, "i");

// Order matters: specific before general
export const FIELD_HINTS = [
  ["PASSWORD", w("password|passwd|pwd|passphrase")],
  ["CVV", w("cvv|cvc|csc|security[\\s_-]?code")],
  [
    "CARD",
    w(
      "card[\\s_-]?(?:number|no|num)|cc[\\s_-]?(?:number|num|no)|credit[\\s_-]?card|debit[\\s_-]?card",
    ),
  ],
  [
    "OTP",
    w(
      "otp|one[\\s_-]?time|verification[\\s_-]?code|auth(?:entication)?[\\s_-]?code|2fa|mfa",
    ),
  ],
  ["AADHAAR", w("aadhaar|aadhar|uidai")],
  ["PAN", w("pan[\\s_-]?(?:number|no|card)|permanent[\\s_-]?account")],
  [
    "API_KEY",
    w(
      "api[\\s_-]?key|secret|access[\\s_-]?key|client[\\s_-]?secret|private[\\s_-]?key",
    ),
  ],
  ["TOKEN", w("token|bearer|jwt|session[\\s_-]?id")],
  ["ACCOUNT", w("account[\\s_-]?(?:number|no)|ifsc|iban|upi")],
  ["EMAIL", w("e[\\s_-]?mail")],
  ["PHONE", w("phone|mobile|telephone|tel|contact[\\s_-]?(?:no|number)")],
  ["ADDRESS", w("address|street|pincode|zip|postal")],
];

const AUTOCOMPLETE = {
  "cc-number": "CARD",
  "cc-csc": "CVV",
  "cc-exp": "CARD_EXPIRY",
  "cc-exp-month": "CARD_EXPIRY",
  "cc-exp-year": "CARD_EXPIRY",
  "cc-name": "NAME",
  "one-time-code": "OTP",
  "current-password": "PASSWORD",
  "new-password": "PASSWORD",
  email: "EMAIL",
  tel: "PHONE",
  name: "NAME",
  "given-name": "NAME",
  "family-name": "NAME",
  "street-address": "ADDRESS",
  "address-line1": "ADDRESS",
  "address-line2": "ADDRESS",
  "postal-code": "ADDRESS",
  bday: "DOB",
};

const NON_TEXT = new Set([
  "button",
  "submit",
  "reset",
  "checkbox",
  "radio",
  "image",
  "file",
  "range",
  "color",
]);

export function matchHint(str) {
  if (!str) return null;
  for (const [type, re] of FIELD_HINTS) if (re.test(str)) return type;
  return null;
}

export function labelText(el) {
  const parts = [];
  if (el.labels) for (const l of el.labels) parts.push(l.textContent);
  const ids = el.getAttribute("aria-labelledby");
  if (ids) {
    const root = el.getRootNode();
    for (const id of ids.split(/\s+/)) {
      const n = root.getElementById?.(id);
      if (n) parts.push(n.textContent);
    }
  }
  return parts.join(" ");
}

export function classifyField(el) {
  if (!["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName)) return null;
  const t = (el.getAttribute("type") || "text").toLowerCase();
  if (NON_TEXT.has(t)) return null;

  if (t === "password")
    return {
      type: "PASSWORD",
      confidence: 1,
      reason: "input type=password",
      layer: "dom",
    };

  for (const tok of (el.getAttribute("autocomplete") || "")
    .toLowerCase()
    .split(/\s+/)) {
    if (AUTOCOMPLETE[tok])
      return {
        type: AUTOCOMPLETE[tok],
        confidence: 0.95,
        reason: `autocomplete=${tok}`,
        layer: "dom",
      };
  }
  if (t === "email")
    return {
      type: "EMAIL",
      confidence: 0.9,
      reason: "input type=email",
      layer: "dom",
    };
  if (t === "tel")
    return {
      type: "PHONE",
      confidence: 0.9,
      reason: "input type=tel",
      layer: "dom",
    };

  const attrs = ["name", "id", "placeholder", "aria-label", "title"]
    .map((a) => el.getAttribute(a) || "")
    .join(" ");
  let type = matchHint(attrs);
  if (type)
    return {
      type,
      confidence: 0.8,
      reason: `field attribute hint (${type.toLowerCase()})`,
      layer: "dom",
    };

  type = matchHint(labelText(el));
  if (type)
    return {
      type,
      confidence: 0.75,
      reason: `field label hint (${type.toLowerCase()})`,
      layer: "dom",
    };

  return null;
}
