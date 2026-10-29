import { luhn, isAadhaar, isPAN } from "./validators.js";

export const PATTERNS = [
  // ---- Financial / government IDs (checksum validated) ----
  {
    type: "CARD",
    priority: 90,
    confidence: 0.97,
    re: /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g,
    validate: luhn,
    reason: "13-19 digits passing Luhn checksum",
  },
  {
    type: "AADHAAR",
    priority: 85,
    confidence: 0.95,
    re: /(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)/g,
    validate: isAadhaar,
    reason: "12 digits passing Verhoeff checksum",
  },
  {
    type: "PAN",
    priority: 85,
    confidence: 0.95,
    re: /\b[A-Z]{5}\d{4}[A-Z]\b/gi,
    validate: (v) => isPAN(v.toUpperCase()),
    reason: "PAN format AAAAA9999A",
  },
  {
    type: "IFSC",
    priority: 65,
    confidence: 0.85,
    re: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
    reason: "IFSC format",
  },
  {
    type: "UPI",
    priority: 70,
    confidence: 0.85,
    re: /\b[\w.-]{2,}@(?:ok\w+|ybl|paytm|upi|axl|ibl|sbi|apl)\b/gi,
    reason: "UPI handle",
  },

  // ---- Contact ----
  {
    type: "EMAIL",
    priority: 80,
    confidence: 0.95,
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    reason: "email address format",
  },
  {
    type: "PHONE",
    priority: 70,
    confidence: 0.85,
    re: /(?<!\d)(?:(?:\+91|91|0)[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)/g,
    reason: "Indian mobile number format",
  },

  // ---- Network ----
  {
    type: "IP",
    priority: 60,
    confidence: 0.8,
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    validate: (v) => v !== "0.0.0.0",
    reason: "IPv4 address",
  },
  {
    type: "IP",
    priority: 60,
    confidence: 0.8,
    re: /\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/g,
    reason: "IPv6 address",
  },

  // ---- Secrets / tokens ----
  {
    type: "API_KEY",
    priority: 88,
    confidence: 0.97,
    re: /\b(?:sk-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g,
    reason: "known API key prefix",
  },
  {
    type: "TOKEN",
    priority: 88,
    confidence: 0.95,
    re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    reason: "JWT structure",
  },
  {
    type: "TOKEN",
    priority: 80,
    confidence: 0.9,
    group: 1,
    re: /\bBearer\s+([A-Za-z0-9._~+\/-]{16,}=*)/g,
    reason: "Bearer token",
  },
  {
    type: "PRIVATE_KEY",
    priority: 95,
    confidence: 0.99,
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    reason: "PEM private key block",
  },
  {
    type: "API_KEY",
    priority: 75,
    confidence: 0.8,
    group: 1,
    re: /(?:api[_-]?key|secret|token|access[_-]?key)\s*[:=]\s*["']?([A-Za-z0-9._\-\/+=]{8,})/gi,
    validate: (v) => /\d/.test(v),
    reason: "secret assignment (key=value)",
  },

  // ---- Contextual ----
  {
    type: "OTP",
    priority: 82,
    confidence: 0.9,
    group: 1,
    re: /(?:otp|one[- ]time (?:password|code)|verification code|security code|auth(?:entication)? code|passcode)\D{0,20}?(\d{4,8})(?!\d)/gi,
    reason: "digits following OTP/code keyword",
  },
  {
    type: "PASSWORD",
    priority: 85,
    confidence: 0.9,
    group: 1,
    re: /(?:password|passwd|pwd)\s*(?:[:=]|\bis\b)\s*["']?([^\s"']{3,})/gi,
    reason: "value following password keyword",
  },
];
