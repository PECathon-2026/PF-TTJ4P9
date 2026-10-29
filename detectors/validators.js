const D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];
const INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

export const digitsOnly = (s) => String(s).replace(/\D/g, "");
const allSame = (s) => /^(\d)\1+$/.test(s);

export function luhn(num) {
  const s = digitsOnly(num);
  if (s.length < 13 || s.length > 19 || allSame(s)) return false;
  let sum = 0,
    alt = false;
  for (let i = s.length - 1; i >= 0; i--) {
    let n = +s[i];
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export function verhoeff(num) {
  const rev = digitsOnly(num).split("").reverse();
  let c = 0;
  for (let i = 0; i < rev.length; i++) c = D[c][P[i % 8][+rev[i]]];
  return c === 0;
}

// Used by tests/demo to generate synthetic valid Aadhaar numbers
export function verhoeffCheckDigit(num) {
  const rev = digitsOnly(num).split("").reverse();
  let c = 0;
  for (let i = 0; i < rev.length; i++) c = D[c][P[(i + 1) % 8][+rev[i]]];
  return INV[c];
}

export function isAadhaar(raw) {
  const s = digitsOnly(raw);
  return s.length === 12 && /^[2-9]/.test(s) && !allSame(s) && verhoeff(s);
}

export function isPAN(raw) {
  // 4th char = holder type
  return /^[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]$/.test(raw);
}

export function shannonEntropy(s) {
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const k in freq) {
    const p = freq[k] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function looksLikeSecret(tok) {
  return (
    tok.length >= 24 &&
    /\d/.test(tok) &&
    /[A-Za-z]/.test(tok) &&
    shannonEntropy(tok) >= 3.6
  );
}
