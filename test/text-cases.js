// Annotated text corpus. All values are synthetic and generated at load time from a seeded PRNG.
const D = require('../src/detector.js');
let seed = 7;
const rnd = () => { seed |= 0; seed = (seed + 0x6D2B79F5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const chars = (n, set) => Array.from({ length: n }, () => set[Math.floor(rnd() * set.length)]).join('');
const AN = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', DG = '0123456789', UP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const aad = () => { const p = '23456789'[Math.floor(rnd() * 8)] + chars(10, DG); const d = p + D.verhoeffCheckDigit(p); return d.slice(0, 4) + ' ' + d.slice(4, 8) + ' ' + d.slice(8); };
const A1 = aad(), A2 = aad().replace(/ /g, ''), SK = 'sk_live_' + chars(24, AN), AWS = 'AKIA' + chars(16, UP), GH = 'ghp_' + chars(36, AN), XOX = 'xoxb-' + chars(12, DG) + '-' + chars(24, AN);
const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJ' + chars(30, AN) + '.' + chars(43, AN), HEX = chars(40, 'abcdef0123456789') + 'Z9', GEN = chars(28, AN);

// [type, text, [values that must not survive]]
const positives = [
  ['AADHAAR', `My Aadhaar is ${A1}.`, [A1]], ['AADHAAR', `UID ${A2}`, [A2]], ['AADHAAR', 'Aadhaar number: 1234 5678 9012', ['1234 5678 9012']],
  ['PAN', 'PAN: ABCPE1234F', ['ABCPE1234F']], ['PAN', 'Tax id BNZAA2318J on file', ['BNZAA2318J']],
  ['EMAIL', 'Contact asha.verma+shop@example.com today', ['asha.verma+shop@example.com']], ['EMAIL', 'cc: rohan_iyer99@mail.example.co.in', ['rohan_iyer99@mail.example.co.in']],
  ['PHONE', 'Call +91 98765 43210', ['98765 43210']], ['PHONE', 'Mobile 9876543210', ['9876543210']], ['PHONE', 'Reach me at (415) 555-0132', ['(415) 555-0132']], ['PHONE', 'Office +44 20 7946 0958', ['+44 20 7946 0958']],
  ['CARD', 'Card 4111 1111 1111 1111', ['4111 1111 1111 1111']], ['CARD', 'Pay with 4111-1111-1111-1111', ['4111-1111-1111-1111']], ['CARD', 'MC 5555555555554444', ['5555555555554444']], ['CARD', 'Amex 3782 822463 10005', ['3782 822463 10005']], ['CARD', 'number: 4000 0566 5566 5556', ['4000 0566 5566 5556']],
  ['CVV', 'CVV: 123', ['123']], ['CVV', 'cvc 4821', ['4821']], ['CARD_EXP', 'Expiry date 09/29', ['09/29']],
  ['OTP', 'Your OTP is 482913', ['482913']], ['OTP', '739204 is your verification code', ['739204']], ['OTP', 'one-time password: 4821', ['4821']],
  ['PASSWORD', 'password: hunter2xyz', ['hunter2xyz']], ['PASSWORD', 'my password is Tr0ub4dor', ['Tr0ub4dor']],
  ['API_KEY', `Stripe key ${SK}`, [SK]], ['API_KEY', `aws_access_key_id=${AWS}`, [AWS]], ['API_KEY', `token ${GH}`, [GH]], ['API_KEY', `slack ${XOX}`, [XOX]],
  ['API_KEY', `Authorization: Bearer ${GEN}`, [GEN]], ['API_KEY', `api_key = "${GEN}"`, [GEN]], ['JWT', `session ${JWT}`, [JWT]],
  ['PRIVATE_KEY', `-----BEGIN RSA PRIVATE KEY-----\n${chars(64, AN)}\n-----END RSA PRIVATE KEY-----`, []],
  ['SECRET', `build id ${HEX}`, [HEX]],
  ['IP', 'Server 203.0.113.45 is down', ['203.0.113.45']], ['IP', 'gateway 10.0.4.17', ['10.0.4.17']], ['IP', 'v6 2001:db8::1f', ['2001:db8::1f']], ['IP', 'full 2001:0db8:85a3:0000:0000:8a2e:0370:7334', ['2001:0db8:85a3:0000:0000:8a2e:0370:7334']],
  ['SSN', 'SSN 123-45-6789', ['123-45-6789']], ['IFSC', 'IFSC HDFC0001234', ['HDFC0001234']], ['ACCOUNT', 'Account number 123456789012', ['123456789012']],
  ['DOB', 'DOB: 14/02/1990', ['14/02/1990']], ['UPI', 'Pay to asha@okaxis', ['asha@okaxis']], ['MEDICAL', 'MRN: 00482913', ['00482913']], ['MEDICAL', 'Diagnosis: type 2 diabetes', ['type 2 diabetes']],
  ['NAME', 'Dear Asha Verma, your claim is ready', ['Asha Verma']],
];
// Evasion / obfuscation: the zero-width and full-width variants must still be caught
const evasion = [
  ['CARD', 'Card 4111\u200B 1111\u200B 1111\u200B 1111', ['4111111111111111']],
  ['CARD', 'Card \uFF14\uFF11\uFF11\uFF11 \uFF11\uFF11\uFF11\uFF11 \uFF11\uFF11\uFF11\uFF11 \uFF11\uFF11\uFF11\uFF11', ['4111111111111111']],
  ['EMAIL', 'mail asha\u200B@exam\u200Bple.com', ['asha@example.com']],
  ['AADHAAR', `id ${A1.split(' ').join('\u00AD ')}`, [A2 === A1 ? A1.replace(/ /g, '') : A1.replace(/ /g, '')]],
  ['CARD', 'Card 4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1', ['4111111111111111']],
];
// Benign text that looks superficially like PII. Any finding here is a false positive.
const negatives = [
  'Total ₹2,598.00 including GST', 'Order #BK-20931 shipped on 2025-10-29', 'Version v1.2.3 released', 'Meeting at 12:30:45 sharp', 'SKU-48213-BLK in stock',
  'Reference 123456789012 not an Aadhaar', 'Serial 1234 5678 9012 3456', 'Call 1800 123 for support', 'Password must be at least 8 characters', 'Password is required',
  'Enter your email address below', 'Add to cart', 'Your cart has 3 items', 'Pincode must be 6 digits', 'Rated 4.5 out of 5 by 1,284 customers', 'Open Mon–Sat 9:00–18:00',
  'Delivery in 2-3 business days', 'Use code SAVE20 at checkout', 'Page 12 of 340', 'Copyright 2026 Blue Kettle Store', 'Order summary', 'Click Sign in to continue',
  'Weekly sync with 4 participants', 'Item weight 1.25 kg', 'Free shipping above ₹499', 'Colour: Matte black', 'Ships from Jodhpur, Rajasthan',
];
// Encoded smuggling attempts against the outbound guard (must be BLOCKED)
const enc = (s) => Buffer.from(s).toString('base64');
const outboundAttacks = [
  ['plain card', JSON.stringify([{ content: 'card 4111 1111 1111 1111' }])],
  ['url-encoded email', JSON.stringify([{ content: 'q=' + encodeURIComponent('asha@example.com') }])],
  ['base64 card', JSON.stringify([{ content: 'blob ' + enc('card 4111 1111 1111 1111 exp') }])],
  ['zero-width aadhaar', JSON.stringify([{ content: A1.split(' ').join('\u200B ') }])],
  ['api key', JSON.stringify([{ content: SK }])],
  ['private key header', JSON.stringify([{ content: '-----BEGIN PRIVATE KEY-----\nabc' }])],
];
module.exports = { positives, evasion, negatives, outboundAttacks };
