import test from "node:test";
import assert from "node:assert/strict";
import { detectText, redactText } from "../src/detectors/text-detector.js";
import { verhoeffCheckDigit } from "../src/detectors/validators.js";

const types = (t) => detectText(t).map((f) => f.type);
const base = "23456789012";
const AADHAAR = base + verhoeffCheckDigit(base); // synthetic, checksum-valid

test("card (Luhn valid)", () => {
  assert.deepEqual(types("Card 4111 1111 1111 1111"), ["CARD"]);
  assert.deepEqual(types("5555 5555 5555 4444"), ["CARD"]); // beats Aadhaar overlap
  assert.deepEqual(types("3782 822463 10005"), ["CARD"]); // Amex
});
test("card (Luhn invalid) is NOT flagged", () => {
  assert.deepEqual(types("Order #4111111111111112"), []);
});
test("aadhaar", () => {
  assert.deepEqual(types(`UID ${AADHAAR}`), ["AADHAAR"]);
  assert.deepEqual(types("UID 2345 6789 0123"), []); // bad checksum (very likely)
});
test("pan / email / phone / ifsc", () => {
  assert.deepEqual(types("PAN ABCPE1234F"), ["PAN"]);
  assert.deepEqual(types("mail test.user@example.com"), ["EMAIL"]);
  assert.deepEqual(types("Call +91 98765 43210"), ["PHONE"]);
  assert.deepEqual(types("IFSC HDFC0001234"), ["IFSC"]);
});
test("otp and password context", () => {
  assert.deepEqual(types("Your OTP is 482915"), ["OTP"]);
  assert.deepEqual(types("password: Secret@123"), ["PASSWORD"]);
});
test("api keys and tokens", () => {
  assert.deepEqual(types("AKIAIOSFODNN7EXAMPLE"), ["API_KEY"]);
  assert.deepEqual(types("sk-abcdefghijklmnopqrstuvwx1234"), ["API_KEY"]);
  assert.deepEqual(
    types(
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEFghi123_-xyzABC",
    ),
    ["TOKEN"],
  );
  assert.deepEqual(types("API_KEY=abcd1234efgh5678"), ["API_KEY"]);
});
test("ip", () => {
  assert.deepEqual(types("server 192.168.1.20"), ["IP"]);
});
test("benign text is untouched", () => {
  for (const s of [
    "Total: 4999 rupees",
    "Date 2026-10-29",
    "Price ₹1,299.00",
    "Place order",
  ])
    assert.deepEqual(types(s), []);
});
test("redaction output has no raw value", () => {
  const t = "Card 4111 1111 1111 1111 mail a@b.com";
  const out = redactText(t, detectText(t));
  assert.equal(out, "Card [REDACTED:CARD] mail [REDACTED:EMAIL]");
});
test("findings never carry the raw value", () => {
  const f = detectText("mail a@b.com")[0];
  assert.ok(!Object.values(f).includes("a@b.com"));
});
