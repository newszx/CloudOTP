import test from "node:test";
import assert from "node:assert/strict";
import { constantTimeEqual, createSession, decryptText, encryptText, normalizeSecret, totp, verifySession } from "../src/crypto.js";

test("CloudOTP TOTP matches RFC 6238 SHA-1 test vector", async () => {
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.equal(await totp(secret, 59_000), "287082");
});

test("encrypted values round-trip and reject the wrong key", async () => {
  const encrypted = await encryptText("JBSWY3DPEHPK3PXP", "correct-key");
  assert.equal(await decryptText(encrypted, "correct-key"), "JBSWY3DPEHPK3PXP");
  await assert.rejects(() => decryptText(encrypted, "wrong-key"));
});

test("session expires and rejects tampering", async () => {
  const session = await createSession("session-key", "csrf", 1_000);
  assert.equal((await verifySession(session, "session-key", 2_000)).csrf, "csrf");
  assert.equal(await verifySession(`${session}x`, "session-key", 2_000), null);
  assert.equal(await verifySession(session, "session-key", 50_000_000), null);
});

test("Base32 normalization accepts spacing and rejects junk", () => {
  assert.equal(normalizeSecret("jbsw y3dp-ehpk3pxp"), "JBSWY3DPEHPK3PXP");
  assert.throws(() => normalizeSecret("not-a-secret!"));
});

test("constant-time comparison handles equal and unequal values", () => {
  assert.equal(constantTimeEqual("same-value", "same-value"), true);
  assert.equal(constantTimeEqual("same-value", "different"), false);
});
