const encoder = new TextEncoder();

export function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function fromBase64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return base64url(new Uint8Array(digest));
}

export function constantTimeEqual(left, right) {
  const a = encoder.encode(String(left));
  const b = encoder.encode(String(right));
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) difference |= (a[i] || 0) ^ (b[i] || 0);
  return difference === 0;
}

async function aesKey(secret) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(secret));
  return crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptText(value, secret) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await aesKey(secret), encoder.encode(value));
  const packed = new Uint8Array(iv.length + ciphertext.byteLength);
  packed.set(iv);
  packed.set(new Uint8Array(ciphertext), iv.length);
  return base64url(packed);
}

export async function decryptText(value, secret) {
  const packed = fromBase64url(value);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: packed.slice(0, 12) },
    await aesKey(secret),
    packed.slice(12),
  );
  return new TextDecoder().decode(plaintext);
}

function base32Bytes(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = value.toUpperCase().replace(/[\s=-]/g, "");
  if (!clean || [...clean].some((char) => !alphabet.includes(char))) throw new Error("2FA 密钥不是有效的 Base32");
  let bits = "";
  for (const char of clean) bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
  const output = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) output.push(Number.parseInt(bits.slice(i, i + 8), 2));
  if (!output.length) throw new Error("2FA 密钥太短");
  return new Uint8Array(output);
}

export function normalizeSecret(value) {
  const secret = value.toUpperCase().replace(/[\s=-]/g, "");
  base32Bytes(secret);
  return secret;
}

export async function totp(secret, timestamp = Date.now()) {
  const counter = Math.floor(timestamp / 1000 / 30);
  const message = new Uint8Array(8);
  let number = counter;
  for (let i = 7; i >= 0; i -= 1) {
    message[i] = number & 255;
    number = Math.floor(number / 256);
  }
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = digest[digest.length - 1] & 15;
  const binary = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(binary % 1_000_000).padStart(6, "0");
}

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return base64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value))));
}

export async function createSession(secret, csrf, now = Date.now()) {
  const payload = base64url(encoder.encode(JSON.stringify({ user: "admin", csrf, exp: now + 12 * 60 * 60 * 1000 })));
  return `${payload}.${await hmac(payload, secret)}`;
}

export async function verifySession(cookie, secret, now = Date.now()) {
  if (!cookie) return null;
  const [payload, signature, extra] = cookie.split(".");
  if (!payload || !signature || extra || !constantTimeEqual(signature, await hmac(payload, secret))) return null;
  try {
    const data = JSON.parse(new TextDecoder().decode(fromBase64url(payload)));
    return data.user === "admin" && data.exp > now ? data : null;
  } catch {
    return null;
  }
}
