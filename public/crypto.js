/**
 * crypto.js — AES-256-GCM helpers for E2E vCard sharing
 *
 * All operations use the Web Crypto API (available in all modern browsers).
 * The AES key is generated once per card and stored in localStorage.
 * It is shared with recipients exclusively via the URL fragment (#), which
 * browsers never transmit to servers.
 */

/**
 * Generate a new random AES-256-GCM key.
 * The key is extractable so it can be exported to the URL fragment.
 * @returns {Promise<CryptoKey>}
 */
export async function generateKey() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,   // extractable — needed to write key to URL fragment
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt a vCard UTF-8 string with AES-256-GCM.
 * A fresh random 12-byte IV is generated for every call; it is prepended
 * to the ciphertext so the recipient can recover it.
 *
 * @param {string}     vcardText  Plain-text vCard string
 * @param {CryptoKey}  key        AES-256-GCM key
 * @returns {Promise<string>}     base64(IV[12] + ciphertext)
 */
export async function encryptVCard(vcardText, key) {
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(vcardText);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );

  const combined = new Uint8Array(12 + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), 12);

  return bytesToBase64(combined);
}

/**
 * Decrypt a blob produced by encryptVCard.
 *
 * @param {string}    base64Blob  base64(IV[12] + ciphertext)
 * @param {CryptoKey} key         AES-256-GCM key
 * @returns {Promise<string>}     Plain-text vCard string
 */
export async function decryptVCard(base64Blob, key) {
  const combined  = base64ToBytes(base64Blob);
  const iv        = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );

  return new TextDecoder().decode(plaintext);
}

/**
 * Export a CryptoKey to a URL-safe base64 string for use in the URL fragment.
 * @param {CryptoKey} key
 * @returns {Promise<string>}
 */
export async function keyToFragment(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  return bytesToBase64url(new Uint8Array(raw));
}

/**
 * Import a URL-safe base64 string from the URL fragment back into a CryptoKey.
 * @param {string} fragment
 * @returns {Promise<CryptoKey>}
 */
export async function fragmentToKey(fragment) {
  const raw = base64urlToBytes(fragment);
  return crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'AES-GCM', length: 256 },
    false,  // non-extractable on recipient side (XSS hardening)
    ['decrypt']
  );
}

/**
 * Generate a cryptographically random URL-safe alphanumeric string.
 * Used for card ids (8 chars) and recipient tokens (16 chars).
 * Uses rejection sampling for uniform distribution.
 *
 * @param {number} length
 * @returns {string}
 */
export function generateRandom(length) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const limit    = Math.floor(256 / alphabet.length) * alphabet.length;
  let result = '';
  while (result.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array((length - result.length) * 2));
    for (const b of bytes) {
      if (result.length >= length) break;
      if (b < limit) result += alphabet[b % alphabet.length];
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Sync identity derivation (passphrase → signing key + encryption key)
// ---------------------------------------------------------------------------

/** PBKDF2 iterations — OWASP-recommended minimum for PBKDF2-HMAC-SHA256 (2023 guidance) */
const SYNC_PBKDF2_ITERATIONS = 600_000;

/** Fixed salt: identity is fully determined by the passphrase, same on every device.
 *  Protocol constant — do not rename: it is part of the KDF input, renaming breaks decryption of existing synced snapshots. */
const SYNC_SALT = 'nostr-vcard-sync-v1';

/**
 * Derive deterministic sync identity material from a passphrase. The same
 * passphrase always yields the same bytes, so any device that knows the
 * passphrase can reconstruct the identity used to locate and decrypt the
 * same sync snapshot. Returned as raw bytes (not CryptoKey) so callers can
 * cache them (e.g. in localStorage, alongside existing card credentials).
 *
 * @param {string} passphrase
 * @returns {Promise<{ syncNsec: Uint8Array, syncKeyRaw: Uint8Array }>}
 *   syncNsec is a raw 32-byte secp256k1 private key (for signing/locating the event);
 *   syncKeyRaw is a raw 32-byte AES-256-GCM key (for encrypting/decrypting the payload).
 */
export async function deriveSyncSecrets(passphrase) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // Domain-separate the two derived secrets by mixing a distinct label into the salt
  const [nsecBits, aesBits] = await Promise.all([
    crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: new TextEncoder().encode(SYNC_SALT + ':nsec'), iterations: SYNC_PBKDF2_ITERATIONS, hash: 'SHA-256' },
      baseKey,
      256
    ),
    crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: new TextEncoder().encode(SYNC_SALT + ':aes'), iterations: SYNC_PBKDF2_ITERATIONS, hash: 'SHA-256' },
      baseKey,
      256
    ),
  ]);

  return { syncNsec: new Uint8Array(nsecBits), syncKeyRaw: new Uint8Array(aesBits) };
}

/**
 * Import raw AES key bytes (from deriveSyncSecrets) as a usable CryptoKey.
 * Extractable, matching how card AES keys are handled elsewhere in this app.
 * @param {Uint8Array} rawKeyBytes
 * @returns {Promise<CryptoKey>}
 */
export async function importSyncKey(rawKeyBytes) {
  return crypto.subtle.importKey('raw', rawKeyBytes, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

// ---------------------------------------------------------------------------
// Pairing identity derivation (code → signing key + encryption key)
// ---------------------------------------------------------------------------

/** Fixed salt, distinct label from sync so the same code/passphrase never collides across features.
 *  Protocol constant — do not rename: it is part of the KDF input, renaming breaks existing pairing codes. */
const PAIR_SALT = 'nostr-vcard-pair-v1';

/**
 * Derive deterministic pairing-channel identity material from a pairing code.
 * Same shape as deriveSyncSecrets — both devices holding the code (scanned
 * from the same QR/link) independently compute the identical identity.
 *
 * @param {string} code
 * @returns {Promise<{ pairNsec: Uint8Array, pairKeyRaw: Uint8Array }>}
 */
export async function derivePairingSecrets(code) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(code),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const [nsecBits, aesBits] = await Promise.all([
    crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: new TextEncoder().encode(PAIR_SALT + ':nsec'), iterations: SYNC_PBKDF2_ITERATIONS, hash: 'SHA-256' },
      baseKey,
      256
    ),
    crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: new TextEncoder().encode(PAIR_SALT + ':aes'), iterations: SYNC_PBKDF2_ITERATIONS, hash: 'SHA-256' },
      baseKey,
      256
    ),
  ]);

  return { pairNsec: new Uint8Array(nsecBits), pairKeyRaw: new Uint8Array(aesBits) };
}

// ---------------------------------------------------------------------------
// Internal base64 helpers
// ---------------------------------------------------------------------------

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

/** Standard base64 → URL-safe base64 (no padding) */
function bytesToBase64url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/** URL-safe base64 → bytes */
function base64urlToBytes(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
