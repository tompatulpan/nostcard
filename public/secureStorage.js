/**
 * secureStorage.js — Encrypted localStorage wrapper
 *
 * Stores sensitive data (like sync identities) in localStorage encrypted
 * under an origin-derived AES-256-GCM key.
 *
 * Honest threat model:
 *   - Protects against a PASSIVE leak of localStorage contents (e.g. a
 *     synced browser-profile backup or a dump scraped by local malware).
 *   - Does NOT protect against XSS on this origin — injected script can
 *     simply re-run the same derivation. The HTTP CSP (public/_headers,
 *     script-src 'self') is the primary XSS defence.
 *
 * Design notes:
 *   - The key is derived from stable factors only (app salt + origin).
 *     Deliberately not from navigator.userAgent — it changes with every
 *     browser update and would silently invalidate all encrypted values.
 *   - The key is cached in module scope (not a window global) and imported
 *     non-extractable; it never leaves this module.
 *   - On non-secure origins (plain http on a LAN IP) crypto.subtle is
 *     unavailable — callers (utils.js secureReadJson/secureWriteJson) fall
 *     back to plain localStorage for that case.
 */

/**
 * Derive an origin-specific encryption key.
 *
 * Honest scope: this protects against a *passive* leak of localStorage data
 * (e.g. a synced browser-profile dump). It does NOT protect against XSS on
 * this origin — an injected script can simply re-run this derivation, which
 * is why the HTTP CSP (public/_headers) is the primary XSS defence.
 *
 * Deliberately NOT part of the derivation input:
 *   - navigator.userAgent — it changes on every browser update, which would
 *     silently invalidate all encrypted values; origin + app salt are stable.
 *
 * The derived key is cached in module scope (not on a window global) for the
 * session, and imported non-extractable — it is only ever used inside this
 * module for encrypt/decrypt.
 * @returns {Promise<CryptoKey>} AES-256-GCM key for encryption/decryption
 */
let cachedDeviceKey = null;

async function getDeviceKey() {
  if (cachedDeviceKey) {
    return cachedDeviceKey;
  }

  // Fixed application salt - changing this invalidates all stored data
  const APP_SALT = 'nostcard-secure-storage-v1';

  const origin = window.location.origin;

  // Combine stable factors
  const combined = APP_SALT + '|' + origin;

  // Derive a 256-bit key using PBKDF2
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(combined),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const keyBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: new TextEncoder().encode(APP_SALT + ':device-key'),
      iterations: 100_000,
      hash: 'SHA-256'
    },
    baseKey,
    256
  );

  cachedDeviceKey = await crypto.subtle.importKey(
    'raw',
    keyBits,
    { name: 'AES-GCM', length: 256 },
    false, // non-extractable — only used inside this module
    ['encrypt', 'decrypt']
  );

  return cachedDeviceKey;
}

/**
 * Encrypt data for secure storage.
 * @param {string} plaintext - The data to encrypt
 * @returns {Promise<string>} - base64 encoded IV + ciphertext
 */
async function encryptForStorage(plaintext) {
  const key = await getDeviceKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );

  const combined = new Uint8Array(12 + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), 12);

  return btoa(String.fromCharCode(...combined));
}

/**
 * Decrypt data from secure storage.
 * Throws on decryption failure (wrong device, corrupted data, tampering, or
 * non-secure origin without crypto.subtle) so callers can fall back to a
 * plain read for legacy plaintext values. Returns null only when the
 * underlying localStorage entry is absent.
 * @param {string} ciphertext - base64 encoded IV + ciphertext
 * @returns {Promise<string|null>} - Decrypted plaintext, or null if not found
 */
async function decryptFromStorage(ciphertext) {
  const combined = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const encrypted = combined.slice(12);

  const key = await getDeviceKey();
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    encrypted
  );

  return new TextDecoder().decode(plaintext);
}

/**
 * Secure storage wrapper for localStorage.
 * Automatically encrypts before storing and decrypts after reading.
 */
export const secureStorage = {
  /**
   * Store a value securely.
   * @param {string} key - Storage key
   * @param {string} value - Value to store (will be stringified if object)
   */
  async setItem(key, value) {
    const plaintext = typeof value === 'string' ? value : JSON.stringify(value);
    const encrypted = await encryptForStorage(plaintext);
    localStorage.setItem(key, encrypted);
  },

  /**
   * Retrieve a value securely.
   * Returns null only when the key is absent; throws when a value exists but
   * cannot be decrypted (legacy plaintext, tampering, non-secure origin) —
   * callers fall back to a plain read and migrate.
   * @param {string} key - Storage key
   * @returns {Promise<string|null>} - Decrypted value, or null if not found
   */
  async getItem(key) {
    const encrypted = localStorage.getItem(key);
    if (encrypted === null) return null;
    return await decryptFromStorage(encrypted);
  },

  /**
   * Remove a value.
   * @param {string} key - Storage key
   */
  removeItem(key) {
    localStorage.removeItem(key);
  },

  /**
   * Clear all secure storage. Note: only clears keys managed by this module.
   */
  clear() {
    // We can't easily distinguish our keys, so this is a no-op
    // Callers should track their own keys
  }
};


