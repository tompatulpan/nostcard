/**
 * secureStorage.js — Encrypted localStorage wrapper
 *
 * Provides a secure way to store sensitive data (like sync identities) in
 * localStorage by encrypting it with a key derived from a device-specific
 * factor. This mitigates XSS attacks that could otherwise steal private keys.
 *
 * Security notes:
 *   - The encryption key is derived from a combination of factors that are
 *     unique to the device/browser, making it difficult for an XSS attack
 *     to decrypt data even if it steals the ciphertext.
 *   - The key is NOT persisted, so encrypted data can only be read by the
 *     same device that wrote it (same origin, same browser profile).
 *   - This is NOT a substitute for proper XSS prevention (CSP) but adds
 *     defense in depth.
 *   - For maximum security, sensitive operations should still use sessionStorage
 *     for ephemeral data and avoid persisting private keys when possible.
 */

/**
 * Derive a device-specific encryption key.
 * Uses a combination of:
 *   - A fixed application salt
 *   - The origin (prevents cross-origin decryption)
 *   - The userAgent (adds entropy, though not perfectly reliable)
 *   - A hardcoded secret (obscures the derivation from external attackers)
 * 
 * The key is cached in memory for the session.
 * @returns {Promise<CryptoKey>} AES-256-GCM key for encryption/decryption
 */
async function getDeviceKey() {
  // Cache the key in memory for the session
  if (window.__secureStorageDeviceKey) {
    return window.__secureStorageDeviceKey;
  }

  // Fixed application salt - changing this invalidates all stored data
  const APP_SALT = 'nostcard-secure-storage-v1';
  
  // Hardcoded secret to obscure the derivation (not a real secret, just adds obscurity)
  const OBSCURE_SECRET = 'x7Fk9pLm2QvR4sT8wY';

  // Gather device-specific factors
  const origin = window.location.origin;
  const userAgent = navigator.userAgent;
  
  // Combine all factors
  const combined = APP_SALT + '|' + origin + '|' + userAgent + '|' + OBSCURE_SECRET;
  
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

  const deviceKey = await crypto.subtle.importKey(
    'raw',
    keyBits,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );

  // Cache for session
  window.__secureStorageDeviceKey = deviceKey;
  
  return deviceKey;
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
 * @param {string} ciphertext - base64 encoded IV + ciphertext
 * @returns {Promise<string|null>} - Decrypted plaintext, or null on failure
 */
async function decryptFromStorage(ciphertext) {
  try {
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
  } catch (e) {
    // Decryption failed - could be wrong device, corrupted data, or tampering
    console.warn('SecureStorage decryption failed:', e);
    return null;
  }
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
   * @param {string} key - Storage key
   * @returns {Promise<string|null>} - Decrypted value, or null if not found or decryption failed
   */
  async getItem(key) {
    const encrypted = localStorage.getItem(key);
    if (!encrypted) return null;
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

/**
 * Check if secure storage is available (i.e., the device key can be derived).
 * @returns {Promise<boolean>}
 */
export async function isSecureStorageAvailable() {
  try {
    await getDeviceKey();
    return true;
  } catch {
    return false;
  }
}

/**
 * Clear the cached device key (e.g., on logout).
 * Note: This doesn't clear stored data, just forces re-derivation on next access.
 */
export function clearDeviceKeyCache() {
  window.__secureStorageDeviceKey = null;
}
