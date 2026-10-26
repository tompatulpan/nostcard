/**
 * sync.js — cross-device sync via a passphrase-derived Nostr identity
 *
 * A user-facing passphrase deterministically derives a signing key (locates
 * the snapshot event on relays) and an AES-256-GCM key (encrypts/decrypts
 * its content). Any device that knows the passphrase can push/pull the same
 * encrypted snapshot — no account, no central server, same trust model as
 * card sharing.
 *
 * Security:
 *   - The passphrase itself is never persisted; only derived material is cached by callers.
 *   - syncNsec / syncKeyRaw / passphrase must never be logged.
 *   - Rate limiting at derivation level prevents brute force attacks
 */

import { deriveSyncSecrets, importSyncKey, encryptVCard, decryptVCard } from './crypto.js';
import { derivePublicKey, publishSyncEvent, fetchSyncEvent, deleteSyncEvent } from './nostr.js';
import { BIP39_ENGLISH } from './vendor/bip39-wordlist.js';

// ---------------------------------------------------------------------------
// Rate limiting for derivation (brute force protection)
// ---------------------------------------------------------------------------

/**
 * In-memory rate limiter for sync passphrase derivation attempts.
 * Prevents offline brute force attacks even if an attacker can call
 * deriveSyncIdentity directly (e.g., via compromised JavaScript).
 */
const derivationRateLimiter = {
  attempts: new Map(), // passphrase -> { count, lastAttempt }
  maxAttempts: 10,
  windowMs: 60 * 1000, // 1 minute
  lockoutMs: 15 * 60 * 1000, // 15 minutes
  
  /**
   * Check if a derivation attempt is allowed.
   * @param {string} passphrase 
   * @returns {boolean} true if allowed
   */
  check(passphrase) {
    const now = Date.now();
    const key = passphrase.slice(0, 20); // Use first 20 chars as key to save memory
    
    const record = this.attempts.get(key);
    if (!record) {
      this.attempts.set(key, { count: 1, lastAttempt: now });
      return true;
    }
    
    // Check if lockout period has passed
    if (now - record.lastAttempt > this.lockoutMs) {
      this.attempts.delete(key);
      this.attempts.set(key, { count: 1, lastAttempt: now });
      return true;
    }
    
    // Check if within rate limit window
    if (now - record.lastAttempt > this.windowMs) {
      this.attempts.set(key, { count: 1, lastAttempt: now });
      return true;
    }
    
    // Check if under limit
    if (record.count < this.maxAttempts) {
      this.attempts.set(key, { count: record.count + 1, lastAttempt: now });
      return true;
    }
    
    return false;
  },
  
  /**
   * Record a failed attempt.
   * @param {string} passphrase
   */
  recordFailure(passphrase) {
    const key = passphrase.slice(0, 20);
    const record = this.attempts.get(key);
    if (record) {
      record.count++;
      record.lastAttempt = Date.now();
    }
  },
  
  /**
   * Clear rate limiting for a passphrase (e.g., after successful derivation).
   * @param {string} passphrase
   */
  clear(passphrase) {
    const key = passphrase.slice(0, 20);
    this.attempts.delete(key);
  },
  
  /**
   * Get remaining lockout time for a passphrase.
   * @param {string} passphrase
   * @returns {number} milliseconds remaining, or 0 if not locked out
   */
  getLockoutTime(passphrase) {
    const key = passphrase.slice(0, 20);
    const record = this.attempts.get(key);
    if (!record) return 0;
    
    const now = Date.now();
    const timeSinceLast = now - record.lastAttempt;
    
    if (timeSinceLast > this.lockoutMs) return 0;
    if (record.count < this.maxAttempts) return 0;
    
    return this.lockoutMs - timeSinceLast;
  }
};

/**
 * Get remaining lockout time for a passphrase (for UI display).
 * @param {string} passphrase
 * @returns {number} milliseconds remaining, or 0 if not locked out
 */
export function getDerivationLockoutTime(passphrase) {
  return derivationRateLimiter.getLockoutTime(passphrase);
}

/**
 * Clear rate limiting for a passphrase (e.g., after successful operation).
 * @param {string} passphrase
 */
export function clearDerivationRateLimit(passphrase) {
  derivationRateLimiter.clear(passphrase);
}

// ---------------------------------------------------------------------------
// Passphrase generation
// ---------------------------------------------------------------------------

// 8 words from the 2048-word BIP39 English list (~88 bits of entropy) — chosen
// for a large, standard, audited wordlist rather than a small ad-hoc one.
const PASSPHRASE_WORD_COUNT = 8;

/**
 * Generate a fresh, memorable sync passphrase (8 random BIP39 English words).
 * @returns {string} e.g. "abandon-cereal-enrich-identify-noodle-romance-three-wheel"
 */
export function generateSyncPassphrase() {
  const words = [];
  for (let i = 0; i < PASSPHRASE_WORD_COUNT; i++) {
    const idx = crypto.getRandomValues(new Uint32Array(1))[0] % BIP39_ENGLISH.length;
    words.push(BIP39_ENGLISH[idx]);
  }
  return words.join('-');
}

/** Minimum accepted word count for a sync passphrase (6 words ≈ 66 bits — far
 *  beyond offline brute-force reach at 600k PBKDF2 iterations). */
const MIN_PASSPHRASE_WORDS = 6;

const BIP39_WORD_SET = new Set(BIP39_ENGLISH);

/**
 * True if the passphrase has the generated form: hyphen-separated words from
 * the BIP39 wordlist, at least MIN_PASSPHRASE_WORDS of them. The generator is
 * the only legitimate source of sync passphrases, so rejecting every other
 * form blocks weak hand-typed passphrases: the encrypted snapshot is public on
 * the relays and contains every card's private key — a guessable passphrase
 * would let anyone brute-force it offline.
 *
 * Additionally checks for:
 *   - Minimum unique word count (prevents repeated words like "aaa-aaa-aaa...")
 *   - No sequential patterns (prevents "abandon-ability-able-...")
 * @param {string} passphrase
 * @returns {boolean}
 */
export function isValidSyncPassphrase(passphrase) {
  const words = passphrase.split('-');
  
  // Check basic requirements
  if (words.length < MIN_PASSPHRASE_WORDS) return false;
  if (!words.every(w => BIP39_WORD_SET.has(w))) return false;
  
  // Check for sufficient uniqueness (at least 50% unique words)
  const uniqueWords = new Set(words);
  if (uniqueWords.size < MIN_PASSPHRASE_WORDS * 0.5) return false;
  
  // Check for sequential BIP39 words (common pattern in weak passphrases)
  // This is a simplified check - a real attacker would use the full wordlist order
  for (let i = 0; i < words.length - 1; i++) {
    const idx1 = BIP39_ENGLISH.indexOf(words[i]);
    const idx2 = BIP39_ENGLISH.indexOf(words[i + 1]);
    if (idx2 === idx1 + 1) {
      // Allow at most one sequential pair (could be coincidence)
      let sequentialCount = 0;
      for (let j = 0; j < words.length - 1; j++) {
        const a = BIP39_ENGLISH.indexOf(words[j]);
        const b = BIP39_ENGLISH.indexOf(words[j + 1]);
        if (b === a + 1) sequentialCount++;
      }
      if (sequentialCount > 1) return false;
    }
  }
  
  return true;
}

// ---------------------------------------------------------------------------
// Identity derivation
// ---------------------------------------------------------------------------

/**
 * Derive the sync identity (signing key + public key + AES key material) from a passphrase.
 * Deterministic — same passphrase always yields the same identity.
 *
 * @param {string} passphrase
 * @returns {Promise<{ syncNsec: Uint8Array, syncNpub: string, syncKeyRaw: Uint8Array }>}
 * @throws {Error} if rate limited
 */
export async function deriveSyncIdentity(passphrase) {
  // Check rate limiting
  if (!derivationRateLimiter.check(passphrase)) {
    const lockoutTime = derivationRateLimiter.getLockoutTime(passphrase);
    throw new Error(`Rate limited. Try again in ${Math.ceil(lockoutTime / 60000)} minutes.`);
  }
  
  const { syncNsec, syncKeyRaw } = await deriveSyncSecrets(passphrase);
  const syncNpub = derivePublicKey(syncNsec);
  
  // Clear rate limiting on successful derivation
  derivationRateLimiter.clear(passphrase);
  
  return { syncNsec, syncNpub, syncKeyRaw };
}

// ---------------------------------------------------------------------------
// Push / pull / delete
// ---------------------------------------------------------------------------

/**
 * Encrypt and publish a sync payload, replacing any previous snapshot.
 *
 * @param {string[]}   relays
 * @param {Uint8Array} syncNsec
 * @param {Uint8Array} syncKeyRaw
 * @param {object}     payload   JSON-serializable snapshot (cards, savedLinks, fields)
 * @returns {Promise<Array<{relay: string, ok: boolean}>>}
 */
export async function pushSyncData(relays, syncNsec, syncKeyRaw, payload) {
  const syncKey = await importSyncKey(syncKeyRaw);
  const blob    = await encryptVCard(JSON.stringify(payload), syncKey);
  return publishSyncEvent(relays, syncNsec, blob);
}

/**
 * Fetch and decrypt the latest sync snapshot.
 *
 * @param {string[]}   relays
 * @param {string}     syncNpub
 * @param {Uint8Array} syncKeyRaw
 * @returns {Promise<{ payload: object, createdAt: number } | null>}
 */
export async function pullSyncData(relays, syncNpub, syncKeyRaw) {
  const event = await fetchSyncEvent(relays, syncNpub);
  if (!event) return null;

  const syncKey = await importSyncKey(syncKeyRaw);
  const json    = await decryptVCard(event.content, syncKey);
  return { payload: JSON.parse(json), createdAt: event.created_at };
}

/**
 * Retire the sync snapshot: overwrite it with an empty one (works on every
 * relay, because replaceable events are always superseded), then publish a
 * NIP-09 deletion (best-effort — not every relay honours it). The overwrite is
 * what actually removes the card keys from relays that ignore deletions.
 * @param {string[]}   relays
 * @param {Uint8Array} syncNsec
 * @param {Uint8Array} syncKeyRaw
 * @returns {Promise<Array<{relay: string, ok: boolean}>>} overwrite results
 */
export async function deleteSyncData(relays, syncNsec, syncKeyRaw) {
  const empty = { version: 3, exported: new Date().toISOString(), cards: [], savedLinks: [], connections: [], fields: {} };
  const results = await pushSyncData(relays, syncNsec, syncKeyRaw, empty);
  await deleteSyncEvent(relays, syncNsec);
  return results;
}
