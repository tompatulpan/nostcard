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
 */

import { deriveSyncSecrets, importSyncKey, encryptVCard, decryptVCard } from './crypto.js';
import { derivePublicKey, publishSyncEvent, fetchSyncEvent, deleteSyncEvent } from './nostr.js';
import { BIP39_ENGLISH } from './vendor/bip39-wordlist.js';

// ---------------------------------------------------------------------------
// Passphrase generation
// ---------------------------------------------------------------------------

// 8 words from the 2048-word BIP39 English list (~88 bits of entropy) — chosen
// for a large, standard, audited wordlist rather than a small ad-hoc one.
const PASSPHRASE_WORD_COUNT = 8;

/**
 * Generate a fresh, memorable sync passphrase (8 random BIP39 English words).
 * @returns {string} e.g. "anchor-jungle-quartz-holly-drift-opal-cedar-forest"
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
 * @param {string} passphrase
 * @returns {boolean}
 */
export function isValidSyncPassphrase(passphrase) {
  const words = passphrase.split('-');
  return words.length >= MIN_PASSPHRASE_WORDS && words.every(w => BIP39_WORD_SET.has(w));
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
 */
export async function deriveSyncIdentity(passphrase) {
  const { syncNsec, syncKeyRaw } = await deriveSyncSecrets(passphrase);
  const syncNpub = derivePublicKey(syncNsec);
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
 * Delete the sync snapshot from relays (best-effort, NIP-09).
 * @param {string[]}   relays
 * @param {Uint8Array} syncNsec
 * @returns {Promise<void>}
 */
export async function deleteSyncData(relays, syncNsec) {
  await deleteSyncEvent(relays, syncNsec);
}
