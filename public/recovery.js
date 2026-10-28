/**
 * recovery.js — per-card ownership recovery via a passphrase
 *
 * Scenario solved: browser storage wiped, no backup, no sync — but the owner
 * still holds the card's share link (naddr + read key). While the card was
 * still owned, a recovery passphrase can be set (editor → 🛟 Recovery
 * passphrase): it publishes an encrypted copy of the card's signing key
 * (nsec) to the card's own relays. The share link plus the passphrase then
 * restore full ownership (edit, rotate key, delete) on any device.
 *
 * Event: kind RECOVERY_KIND (addressable), same d-tag as the card event,
 * signed by the card's nsec. Content is JSON:
 *   { v: 1, kdf: { name, iterations }, salt: base64url(16 random bytes),
 *     blob: base64(IV[12] + AES-256-GCM(passphrase-derived key, nsec hex)) }
 * The KDF descriptor is stored inside the blob, so parameters can be
 * strengthened for new blobs later without invalidating existing ones
 * (relays may archive old ciphertext forever — there is no re-encrypt path).
 * The salt is public and per-card, so two cards sharing a passphrase never
 * share derived key material. Relays see only ciphertext — plus the (already
 * public) association between the recovery event and the card address.
 *
 * Security:
 *   - Same threat model as sync.js: brute-force resistance is the passphrase
 *     entropy (8 BIP39 words ≈ 88 bits) plus 600k PBKDF2 iterations per
 *     attempt. Only generated passphrases are accepted (8 words, isValidRecoveryPassphrase).
 *   - The passphrase is never persisted; shown once at generation.
 *   - Anyone holding BOTH the share link and the passphrase can re-own the
 *     card. The passphrase must never be shared with card recipients.
 */

import { deriveRecoveryKey, RECOVERY_KDF_PARAMS, encryptVCard, decryptVCard } from './crypto.js';
import {
  publishRecoveryEvent, fetchRecoveryEvents, deleteRecoveryEvent,
  derivePublicKey,
} from './nostr.js';
import { generateSyncPassphrase, isValidSyncPassphrase } from './sync.js';
import { bytesToHex, hexToBytes, bytesToBase64url, base64urlToBytes } from './utils.js';

// Reuse the sync passphrase generator and validator: same 8-word BIP39 form,
// same minimum-entropy guarantee, one familiar shape for the user.
export { generateSyncPassphrase as generateRecoveryPassphrase };

/** Recovery ciphertext is public and permanent on relays, so require the full
 *  generated length (8 words) rather than the sync minimum. */
export function isValidRecoveryPassphrase(passphrase) {
  return passphrase.split('-').length >= RECOVERY_MIN_WORDS && isValidSyncPassphrase(passphrase);
}

const RECOVERY_MIN_WORDS = 8;

/** Byte length of the per-card random salt stored alongside the ciphertext. */
const RECOVERY_SALT_BYTES = 16;

/** Current recovery payload format version — bumped only on format changes. */
const RECOVERY_FORMAT_VERSION = 1;

/**
 * Set (or replace) the recovery protection for a card: encrypt the signing
 * key under a passphrase-derived key and publish it to the card's relays.
 * Replaces any previous recovery event for the card (NIP-33 semantics).
 *
 * @param {string[]}   relays      WebSocket relay URLs
 * @param {Uint8Array} nsec       Card owner's private key (raw 32 bytes)
 * @param {string}     cardId      Card identifier (d-tag)
 * @param {string}     passphrase  Recovery passphrase (validated by the caller)
 * @returns {Promise<Array<{relay: string, ok: boolean}>>} per-relay results
 */
export async function setRecoveryData(relays, nsec, cardId, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(RECOVERY_SALT_BYTES));
  const key  = await deriveRecoveryKey(passphrase, salt);
  const blob = await encryptVCard(bytesToHex(nsec), key);
  const content = JSON.stringify({
    v:    RECOVERY_FORMAT_VERSION,
    kdf:  RECOVERY_KDF_PARAMS,
    salt: bytesToBase64url(salt),
    blob,
  });
  return publishRecoveryEvent(relays, nsec, cardId, content);
}

/**
 * Recover full ownership of a card from a share link + recovery passphrase:
 * locate the recovery event via the naddr (pubkey + d-tag), decrypt the
 * stored signing key with the passphrase, and hand back the raw private key.
 *
 * @param {string[]} relays      WebSocket relay URLs (naddr hints + defaults)
 * @param {string}   npub        Owner's public key (hex) — from the naddr
 * @param {string}   cardId      Card identifier (d-tag) — from the naddr
 * @param {string}   passphrase  Recovery passphrase
 * @returns {Promise<Uint8Array>} raw 32-byte private key
 * @throws {Error} code 'no-recovery' | 'bad-format' | 'bad-passphrase' | 'key-mismatch'
 */
export async function recoverCardSecret(relays, npub, cardId, passphrase) {
  const events = await fetchRecoveryEvents(relays, npub, cardId);
  if (!events.length) throw recoveryError('no-recovery', 'No recovery event found for this card');

  // Relays may serve different generations (partial replace, ignored
  // deletion, a future format version an older client can't parse). Newest
  // first; every generation encrypts the same nsec, so the first one that
  // opens is a valid recovery. If none opens, surface the most actionable
  // error: a decryptable-but-wrong-passphrase beats a malformed generation.
  let passphraseErr = null;
  let newestErr     = null;
  for (const event of events) {
    try {
      return await decryptRecoveryEvent(event, npub, passphrase);
    } catch (err) {
      if (err.code === 'bad-passphrase' || err.code === 'key-mismatch') {
        if (!passphraseErr) passphraseErr = err;
      }
      if (!newestErr) newestErr = err;
    }
  }
  throw passphraseErr || newestErr;
}

function recoveryError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

async function decryptRecoveryEvent(event, npub, passphrase) {
  let payload;
  try {
    payload = JSON.parse(event.content);
  } catch {
    payload = null;
  }
  if (!payload
      || payload.v !== RECOVERY_FORMAT_VERSION
      || typeof payload.salt !== 'string'
      || typeof payload.blob !== 'string'
      // KDF descriptor: read from the blob, not from current code constants —
      // only the algorithm is fixed here; iterations come from the payload.
      // The bounds only guard against pathological values.
      || !payload.kdf
      || payload.kdf.name !== RECOVERY_KDF_PARAMS.name
      || !Number.isInteger(payload.kdf.iterations)
      || payload.kdf.iterations < 100_000
      || payload.kdf.iterations > 10_000_000) {
    throw recoveryError('bad-format', 'Malformed recovery payload');
  }

  let nsecHex;
  try {
    const key = await deriveRecoveryKey(
      passphrase,
      base64urlToBytes(payload.salt),
      { iterations: payload.kdf.iterations }
    );
    nsecHex = (await decryptVCard(payload.blob, key)).trim();
  } catch {
    throw recoveryError('bad-passphrase', 'Wrong passphrase');
  }

  if (!/^[0-9a-f]{64}$/i.test(nsecHex)) {
    throw recoveryError('bad-format', 'Malformed recovery payload');
  }

  const nsecBytes = hexToBytes(nsecHex);
  // The fetch layer only returns events authored by npub; this additionally
  // proves the decrypted key really is that author's key.
  if (derivePublicKey(nsecBytes) !== npub) {
    throw recoveryError('key-mismatch', 'Recovered key does not match the card address');
  }

  return nsecBytes;
}

/**
 * Remove the recovery protection from a card (the card itself stays live).
 * Best-effort: publishes a NIP-09 deletion request for the recovery event.
 *
 * @param {string[]}   relays  WebSocket relay URLs
 * @param {Uint8Array} nsec    Card owner's private key (raw 32 bytes)
 * @param {string}     cardId  Card identifier (d-tag)
 * @returns {Promise<void>}
 */
export async function removeRecoveryData(relays, nsec, cardId) {
  await deleteRecoveryEvent(relays, nsec, cardId);
}
