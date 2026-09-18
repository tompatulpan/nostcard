/**
 * pairing.js — in-person "Connections" pairing via a shared code (QR/link)
 *
 * A short-lived random code, exchanged only via an in-person QR scan or link,
 * deterministically derives a Nostr identity (locates the pairing channel) and
 * an AES-256-GCM key (encrypts its content) — same trick as sync.js, but the
 * secret is single-use and time-boxed instead of a memorised passphrase.
 * Both devices holding the code compute the identical identity and can each
 * publish to their own "slot" without colliding.
 *
 * Security:
 *   - The code is equivalent to a decryption key — never log it, never send
 *     it anywhere but the URL fragment (or QR contents scanned in person).
 *   - Offers older than PAIR_TTL_MS are treated as expired and ignored.
 */

import { generateRandom, derivePairingSecrets, importSyncKey, encryptVCard, decryptVCard } from './crypto.js';
import { derivePublicKey, publishPairingSlot, fetchPairingSlot, deletePairingSlots } from './nostr.js';

/** How long a pairing code remains valid before offers are ignored */
export const PAIR_TTL_MS = 30 * 60 * 1000;

/**
 * Generate a fresh, URL-safe pairing code.
 * @returns {string}
 */
export function generatePairingCode() {
  return generateRandom(16);
}

/**
 * Derive the pairing identity (signing key + public key + AES key material) from a code.
 * Deterministic — the same code always yields the same identity.
 * @param {string} code
 * @returns {Promise<{ pairNsec: Uint8Array, pairNpub: string, pairKeyRaw: Uint8Array }>}
 */
export async function derivePairingIdentity(code) {
  const { pairNsec, pairKeyRaw } = await derivePairingSecrets(code);
  const pairNpub = derivePublicKey(pairNsec);
  return { pairNsec, pairNpub, pairKeyRaw };
}

/**
 * Encrypt and publish a payload to one pairing slot.
 * @param {string[]}   relays
 * @param {Uint8Array} pairNsec
 * @param {Uint8Array} pairKeyRaw
 * @param {'a'|'b'}    slot
 * @param {object}     payload   JSON-serializable — e.g. { naddr, key, label }
 * @returns {Promise<Array<{relay: string, ok: boolean}>>}
 */
export async function publishPairingPayload(relays, pairNsec, pairKeyRaw, slot, payload) {
  const pairKey = await importSyncKey(pairKeyRaw);
  const blob    = await encryptVCard(JSON.stringify(payload), pairKey);
  return publishPairingSlot(relays, pairNsec, slot, blob);
}

/**
 * Fetch and decrypt one pairing slot's payload, if present and not expired.
 * @param {string[]}   relays
 * @param {string}     pairNpub
 * @param {Uint8Array} pairKeyRaw
 * @param {'a'|'b'}    slot
 * @param {number}     [maxAgeMs]  defaults to PAIR_TTL_MS
 * @returns {Promise<{ payload: object, createdAt: number } | null>}
 */
export async function fetchPairingPayload(relays, pairNpub, pairKeyRaw, slot, maxAgeMs = PAIR_TTL_MS) {
  const event = await fetchPairingSlot(relays, pairNpub, slot);
  if (!event) return null;
  if (Date.now() - event.created_at * 1000 > maxAgeMs) return null;

  const pairKey = await importSyncKey(pairKeyRaw);
  const json    = await decryptVCard(event.content, pairKey);
  return { payload: JSON.parse(json), createdAt: event.created_at };
}

/**
 * Best-effort cleanup of both pairing slots once a handshake is complete (or cancelled).
 * @param {string[]}   relays
 * @param {Uint8Array} pairNsec
 * @returns {Promise<void>}
 */
export async function cleanupPairing(relays, pairNsec) {
  await deletePairingSlots(relays, pairNsec);
}
