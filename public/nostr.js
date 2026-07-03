/**
 * nostr.js — Nostr protocol layer for nostr-vcard
 *
 * Handles keypair generation, event publishing, fetching, and naddr encoding.
 * All relay I/O is done via nostr-tools SimplePool (CDN import from esm.sh).
 *
 * Card events use NIP-33 (addressable replaceable events, kind 30402).
 * Deletion uses NIP-09 (kind 5).
 * Addresses are encoded as NIP-19 naddr bech32 strings.
 *
 * Security:
 *   - nsec (private key) is never logged here. Callers must not log card objects.
 *   - naddrDecode wraps nip19.decode in a try/catch; callers should also wrap.
 *   - Relay URLs are validated as wss:// (or ws:// in dev) before use.
 */

import { generateSecretKey, getPublicKey, finalizeEvent }
  from 'https://esm.sh/nostr-tools@2.23.9/pure';
import { SimplePool }
  from 'https://esm.sh/nostr-tools@2.23.9/pool';
import * as nip19
  from 'https://esm.sh/nostr-tools@2.23.9/nip19';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://relay.nostr.band',
  'wss://nos.lol',
];

/** NIP-33 addressable replaceable event kind for vCard blobs */
const CARD_KIND = 30402;

/** Timeout for relay fetch operations (ms) */
const FETCH_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// Keypair generation
// ---------------------------------------------------------------------------

/**
 * Generate a fresh Nostr keypair for a new card.
 * @returns {{ nsec: Uint8Array, npub: string }} nsec is the raw 32-byte private key;
 *   npub is the hex-encoded public key.
 */
export function generateKeypair() {
  const nsec = generateSecretKey();           // Uint8Array(32)
  const npub = getPublicKey(nsec);            // hex string
  return { nsec, npub };
}

// ---------------------------------------------------------------------------
// Publish card event (NIP-33, kind 30402)
// ---------------------------------------------------------------------------

/**
 * Publish (or replace) a card event to all given relays.
 * NIP-33 semantics: relays keep only the latest event per (pubkey, kind, d-tag),
 * so re-publishing with the same d-tag automatically replaces the old event.
 *
 * @param {string[]}   relays         WebSocket relay URLs
 * @param {Uint8Array} nsec           Owner's private key (raw 32 bytes)
 * @param {string}     cardId         8-char card identifier (d-tag)
 * @param {string}     encryptedBlob  base64(IV[12] + AES-256-GCM ciphertext)
 * @param {string}     label          Human-readable card label (plaintext is fine)
 * @returns {Promise<Array<{relay: string, ok: boolean}>>}
 */
export async function publishCard(relays, nsec, cardId, encryptedBlob, label) {
  const template = {
    kind:       CARD_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags:       [['d', cardId], ['title', label]],
    content:    encryptedBlob,
  };

  const event = finalizeEvent(template, nsec);
  const pool  = new SimplePool();

  try {
    const publishPromises = relays.map(async relay => {
      try {
        await pool.publish([relay], event);
        return { relay, ok: true };
      } catch {
        return { relay, ok: false };
      }
    });

    // Use allSettled so a single relay failure doesn't abort the rest
    const settled = await Promise.allSettled(publishPromises);
    return settled.map(r =>
      r.status === 'fulfilled' ? r.value : { relay: '?', ok: false }
    );
  } finally {
    pool.close(relays);
  }
}

// ---------------------------------------------------------------------------
// Fetch card event (NIP-33, kind 30402)
// ---------------------------------------------------------------------------

/**
 * Fetch the latest card event for a given owner + card ID from the given relays.
 *
 * @param {string[]} relays   WebSocket relay URLs
 * @param {string}   npub     Owner's public key (hex)
 * @param {string}   cardId   Card identifier (d-tag)
 * @returns {Promise<{content: string, created_at: number}|null>}
 *   Returns the event content (encrypted blob) and timestamp, or null if not found.
 */
export async function fetchCard(relays, npub, cardId) {
  const pool = new SimplePool();

  try {
    const event = await Promise.race([
      pool.get(relays, {
        kinds:   [CARD_KIND],
        authors: [npub],
        '#d':    [cardId],
      }),
      new Promise(resolve => setTimeout(() => resolve(null), FETCH_TIMEOUT_MS)),
    ]);

    if (!event) return null;
    return { content: event.content, created_at: event.created_at, tags: event.tags || [] };
  } finally {
    pool.close(relays);
  }
}

// ---------------------------------------------------------------------------
// Delete card event (NIP-09, kind 5)
// ---------------------------------------------------------------------------

/**
 * Publish a NIP-09 deletion event for a card.
 * Deletion is best-effort — well-behaved relays will stop serving the event,
 * but not all relays honour deletion requests.
 *
 * @param {string[]}   relays  WebSocket relay URLs
 * @param {Uint8Array} nsec    Owner's private key (raw 32 bytes)
 * @param {string}     cardId  Card identifier
 * @returns {Promise<void>}
 */
export async function deleteCard(relays, nsec, cardId) {
  const npub = getPublicKey(nsec);
  const template = {
    kind:       5,
    created_at: Math.floor(Date.now() / 1000),
    tags:       [['a', `${CARD_KIND}:${npub}:${cardId}`]],
    content:    'deleted',
  };

  const event = finalizeEvent(template, nsec);
  const pool  = new SimplePool();

  try {
    await Promise.allSettled(relays.map(relay => pool.publish([relay], event)));
  } finally {
    pool.close(relays);
  }
}

// ---------------------------------------------------------------------------
// NIP-19 naddr encode / decode
// ---------------------------------------------------------------------------

/**
 * Encode a card address as an naddr bech32 string for use in share URLs.
 *
 * @param {string}   npub    Owner's public key (hex)
 * @param {string}   cardId  Card identifier (d-tag)
 * @param {string[]} relays  Relay hints for recipients
 * @returns {string}  e.g. "naddr1qq9kummnw3..."
 */
export function naddrEncode(npub, cardId, relays) {
  return nip19.naddrEncode({
    kind:       CARD_KIND,
    pubkey:     npub,
    identifier: cardId,
    relays,
  });
}

/**
 * Decode an naddr bech32 string.
 * Throws if the string is malformed or not an naddr — callers must wrap in try/catch.
 *
 * @param {string} naddr
 * @returns {{ kind: number, pubkey: string, identifier: string, relays: string[] }}
 */
export function naddrDecode(naddr) {
  const decoded = nip19.decode(naddr);
  if (decoded.type !== 'naddr') {
    throw new Error(`Expected naddr, got ${decoded.type}`);
  }
  const { kind, pubkey, identifier, relays } = decoded.data;
  return { kind, pubkey, identifier, relays: relays || [] };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Validate a relay URL. Accepts wss:// always; ws:// only on localhost/dev.
 * @param {string} url
 * @returns {boolean}
 */
export function isValidRelayUrl(url) {
  try {
    const u = new URL(url);
    if (u.protocol === 'wss:') return true;
    // Allow ws:// only in local development
    if (u.protocol === 'ws:' &&
        (location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}
