/**
 * nostr.js — Nostr protocol layer for NostCard
 *
 * Handles keypair generation, event publishing, fetching, and naddr encoding.
 * All relay I/O is done via nostr-tools SimplePool (self-hosted bundle in vendor/).
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

// Self-hosted bundle (nostr-tools 2.23.9) — rebuild with `npm run build:vendor`
import { generateSecretKey, getPublicKey, finalizeEvent, SimplePool, nip19 }
  from './vendor/nostr-tools.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Default relay set. Chosen for reliability and verified to accept kind 30402
 * writes; relay.nostr.band was removed after its WebSocket endpoint stopped
 * responding — every operation touching it wasted the connection timeout.
 * Users can add/remove relays per card in the editor.
 */
export const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://nostr.mom',
  'wss://offchain.pub',
];

/** NIP-33 addressable replaceable event kind for vCard blobs */
export const CARD_KIND = 30402;

/** NIP-78 "application-specific data" kind used for the cross-device sync snapshot */
export const SYNC_KIND = 30078;

/** Fixed d-tag identifying the sync snapshot event (one per sync identity).
 *  Protocol constant — do not rename: changing it orphans sync snapshots already published to relays. */
const SYNC_D_TAG = 'nostr-vcard-sync';

/** Custom addressable kind used for the ephemeral in-person pairing handshake */
export const PAIR_KIND = 30403;

/** Timeout for the first relay fetch attempt (ms) */
const FETCH_TIMEOUT_MS = 10_000;

/** Timeout for the retry attempt (ms) — slow relays and flaky connections get a second, longer window */
const FETCH_RETRY_TIMEOUT_MS = 15_000;

// ---------------------------------------------------------------------------
// Shared relay pool
// ---------------------------------------------------------------------------

/**
 * One SimplePool for the whole module. Connections are reused across publish /
 * fetch / delete operations instead of being opened and torn down per call.
 * Handshake rate limits make the connect-per-operation pattern a reliability
 * problem — relay.damus.io intermittently answers 503 to a burst of rapid
 * successive handshakes, which the old new-SimplePool-per-call code produced
 * constantly (one pool + close per fetch, publish, sync and pairing poll).
 */
const sharedPool = new SimplePool();

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

/**
 * Derive the hex public key from a raw 32-byte private key.
 * Used on backup import so the stored npub is never trusted from the file.
 * @param {Uint8Array} nsec
 * @returns {string} hex public key
 */
export function derivePublicKey(nsec) {
  return getPublicKey(nsec);
}

// ---------------------------------------------------------------------------
// Publish card event (NIP-33, kind 30402)
// ---------------------------------------------------------------------------

/**
 * Publish (or replace) a card event to all given relays.
 * NIP-33 semantics: relays keep only the latest event per (pubkey, kind, d-tag),
 * so re-publishing with the same d-tag automatically replaces the old event.
 *
 * No title/label tag is published — the relay must learn nothing about the
 * card owner beyond the public address (npub + d-tag). The label stays local;
 * recipients see the name from the decrypted vCard (FN field).
 *
 * @param {string[]}   relays         WebSocket relay URLs
 * @param {Uint8Array} nsec           Owner's private key (raw 32 bytes)
 * @param {string}     cardId         8-char card identifier (d-tag)
 * @param {string}     encryptedBlob  base64(IV[12] + AES-256-GCM ciphertext)
 * @returns {Promise<Array<{relay: string, ok: boolean}>>}
 */
export async function publishCard(relays, nsec, cardId, encryptedBlob) {
  const template = {
    kind:       CARD_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags:       [['d', cardId]],
    content:    encryptedBlob,
  };

  const event = finalizeEvent(template, nsec);

  const publishPromises = relays.map(async relay => {
    try {
      await sharedPool.publish([relay], event);
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
}

// ---------------------------------------------------------------------------
// Fetch card event (NIP-33, kind 30402)
// ---------------------------------------------------------------------------

/**
 * Fetch the latest card event for a given owner + card ID from the given relays.
 *
 * Robustness: relays are flaky — a first attempt that comes up empty (timeout,
 * dropped connection, relay briefly offline) is retried once with the default
 * relays added to the pool and a longer timeout. Without this, one slow relay
 * reads as "card not found" even though the event is live on another relay.
 *
 * @param {string[]} relays   WebSocket relay URLs (from the naddr hints)
 * @param {string}   npub     Owner's public key (hex)
 * @param {string}   cardId   Card identifier (d-tag)
 * @param {{fallbackRelays?: string[]}} [opts] Extra relays to add on the retry
 *   attempt. Defaults to DEFAULT_RELAYS; pass [] to disable the fallback.
 * @returns {Promise<{content: string, created_at: number}|null>}
 *   Returns the event content (encrypted blob) and timestamp, or null if not found.
 */
export async function fetchCard(relays, npub, cardId, { fallbackRelays = DEFAULT_RELAYS } = {}) {
  const event = await fetchCardOnce(relays, npub, cardId, FETCH_TIMEOUT_MS);
  if (event) return event;

  const retryRelays = [...relays];
  for (const relay of (fallbackRelays || [])) {
    if (!retryRelays.includes(relay) && isValidRelayUrl(relay)) retryRelays.push(relay);
  }
  return fetchCardOnce(retryRelays, npub, cardId, FETCH_RETRY_TIMEOUT_MS);
}

/** Single fetch attempt against the given relay list with an outer timeout. */
async function fetchCardOnce(relays, npub, cardId, timeoutMs) {
  const event = await Promise.race([
    sharedPool.get(relays, {
      kinds:   [CARD_KIND],
      authors: [npub],
      '#d':    [cardId],
    }),
    new Promise(resolve => setTimeout(() => resolve(null), timeoutMs)),
  ]);

  if (!event) return null;
  return { content: event.content, created_at: event.created_at, tags: event.tags || [] };
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
  await Promise.allSettled(relays.map(relay => sharedPool.publish([relay], event)));
}

// ---------------------------------------------------------------------------
// Sync snapshot event (NIP-78, kind 30078)
// ---------------------------------------------------------------------------

/**
 * Publish (or replace) the encrypted cross-device sync snapshot.
 * Same replaceable-event semantics as publishCard: relays keep only the
 * latest event per (pubkey, kind, d-tag), so re-publishing overwrites the old snapshot.
 *
 * @param {string[]}   relays         WebSocket relay URLs
 * @param {Uint8Array} syncNsec       Sync identity's private key (derived from a passphrase)
 * @param {string}     encryptedBlob  base64(IV[12] + AES-256-GCM ciphertext)
 * @returns {Promise<Array<{relay: string, ok: boolean}>>}
 */
export async function publishSyncEvent(relays, syncNsec, encryptedBlob) {
  const template = {
    kind:       SYNC_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags:       [['d', SYNC_D_TAG]],
    content:    encryptedBlob,
  };

  const event = finalizeEvent(template, syncNsec);

  const publishPromises = relays.map(async relay => {
    try {
      await sharedPool.publish([relay], event);
      return { relay, ok: true };
    } catch {
      return { relay, ok: false };
    }
  });

  const settled = await Promise.allSettled(publishPromises);
  return settled.map(r =>
    r.status === 'fulfilled' ? r.value : { relay: '?', ok: false }
  );
}

/**
 * Fetch the latest sync snapshot event for a given sync identity.
 *
 * @param {string[]} relays    WebSocket relay URLs
 * @param {string}   syncNpub  Sync identity's public key (hex)
 * @returns {Promise<{content: string, created_at: number}|null>}
 */
export async function fetchSyncEvent(relays, syncNpub) {
  const event = await Promise.race([
    sharedPool.get(relays, {
      kinds:   [SYNC_KIND],
      authors: [syncNpub],
      '#d':    [SYNC_D_TAG],
    }),
    new Promise(resolve => setTimeout(() => resolve(null), FETCH_TIMEOUT_MS)),
  ]);

  if (!event) return null;
  return { content: event.content, created_at: event.created_at };
}

/**
 * Publish a NIP-09 deletion event for the sync snapshot.
 * Deletion is best-effort — well-behaved relays will stop serving the event,
 * but not all relays honour deletion requests.
 *
 * @param {string[]}   relays    WebSocket relay URLs
 * @param {Uint8Array} syncNsec  Sync identity's private key
 * @returns {Promise<void>}
 */
export async function deleteSyncEvent(relays, syncNsec) {
  const syncNpub = getPublicKey(syncNsec);
  const template = {
    kind:       5,
    created_at: Math.floor(Date.now() / 1000),
    tags:       [['a', `${SYNC_KIND}:${syncNpub}:${SYNC_D_TAG}`]],
    content:    'deleted',
  };

  const event = finalizeEvent(template, syncNsec);
  await Promise.allSettled(relays.map(relay => sharedPool.publish([relay], event)));
}

// ---------------------------------------------------------------------------
// Pairing handshake slots (kind 30403) — two devices sharing a code (derived
// off-band, e.g. via QR) sign as the same identity but publish to different
// d-tag "slots" ('a' = initiator, 'b' = responder) so their offers don't
// overwrite each other.
// ---------------------------------------------------------------------------

/**
 * Publish (or replace) one pairing slot.
 * @param {string[]}   relays         WebSocket relay URLs
 * @param {Uint8Array} pairNsec       Pairing identity's private key (derived from the shared code)
 * @param {string}     slot           'a' (initiator) or 'b' (responder)
 * @param {string}     encryptedBlob  base64(IV[12] + AES-256-GCM ciphertext)
 * @returns {Promise<Array<{relay: string, ok: boolean}>>}
 */
export async function publishPairingSlot(relays, pairNsec, slot, encryptedBlob) {
  const template = {
    kind:       PAIR_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags:       [['d', slot]],
    content:    encryptedBlob,
  };

  const event = finalizeEvent(template, pairNsec);

  const publishPromises = relays.map(async relay => {
    try {
      await sharedPool.publish([relay], event);
      return { relay, ok: true };
    } catch {
      return { relay, ok: false };
    }
  });

  const settled = await Promise.allSettled(publishPromises);
  return settled.map(r =>
    r.status === 'fulfilled' ? r.value : { relay: '?', ok: false }
  );
}

/**
 * Fetch one pairing slot's latest event.
 * @param {string[]} relays    WebSocket relay URLs
 * @param {string}   pairNpub  Pairing identity's public key (hex)
 * @param {string}   slot      'a' or 'b'
 * @returns {Promise<{content: string, created_at: number}|null>}
 */
export async function fetchPairingSlot(relays, pairNpub, slot) {
  const event = await Promise.race([
    sharedPool.get(relays, {
      kinds:   [PAIR_KIND],
      authors: [pairNpub],
      '#d':    [slot],
    }),
    new Promise(resolve => setTimeout(() => resolve(null), FETCH_TIMEOUT_MS)),
  ]);

  if (!event) return null;
  return { content: event.content, created_at: event.created_at };
}

/**
 * Delete both pairing slots (best-effort NIP-09 — not all relays honour it).
 * @param {string[]}   relays    WebSocket relay URLs
 * @param {Uint8Array} pairNsec  Pairing identity's private key
 * @returns {Promise<void>}
 */
export async function deletePairingSlots(relays, pairNsec) {
  const pairNpub = getPublicKey(pairNsec);
  const template = {
    kind:       5,
    created_at: Math.floor(Date.now() / 1000),
    tags:       [
      ['a', `${PAIR_KIND}:${pairNpub}:a`],
      ['a', `${PAIR_KIND}:${pairNpub}:b`],
    ],
    content:    'deleted',
  };

  const event = finalizeEvent(template, pairNsec);
  await Promise.allSettled(relays.map(relay => sharedPool.publish([relay], event)));
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

/**
 * Compare two naddr strings by the card identity they point to (pubkey + d-tag),
 * ignoring relay hints — so re-sharing after adding/removing a relay, or a
 * peer re-pairing, is recognised as the same card instead of producing a duplicate.
 * Falls back to raw string equality if either naddr fails to decode.
 * @param {string} naddrA
 * @param {string} naddrB
 * @returns {boolean}
 */
export function sameCardAddress(naddrA, naddrB) {
  try {
    const a = naddrDecode(naddrA);
    const b = naddrDecode(naddrB);
    return a.pubkey === b.pubkey && a.identifier === b.identifier;
  } catch {
    return naddrA === naddrB;
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Validate a relay URL. Accepts wss:// always; ws:// only from a local
 * development origin — localhost, or a private-LAN IP served over plain http
 * (e.g. testing the dev server from a phone at http://192.168.x.x:8123
 * against a local test relay). Deployed pages (https, public domain) never
 * accept insecure relays, so a crafted share link can't direct a recipient's
 * browser at ws:// hosts.
 * @param {string} url
 * @returns {boolean}
 */
export function isValidRelayUrl(url) {
  try {
    const u = new URL(url);
    if (u.protocol === 'wss:') return true;
    if (u.protocol === 'ws:' && isLocalDevOrigin()) return true;
    return false;
  } catch {
    return false;
  }
}

/** True when the current page is served from a local development origin. */
function isLocalDevOrigin() {
  try {
    const host = location.hostname;
    if (host === 'localhost' || host === '::1' || host === '[::1]') return true;
    // Loopback and private LAN IPs (RFC 1918) + IPv4 link-local — but only
    // over plain http; an https page on a private IP is not a dev server
    // we set up.
    if (location.protocol !== 'http:') return false;
    const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return false;
    const a = Number(m[1]), b = Number(m[2]);
    return a === 127
      || a === 10
      || (a === 192 && b === 168)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 169 && b === 254);
  } catch {
    return false;
  }
}
