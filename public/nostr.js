/**
 * nostr.js — Nostr protocol layer for NostCard
 *
 * Handles keypair generation, event publishing, fetching, and naddr encoding.
 * All relay I/O is done via nostr-tools SimplePool (self-hosted bundle in vendor/).
 *
 * Card events use NIP-33 (addressable replaceable events, kind 36350).
 * Deletion uses NIP-09 (kind 5) and also requests removal of the old kind
 * 30402 address used before the kind switch — see LEGACY_CARD_KIND below.
 * Addresses are encoded as NIP-19 naddr bech32 strings.
 *
 * Security:
 *   - nsec (private key) is never logged here. Callers must not log card objects.
 *   - naddrDecode wraps nip19.decode in a try/catch; callers should also wrap.
 *   - Relay URLs are validated as wss:// (or ws:// in dev) before use.
 */

// Self-hosted bundle (nostr-tools 2.23.9) — rebuild with `npm run build:vendor`
import { generateSecretKey, getPublicKey, finalizeEvent, SimplePool, nip19, verifyEvent }
  from './vendor/nostr-tools.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Default relay set. Chosen for reliability and verified to accept card-event
 * writes (originally kind 30402; the same relays accept addressable kinds in
 * general, including the current CARD_KIND);
 * relay.nostr.band was removed after its WebSocket endpoint stopped
 * responding — every operation touching it wasted the connection timeout.
 * Users can add/remove relays per card in the editor.
 */
export const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://nostr.mom',
  'wss://offchain.pub',
];

/**
 * NIP-33 addressable replaceable event kind for vCard blobs. Chosen after
 * RFC 6350 (the vCard 4.0 spec) and verified unclaimed in the official NIPs
 * kind table and the nostr-protocol/registry-of-kinds registry.
 */
export const CARD_KIND = 36350;

/**
 * Kind used for card events before the switch to CARD_KIND. 30402 belongs to
 * NIP-99 (classified listings), which is why cards moved off it. No longer
 * read or written — only referenced in NIP-09 deletion requests so that
 * cards published before the switch are actually removed from relays.
 */
export const LEGACY_CARD_KIND = 30402;

/** NIP-78 "application-specific data" kind used for the cross-device sync snapshot */
export const SYNC_KIND = 30078;

/** Fixed d-tag identifying the sync snapshot event (one per sync identity).
 *  Protocol constant — do not rename: changing it orphans sync snapshots already published to relays. */
const SYNC_D_TAG = 'nostr-vcard-sync';

/** Custom addressable kind used for the ephemeral in-person pairing handshake */
export const PAIR_KIND = 30403;

/**
 * Addressable kind for the per-card recovery blob: the card's signing key
 * (nsec) encrypted under a passphrase-derived AES key. Same d-tag as the
 * card event and signed by the same nsec, so a share link (whose naddr
 * carries pubkey + d-tag) is enough to locate it and the recovery
 * passphrase is enough to decrypt it. Chosen adjacent to CARD_KIND; see
 * recovery.js for the content format.
 */
export const RECOVERY_KIND = 36351;

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

/**
 * Parse a user-supplied Nostr private key — bech32 (nsec1…) or 64-char hex.
 * Used by the "sign with your existing identity" option at card creation.
 * @param {string} input
 * @returns {Uint8Array} raw 32-byte private key
 * @throws on malformed input — callers must wrap in try/catch
 */
export function parseSecretKey(input) {
  const trimmed = String(input || '').trim();
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
    return bytes;
  }
  if (/^nsec1[a-z0-9]+$/i.test(trimmed)) {
    const decoded = nip19.decode(trimmed.toLowerCase());
    if (decoded.type !== 'nsec' || !(decoded.data instanceof Uint8Array) || decoded.data.length !== 32) {
      throw new Error('Invalid nsec');
    }
    return decoded.data;
  }
  throw new Error('Invalid private key');
}

// ---------------------------------------------------------------------------
// Publish card event (NIP-33, kind 36350)
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
  const event = finalizeEvent({
    kind:       CARD_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags:       [['d', cardId]],
    content:    encryptedBlob,
  }, nsec);

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
// Fetch card event (NIP-33, kind 36350)
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
  const event = await fetchCardOnce(relays, npub, cardId, FETCH_TIMEOUT_MS, CARD_KIND);
  if (event) return event;

  const retryRelays = [...relays];
  for (const relay of (fallbackRelays || [])) {
    if (!retryRelays.includes(relay) && isValidRelayUrl(relay)) retryRelays.push(relay);
  }
  return fetchCardOnce(retryRelays, npub, cardId, FETCH_RETRY_TIMEOUT_MS, CARD_KIND);
}

/** Single fetch attempt against the given relay list with an outer timeout. */
async function fetchCardOnce(relays, npub, cardId, timeoutMs, kind = CARD_KIND) {
  const event = await Promise.race([
    sharedPool.get(relays, {
      kinds:   [kind],
      authors: [npub],
      '#d':    [cardId],
    }),
    new Promise(resolve => setTimeout(() => resolve(null), timeoutMs)),
  ]);

  if (!event) return null;

  // Defense in depth: a malicious relay could ignore the filter and serve a
  // forged event. The AES-GCM content tag already prevents tampered payloads
  // from decrypting, but signature verification also rejects events signed
  // by a different key before decryption is attempted.
  if (!isAuthenticEvent(event, npub, kind, cardId)) {
    console.warn('Card event verification failed - possible tampering');
    return null;
  }

  return { content: event.content, created_at: event.created_at, tags: event.tags || [] };
}

/**
 * A valid signature alone only proves *someone* signed the event, so also
 * require the expected author, kind and d-tag — a relay can ignore the filter.
 * @param {object} event
 * @param {string} npub    expected author (hex)
 * @param {number} kind    expected kind
 * @param {string} cardId  expected d-tag
 * @returns {boolean}
 */
function isAuthenticEvent(event, npub, kind, cardId) {
  return event?.pubkey === npub
    && event.kind === kind
    && Array.isArray(event.tags)
    && event.tags.some(t => t[0] === 'd' && t[1] === cardId)
    && isVerifiedEvent(event);
}

/**
 * Verify a fetched event's signature; false on forged or malformed events.
 * Shared by all relay reads (cards, sync, pairing).
 * @param {object} event
 * @returns {boolean}
 */
function isVerifiedEvent(event) {
  try {
    return verifyEvent(event);
  } catch {
    return false;
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
 * The request covers the current address, the old kind-30402 address, and the
 * recovery-event address (kind RECOVERY_KIND, same d-tag): cards published
 * before the kind switch still have a live 30402 event on the relays, and a
 * card with a recovery passphrase set has a live recovery event — deleting a
 * card must remove all of them.
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
    tags:       [
      ['a', `${CARD_KIND}:${npub}:${cardId}`],
      ['a', `${LEGACY_CARD_KIND}:${npub}:${cardId}`],
      ['a', `${RECOVERY_KIND}:${npub}:${cardId}`],
    ],
    content:    'deleted',
  };

  const event = finalizeEvent(template, nsec);
  await Promise.allSettled(relays.map(relay => sharedPool.publish([relay], event)));
}

/**
 * Publish a NIP-09 deletion request for a card, then verify per relay that
 * the card event is actually no longer served, retrying the request once on
 * every relay that still serves it.
 *
 * Rationale: deletions apply with a delay on many relays and some ignore
 * NIP-09 entirely; plain deleteCard() gave the owner no signal about either.
 * Verification is a read: a relay that times out or errors is reported as
 * `deleted: true, verified: false` (benefit of the doubt) — only a relay
 * that verifiably still returns the event counts as not deleted, and only a
 * clean empty read counts as `verified: true`.
 *
 * @param {string[]}   relays  WebSocket relay URLs
 * @param {Uint8Array} nsec    Owner's private key (raw 32 bytes)
 * @param {string}     cardId  Card identifier
 * @param {{ verifyDelayMs?: number, verifyTimeoutMs?: number }} [opts]
 *   verifyDelayMs: pause after publishing before the first check (relays
 *   need a moment to apply the deletion). verifyTimeoutMs: per-relay read
 *   timeout for each verification round.
 * @returns {Promise<Array<{relay: string, deleted: boolean, verified: boolean}>>}
 *   deleted=false only when the relay verifiably still serves the event
 *   after the retry; verified=false means the check was inconclusive.
 */
export async function deleteCardVerified(relays, nsec, cardId, { verifyDelayMs = 1500, verifyTimeoutMs = 3000 } = {}) {
  const npub = getPublicKey(nsec);

  // Relay still serving the card? 'yes' only on a definitive event; 'no' on a
  // clean empty read; 'unknown' on timeout or error (inconclusive).
  const check = async (relay) => {
    let timer;
    try {
      const event = await Promise.race([
        sharedPool.get([relay], {
          kinds:   [CARD_KIND, LEGACY_CARD_KIND],
          authors: [npub],
          '#d':    [cardId],
        }),
        new Promise(resolve => { timer = setTimeout(() => resolve(TIMED_OUT), verifyTimeoutMs); }),
      ]);
      if (event === TIMED_OUT) return 'unknown';
      return event ? 'yes' : 'no';
    } catch {
      return 'unknown';
    } finally {
      clearTimeout(timer);
    }
  };
  const TIMED_OUT = Symbol('timeout');
  const toResult = (relay, state) => ({ relay, deleted: state !== 'yes', verified: state === 'no' });

  await deleteCard(relays, nsec, cardId);
  await sleep(verifyDelayMs);

  const firstRound = await Promise.all(relays.map(async relay => ({ relay, state: await check(relay) })));
  let results = firstRound.map(r => toResult(r.relay, r.state));

  // One retry round for relays that verifiably still serve the card
  const failedRelays = firstRound.filter(r => r.state === 'yes').map(r => r.relay);
  if (failedRelays.length > 0) {
    await deleteCard(failedRelays, nsec, cardId);
    await sleep(verifyDelayMs);
    const retryRound = await Promise.all(failedRelays.map(async relay => ({ relay, state: await check(relay) })));
    const retryMap = new Map(retryRound.map(r => [r.relay, toResult(r.relay, r.state)]));
    results = results.map(res => retryMap.get(res.relay) ?? res);
  }

  return results;
}

/** Promise-based pause. */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
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

  // Defense in depth — see fetchCardOnce.
  if (!isVerifiedEvent(event)) {
    console.warn('Sync event signature verification failed - possible tampering');
    return null;
  }

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
// Recovery event (addressable, kind 36351) — passphrase-encrypted copy of
// the card's signing key, see recovery.js for the content format.
// ---------------------------------------------------------------------------

/**
 * Publish (or replace) a card's recovery event to all given relays.
 * Same replaceable-event semantics as publishCard: relays keep only the
 * latest event per (pubkey, kind, d-tag), so re-publishing with the same
 * d-tag replaces the previous recovery blob (e.g. after rotating the
 * recovery passphrase).
 *
 * @param {string[]}   relays  WebSocket relay URLs
 * @param {Uint8Array} nsec    Owner's private key (raw 32 bytes)
 * @param {string}     cardId  Card identifier (d-tag — same as the card event)
 * @param {string}     content JSON payload (see recovery.js)
 * @returns {Promise<Array<{relay: string, ok: boolean}>>}
 */
export async function publishRecoveryEvent(relays, nsec, cardId, content) {
  const event = finalizeEvent({
    kind:       RECOVERY_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags:       [['d', cardId]],
    content,
  }, nsec);

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
 * Fetch every recovery event the relays serve for a card, newest first.
 * Relays can hold different generations (a replace that only reached some
 * relays, or a NIP-09 removal a relay ignored), so callers try them in order
 * rather than trusting whichever relay answered first.
 *
 * @param {string[]} relays  WebSocket relay URLs (from the naddr hints)
 * @param {string}   npub    Owner's public key (hex)
 * @param {string}   cardId  Card identifier (d-tag)
 * @returns {Promise<Array<{content: string, created_at: number}>>}
 */
export async function fetchRecoveryEvents(relays, npub, cardId, { fallbackRelays = DEFAULT_RELAYS } = {}) {
  const query = async (list, maxWait) => {
    let events;
    try {
      events = await sharedPool.querySync(list, {
        kinds:   [RECOVERY_KIND],
        authors: [npub],
        '#d':    [cardId],
      }, { maxWait });
    } catch {
      return [];
    }
    return events
      .filter(ev => isAuthenticEvent(ev, npub, RECOVERY_KIND, cardId))
      // The same event id arrives once per relay serving it — dedupe before
      // returning, or a wrong passphrase pays one PBKDF2 derivation per copy.
      .filter((ev, i, all) => all.findIndex(o => o.id === ev.id) === i)
      .sort((a, b) => b.created_at - a.created_at)
      .map(ev => ({ content: ev.content, created_at: ev.created_at }));
  };

  const found = await query(relays, FETCH_TIMEOUT_MS);
  if (found.length) return found;

  const retryRelays = [...relays];
  for (const relay of (fallbackRelays || [])) {
    if (!retryRelays.includes(relay) && isValidRelayUrl(relay)) retryRelays.push(relay);
  }
  return query(retryRelays, FETCH_RETRY_TIMEOUT_MS);
}

/**
 * Publish a NIP-09 deletion request for a card's recovery event only — the
 * card itself stays live. Used by "Remove recovery" in the editor.
 * Deletion is best-effort; not all relays honour NIP-09.
 *
 * @param {string[]}   relays  WebSocket relay URLs
 * @param {Uint8Array} nsec    Owner's private key (raw 32 bytes)
 * @param {string}     cardId  Card identifier (d-tag)
 * @returns {Promise<void>}
 */
export async function deleteRecoveryEvent(relays, nsec, cardId) {
  const npub = getPublicKey(nsec);
  const event = finalizeEvent({
    kind:       5,
    created_at: Math.floor(Date.now() / 1000),
    tags:       [['a', `${RECOVERY_KIND}:${npub}:${cardId}`]],
    content:    'deleted',
  }, nsec);
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

  // Defense in depth — see fetchCardOnce.
  if (!isVerifiedEvent(event)) {
    console.warn('Pairing event signature verification failed - possible tampering');
    return null;
  }

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
 * Encode a hex public key as an npub bech32 string (NIP-19) for display and
 * copy-paste into other Nostr clients. Throws on invalid hex — callers wrap.
 *
 * @param {string} npub Owner's public key (hex)
 * @returns {string} e.g. "npub1abc…"
 */
export function npubEncode(npub) {
  return nip19.npubEncode(npub);
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
