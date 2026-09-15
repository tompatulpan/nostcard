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

// ---------------------------------------------------------------------------
// Passphrase generation
// ---------------------------------------------------------------------------

// Small, unambiguous wordlist (no lookalike words) for a memorable, high-entropy passphrase.
const WORDLIST = [
  'anchor','banjo','canyon','delta','ember','falcon','glacier','harbor','indigo','jungle',
  'kayak','lantern','meadow','nectar','oasis','pebble','quartz','raven','summit','timber',
  'umbra','velvet','willow','xenon','yonder','zephyr','amber','birch','cedar','dune',
  'echo','forest','granite','holly','ivory','jasper','koala','lotus','maple','nimbus',
  'onyx','prairie','quokka','ridge','sable','tundra','ursa','violet','walnut','yarrow',
  'zinnia','arbor','basin','clover','drift','fjord','grove','haven','ibis',
  'juniper','kelp','lagoon','moss','nettle','opal','pine','quill','reef','shale',
  'thistle','umber','vale','wren','yew','zircon','alder','bramble','cinder','dusk',
];

/**
 * Generate a fresh, memorable sync passphrase (6 random words from a fixed wordlist).
 * @returns {string} e.g. "anchor-jungle-quartz-holly-drift-opal"
 */
export function generateSyncPassphrase() {
  const words = [];
  for (let i = 0; i < 6; i++) {
    const idx = crypto.getRandomValues(new Uint32Array(1))[0] % WORDLIST.length;
    words.push(WORDLIST[idx]);
  }
  return words.join('-');
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
