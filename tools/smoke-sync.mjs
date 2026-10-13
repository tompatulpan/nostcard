/**
 * smoke-sync.mjs — end-to-end offline test of the cross-device sync feature
 *
 * Spawns tools/test-relay.mjs (local, no signature verification) and drives
 * the real sync layer end to end: passphrase → derived identity → encrypted
 * snapshot push → pull on a second "device" → field-cache merge. Covers the
 * regression where a pull never updated a stale local field cache (edits made
 * on another device were invisible until the cache was manually cleared).
 *
 * No test framework, no extra dependencies: `node tools/smoke-sync.mjs`
 *
 * Not covered here: NIP-09 snapshot deletion (the test relay doesn't honour
 * deletion requests) and the sync modal UI (needs a browser).
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const TOOLS_DIR = dirname(fileURLToPath(import.meta.url));
const RELAY_PORT = 48778;
const RELAY_URL = `ws://127.0.0.1:${RELAY_PORT}`;

// --- start the local test relay ------------------------------------------------

const relay = spawn(process.execPath, [join(TOOLS_DIR, 'test-relay.mjs'), String(RELAY_PORT)], {
  stdio: ['ignore', 'pipe', 'inherit'],
});
await new Promise((resolve, reject) => {
  relay.stdout.on('data', chunk => { if (String(chunk).includes('listening')) resolve(); });
  relay.on('error', reject);
  relay.on('exit', code => reject(new Error(`test relay exited early (code ${code})`)));
  setTimeout(() => reject(new Error('test relay did not start in 10s')), 10_000);
});

try {
  const { default: assert } = await import('node:assert');

  // localStorage stub — the "second device" local state (stale field caches)
  const store = new Map();
  globalThis.localStorage = {
    getItem:    k => (store.has(k) ? store.get(k) : null),
    setItem:    (k, v) => store.set(k, String(v)),
    removeItem: k => store.delete(k),
  };

  const {
    generateSyncPassphrase, isValidSyncPassphrase, deriveSyncIdentity,
    pushSyncData, pullSyncData,
  } = await import('../public/sync.js');
  const { STORAGE_KEYS, mergeFieldCaches } = await import('../public/utils.js');

  // --- passphrase form ---------------------------------------------------------

  const passphrase = generateSyncPassphrase();
  const words = passphrase.split('-');
  assert.strictEqual(words.length, 8, 'generated passphrase must be 8 words');
  assert.ok(isValidSyncPassphrase(passphrase), 'generated passphrase must validate');
  assert.ok(!isValidSyncPassphrase('hunter2'), 'hand-typed passphrase must be rejected');
  assert.ok(!isValidSyncPassphrase(words.slice(0, 5).join('-')), 'too few words must be rejected');
  assert.ok(!isValidSyncPassphrase(words.slice(0, 7).concat('notaword').join('-')), 'non-BIP39 words must be rejected');

  // --- device A: derive identity, push a v3 snapshot ---------------------------

  const identityA = await deriveSyncIdentity(passphrase);
  const snapshotA = {
    version: 3,
    exported: new Date().toISOString(),
    cards: [
      { id: 'card1', label: 'Work', nsec: 'a'.repeat(64), npub: 'b'.repeat(64), key: 'k1', relays: [RELAY_URL] },
      { id: 'card2', label: 'Personal', nsec: 'c'.repeat(64), npub: 'd'.repeat(64), key: 'k2', relays: [RELAY_URL] },
    ],
    savedLinks: [{ url: 'https://host/card?naddr=abc#key', label: 'Alice', savedAt: '2026-10-01T00:00:00Z', updatedAt: '2026-10-01T00:00:00Z' }],
    connections: [],
    fields: {
      card1: { fn: 'Alice', tel: ['+46700000000'], __relayTs: 1_000 },
      card2: { fn: 'Bob', __relayTs: 1_000 },
    },
  };
  const pushed = await pushSyncData([RELAY_URL], identityA.syncNsec, identityA.syncKeyRaw, snapshotA);
  assert.ok(pushed.every(r => r.ok), `snapshot push must succeed on the test relay (got ${JSON.stringify(pushed)})`);

  // --- device B: same passphrase → same identity, pull, merge ------------------
  // Device B already has card1 with a STALE cache (edit made on A is newer).
  // This is the regression: the pull must bring A's newer fields across.

  const identityB = await deriveSyncIdentity(passphrase);
  assert.strictEqual(identityB.syncNpub, identityA.syncNpub, 'same passphrase must derive the same sync identity');
  assert.strictEqual(identityB.syncKeyRaw.join(), identityA.syncKeyRaw.join(), 'same passphrase must derive the same AES key');

  store.set(STORAGE_KEYS.fields('card1'), JSON.stringify({ fn: 'Alice Old', __relayTs: 500 }));
  const pulledB = await pullSyncData([RELAY_URL], identityB.syncNpub, identityB.syncKeyRaw);
  assert.ok(pulledB, 'pull must find the snapshot pushed moments ago');
  assert.deepStrictEqual(pulledB.payload, snapshotA, 'pulled payload must match the pushed snapshot');
  assert.ok(pulledB.createdAt > 0, 'pull must report the snapshot event timestamp');

  mergeFieldCaches(pulledB.payload.fields);
  const cacheB1 = JSON.parse(store.get(STORAGE_KEYS.fields('card1')));
  assert.strictEqual(cacheB1.fn, 'Alice', 'pull must overwrite a stale local field cache (newer __relayTs wins)');
  assert.strictEqual(cacheB1.__relayTs, 1_000, 'merge must keep the snapshot\'s own __relayTs');
  const cacheB2 = JSON.parse(store.get(STORAGE_KEYS.fields('card2')));
  assert.strictEqual(cacheB2.fn, 'Bob', 'pull must fill a device that has no cache for the card');

  // --- wrong passphrase → no snapshot found ------------------------------------

  const identityC = await deriveSyncIdentity(generateSyncPassphrase());
  const pulledC = await pullSyncData([RELAY_URL], identityC.syncNpub, identityC.syncKeyRaw);
  assert.strictEqual(pulledC, null, 'a different passphrase must find nothing');

  // --- edit on device A, re-push; device B pulls and sees the change -----------
  // (wait >1s so the replacement event has a strictly newer created_at —
  //  the test relay serves all versions and the client picks the newest)

  await new Promise(r => setTimeout(r, 1_100));
  snapshotA.fields.card1 = { fn: 'Alice Updated', tel: ['+46700000000'], __relayTs: 2_000 };
  snapshotA.cards[0].label = 'Work (renamed)';
  const repushed = await pushSyncData([RELAY_URL], identityA.syncNsec, identityA.syncKeyRaw, snapshotA);
  assert.ok(repushed.every(r => r.ok), 'replacing the snapshot must succeed');

  const pulledB2 = await pullSyncData([RELAY_URL], identityB.syncNpub, identityB.syncKeyRaw);
  assert.ok(pulledB2, 'second pull must find the replaced snapshot');
  assert.strictEqual(pulledB2.payload.fields.card1.fn, 'Alice Updated', 'pull must return the replaced snapshot, not the original');
  assert.strictEqual(pulledB2.payload.cards[0].label, 'Work (renamed)');

  mergeFieldCaches(pulledB2.payload.fields);
  const cacheB1b = JSON.parse(store.get(STORAGE_KEYS.fields('card1')));
  assert.strictEqual(cacheB1b.fn, 'Alice Updated', 'an edit pushed on device A must land on device B via pull + merge');
  assert.strictEqual(cacheB1b.__relayTs, 2_000);

  // Device B made a NEWER local edit after the pull — a stale re-pull must not clobber it
  store.set(STORAGE_KEYS.fields('card2'), JSON.stringify({ fn: 'Bob Local Edit', __relayTs: 3_000 }));
  mergeFieldCaches(pulledB2.payload.fields);
  const cacheB2b = JSON.parse(store.get(STORAGE_KEYS.fields('card2')));
  assert.strictEqual(cacheB2b.fn, 'Bob Local Edit', 'newer local cache must survive a pull of older data');

  console.log('smoke-sync: all checks passed');
} finally {
  relay.kill('SIGTERM');
}
