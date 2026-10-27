/**
 * security-tests.js — smoke tests for the security-sensitive code paths
 *
 * Run with: node tests/security-tests.js   (Node >= 19, or 18 with --experimental-global-webcrypto)
 * Uses browser shims (localStorage, location) so the app modules load as-is.
 */

// ---------------------------------------------------------------------------
// Browser shims
// ---------------------------------------------------------------------------

const store = new Map();
globalThis.localStorage = {
  getItem: k => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: k => store.delete(k),
};
globalThis.window = globalThis;
globalThis.location = { origin: 'https://nostcard.test', hostname: 'nostcard.test', protocol: 'https:' };

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const results = [];
const check = (name, ok) => { results.push({ name, ok }); console.log(`${ok ? '✅' : '❌'} ${name}`); };

async function testPassphraseValidation() {
  const { isValidSyncPassphrase, generateSyncPassphrase } = await import('../public/sync.js');
  const { BIP39_ENGLISH } = await import('../public/vendor/bip39-wordlist.js');

  // Words taken straight from the wordlist at spread-out indices
  const spread = [0, 300, 600, 900, 1200, 1500, 1800, 2000].map(i => BIP39_ENGLISH[i]).join('-');
  check('valid 8-word passphrase accepted', isValidSyncPassphrase(spread));
  check('too few words rejected', !isValidSyncPassphrase('zoo-zebra-yellow-wine-violin'));
  check('repeated words rejected', !isValidSyncPassphrase('abandon-abandon-abandon-abandon-abandon-abandon'));
  check('non-BIP39 word rejected', !isValidSyncPassphrase('zoo-zebra-yellow-xray-wine-violin'));
  check('excessive sequential pattern rejected', !isValidSyncPassphrase('abandon-ability-able-absurd-academy-across-action-actual'));

  // The generator is the only legitimate passphrase source — its output must always validate
  let allValid = true;
  for (let i = 0; i < 200; i++) {
    if (!isValidSyncPassphrase(generateSyncPassphrase())) { allValid = false; break; }
  }
  check('200 generated passphrases all accepted', allValid);
}

async function testSecureStorage() {
  const { secureStorage } = await import('../public/secureStorage.js');

  // Roundtrip
  await secureStorage.setItem('k1', JSON.stringify({ secret: 'nsec-data', n: 42 }));
  check('stored value is not plaintext', !store.get('k1').includes('nsec-data'));
  const back = JSON.parse(await secureStorage.getItem('k1'));
  check('roundtrip decrypts correctly', back.secret === 'nsec-data' && back.n === 42);

  // Absent key
  check('missing key returns null', (await secureStorage.getItem('nope')) === null);

  // Legacy plaintext value must throw so callers (secureReadJson) fall back to a plain read
  store.set('k2', JSON.stringify({ legacy: true }));
  let threw = false;
  try { await secureStorage.getItem('k2'); } catch { threw = true; }
  check('legacy plaintext throws (caller falls back + migrates)', threw);
}

async function testSignatureVerification() {
  const { generateSecretKey, finalizeEvent, verifyEvent } = await import('../public/vendor/nostr-tools.js');

  const nsec = generateSecretKey();
  const ev = finalizeEvent({ kind: 30078, created_at: 1_700_000_000, tags: [['d', 'test']], content: 'blob' }, nsec);

  // Simulate the relay→browser wire path: a WebSocket delivers parsed JSON,
  // which strips the verified-symbol cache finalizeEvent stamps on the local
  // object. (Object spread would keep that cache and make verifyEvent a no-op
  // — that is why the test goes through JSON.)
  const wire = JSON.parse(JSON.stringify(ev));
  check('valid wire event verifies', verifyEvent(wire) === true);
  check('tampered wire event rejected', verifyEvent(JSON.parse(JSON.stringify({ ...ev, content: 'evil' }))) === false);
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

await testPassphraseValidation();
await testSecureStorage();
await testSignatureVerification();

const failed = results.filter(r => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length > 0 ? 1 : 0);
