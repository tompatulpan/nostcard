/**
 * smoke-utils.mjs — browser-free smoke test for public/utils.js
 *
 * Runs the pure/shared logic (codecs, escaping, trust flags, rate limiting,
 * debounce) under Node with a minimal localStorage stub. No test framework,
 * no dependencies: `node tools/smoke-utils.mjs`
 *
 * Not covered here (need a browser + relays): DOM builders, .vcf download,
 * deletion verification — see the manual checklist in
 * FEATURE_CLEANUP_AND_REVIEW.md ("P1 — How to test").
 */

// localStorage stub — just enough for readJson/writeJson/getTrust/rate limiter
const store = new Map();
globalThis.localStorage = {
  getItem:    k => (store.has(k) ? store.get(k) : null),
  setItem:    (k, v) => store.set(k, String(v)),
  removeItem: k => store.delete(k),
};

const { default: assert } = await import('node:assert');
const {
  STORAGE_KEYS, readJson, writeJson,
  htmlEscape, makeInitials, bytesToHex, hexToBytes, bytesToBase64url, base64urlToBytes,
  sameSharedCardUrl, isSafeLinkUrl, getTrust, setTrust,
  debounce, checkRateLimit, recordRateLimitedAttempt, clearRateLimit,
} = await import('../public/utils.js');

// --- storage keys -----------------------------------------------------------
assert.strictEqual(STORAGE_KEYS.fields('abc'), 'e2e:fields:abc');
assert.strictEqual(STORAGE_KEYS.trust('pk:abc'), 'e2e:trusted:pk:abc');
assert.strictEqual(STORAGE_KEYS.savedLinks, 'e2e:saved-links');

// --- readJson/writeJson -----------------------------------------------------
assert.deepStrictEqual(readJson(STORAGE_KEYS.cards, []), []);
writeJson(STORAGE_KEYS.cards, [{ id: 'x' }]);
assert.deepStrictEqual(readJson(STORAGE_KEYS.cards, []), [{ id: 'x' }]);
store.set(STORAGE_KEYS.cards, '{not json');
assert.deepStrictEqual(readJson(STORAGE_KEYS.cards, []), []); // corrupt JSON → fallback

// --- htmlEscape -------------------------------------------------------------
assert.strictEqual(htmlEscape(`<a href="x">&'`), '&lt;a href=&quot;x&quot;&gt;&amp;&#x27;');

// --- hex / base64url codecs --------------------------------------------------
const bytes = new Uint8Array([0, 1, 2, 250, 255, 16]);
assert.strictEqual(bytesToHex(bytes), '000102faff10');
assert.deepStrictEqual(hexToBytes('000102faff10'), bytes);
const b64url = bytesToBase64url(bytes);
assert.ok(!/[+/=]/.test(b64url), 'base64url must not contain +, / or padding');
assert.deepStrictEqual(base64urlToBytes(b64url), bytes);

// --- makeInitials ------------------------------------------------------------
assert.strictEqual(makeInitials('Tomas Svensson'), 'TS');
assert.strictEqual(makeInitials('cher'), 'C');
assert.strictEqual(makeInitials(''), '');

// --- share URL identity -----------------------------------------------------
const urlA = 'https://host/card?naddr=naddr1qq9kummnw3example#key';
const urlB = 'https://other.host/card?naddr=naddr1qq9kummnw3example#otherkey';
const urlC = 'https://host/card?naddr=naddr1different#key';
assert.strictEqual(sameSharedCardUrl(urlA, urlB), true);   // same naddr, different origin/key
assert.strictEqual(sameSharedCardUrl(urlA, urlC), false);  // different naddr
assert.strictEqual(sameSharedCardUrl('not a url', 'not a url'), true); // fallback: raw equality

// --- safe link URLs ---------------------------------------------------------
assert.strictEqual(isSafeLinkUrl('https://host/card'), true);
assert.strictEqual(isSafeLinkUrl('http://localhost:8123/card'), true);
assert.strictEqual(isSafeLinkUrl('http://example.com/card'), false);
assert.strictEqual(isSafeLinkUrl('javascript:alert(1)'), false);
assert.strictEqual(isSafeLinkUrl('data:text/html,hi'), false);

// --- trust flags (30-day sliding TTL) --------------------------------------
setTrust('pk:card1');
assert.strictEqual(getTrust('pk:card1'), true);
assert.strictEqual(getTrust('pk:card2'), false);            // separate flag per card
store.set(STORAGE_KEYS.trust('pk:card3'), JSON.stringify({ ok: true, expires: Date.now() - 1000 }));
assert.strictEqual(getTrust('pk:card3'), false);            // expired → removed, fail closed
assert.ok(!store.has(STORAGE_KEYS.trust('pk:card3')), 'expired flag should be removed');

// --- rate limiter -----------------------------------------------------------
const opts = { max: 3, windowMs: 1000, lockoutMs: 2000 };
assert.strictEqual(checkRateLimit('t', opts).allowed, true);
recordRateLimitedAttempt('t', opts);
recordRateLimitedAttempt('t', opts);
assert.strictEqual(checkRateLimit('t', opts).remaining, 1);
recordRateLimitedAttempt('t', opts);                        // 3rd attempt → lockout starts
const locked = checkRateLimit('t', opts);
assert.strictEqual(locked.allowed, false);
assert.ok(locked.waitMs > 0 && locked.waitMs <= 2000);
clearRateLimit('t');
assert.strictEqual(checkRateLimit('t', opts).allowed, true);

// --- debounce ---------------------------------------------------------------
let calls = 0;
const bump = debounce(() => calls++, 20);
bump(); bump(); bump(); bump();                            // rapid clicks coalesce
assert.strictEqual(calls, 0, 'debounced fn must not run synchronously');
await new Promise(r => setTimeout(r, 60));
assert.strictEqual(calls, 1, 'rapid calls must coalesce into exactly one run');

console.log('smoke-utils: all checks passed');
