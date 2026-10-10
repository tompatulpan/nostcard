/**
 * utils.js — shared helpers, constants and small utilities for NostCard
 *
 * Single home for everything app.js, card.js and proof.js used to duplicate:
 *   - STORAGE_KEYS: every localStorage key as a named constant (typo-proof,
 *     greppable, one place to rename)
 *   - HTML escaping and safe DOM row building
 *   - hex / base64url codecs
 *   - recipient trust flags (30-day sliding TTL)
 *   - share-URL card-identity comparison
 *   - central non-fatal error reporter
 *   - debounce (publish coalescing) and localStorage-backed rate limiting
 *
 * Security:
 *   - htmlEscape() must wrap every user-controlled value placed into an
 *     innerHTML template string
 *   - reportError() logs err.message only — never pass raw card objects
 *     (they contain nsec / AES keys)
 *   - trust and rate-limit helpers tolerate blocked storage (public mode,
 *     sandboxed iframes) by failing closed / open respectively
 */

import { sameCardAddress } from './nostr.js';
import { brandIconSvg } from './brand-icons.js';

// ---------------------------------------------------------------------------
// Storage keys — every localStorage key in the app, as named constants
// ---------------------------------------------------------------------------

/**
 * All localStorage keys used by NostCard. Functions build per-entity keys
 * (card fields, relay status, trust flags, …) so the `e2e:` prefix and each
 * key's shape are defined in exactly one place.
 *
 * Do not rename existing values: stored data (trust flags, rate-limit
 * counters) would be orphaned for existing users.
 *
 * @typedef {{ id: string, label: string, nsec: string, npub: string, key: string, relays: string[] }} CardCredential
 * @typedef {{ url: string, label: string, savedAt: string, updatedAt: string }} SavedLink
 * @typedef {{ id: string, peerLabel: string, peerNaddr: string, peerKey: string, myCardId: string|null, pairedAt: string, updatedAt: string }} Connection
 */
export const STORAGE_KEYS = {
  /** @type {CardCredential[]} */
  cards: 'e2e:cards',
  /** @param {string} id @returns {string} */
  fields: (id) => `e2e:fields:${id}`,
  /** @type {SavedLink[]} */
  savedLinks: 'e2e:saved-links',
  /** "1" marks a card as backed up — @param {string} id @returns {string} */
  exported: (id) => `e2e:exported:${id}`,
  /** cached passphrase-derived sync identity */
  syncIdentity: 'e2e:sync-identity',
  /** sync push/pull timestamps */
  syncMeta: 'e2e:sync-meta',
  /** @type {Connection[]} */
  connections: 'e2e:connections',
  /** cached decrypted vCard fields of a paired peer — @param {string} id @returns {string} */
  connectionFields: (id) => `e2e:connection-fields:${id}`,
  /** per-card relay publish status [{relay, ok}] — @param {string} id @returns {string} */
  relayStatus: (id) => `e2e:relay-status:${id}`,
  /** device trust flag {ok, expires} — @param {string} trustId `<pubkey>:<cardId>` @returns {string} */
  trust: (trustId) => `e2e:trusted:${trustId}`,
  /** language preference (written by i18n.js setLang) */
  lang: 'e2e:lang',
  /** attempt-counter buckets for the rate limiter — @param {string} bucket @returns {string} */
  rateLimit: (bucket) => `e2e:rl:${bucket}`,
};

/**
 * Read and parse a JSON localStorage value. Storage may be blocked (public
 * mode, sandboxed iframe, quota) — returns the fallback instead of throwing.
 * @template T
 * @param {string} key
 * @param {T} fallback
 * @returns {T}
 */
export function readJson(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    if (raw === null) return fallback;
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

/**
 * Serialize and write a JSON value. Throws only if storage itself rejects the
 * write (quota) — callers decide whether that is fatal; most treat it as
 * best-effort and wrap in try/catch.
 * @param {string} key
 * @param {unknown} value
 * @returns {void}
 */
export function writeJson(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}

// ---------------------------------------------------------------------------
// HTML escaping
// ---------------------------------------------------------------------------

/**
 * Escape HTML special characters for safe interpolation into innerHTML
 * template strings. All user-controlled values must pass through this.
 * @param {unknown} str
 * @returns {string}
 */
export function htmlEscape(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ---------------------------------------------------------------------------
// Codecs
// ---------------------------------------------------------------------------

/**
 * Hex-encode a byte array.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Decode a hex string into a byte array. Callers must trust the input shape
 * (callers validate length before use as a key).
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

/**
 * Standard base64 → URL-safe base64 (no `+`, `/`, or padding).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToBase64url(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * URL-safe base64 → bytes. Throws on malformed input (callers wrap in
 * try/catch — this doubles as key-format validation).
 * @param {string} str
 * @returns {Uint8Array}
 */
export function base64urlToBytes(str) {
  const b64    = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/**
 * Up to two uppercase initials from a full name, for the avatar circle.
 * @param {string} name
 * @returns {string}
 */
export function makeInitials(name) {
  return String(name || '')
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map(w => w[0].toUpperCase())
    .join('');
}

// ---------------------------------------------------------------------------
// Share URLs
// ---------------------------------------------------------------------------

/**
 * Extract the `naddr` query param from a share URL, or null if missing/malformed.
 * @param {string} url
 * @returns {string|null}
 */
export function extractNaddrFromUrl(url) {
  try { return new URL(url).searchParams.get('naddr'); } catch { return null; }
}

/**
 * Compare two share URLs by the card identity their naddr points at
 * (pubkey + d-tag), not by exact string — so re-sharing after a relay-list
 * edit is recognised as the same card instead of producing a duplicate.
 * Falls back to raw string equality if either URL has no valid naddr.
 * @param {string} urlA
 * @param {string} urlB
 * @returns {boolean}
 */
export function sameSharedCardUrl(urlA, urlB) {
  const a = extractNaddrFromUrl(urlA), b = extractNaddrFromUrl(urlB);
  if (!a || !b) return urlA === urlB;
  return sameCardAddress(a, b);
}

/**
 * True if a saved-link URL may be opened: https:// always, http:// only from
 * localhost (dev). Rejects arbitrary-scheme injection (javascript:, data:, …).
 * @param {string} url
 * @returns {boolean}
 */
export function isSafeLinkUrl(url) {
  try {
    const u = new URL(url);
    if (u.protocol === 'https:') return true;
    return u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1');
  } catch { return false; }
}

// ---------------------------------------------------------------------------
// Recipient device trust (30-day sliding TTL)
// ---------------------------------------------------------------------------

/** How long a "trusted device" flag lasts; every trusted visit re-extends it. */
export const TRUST_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * True if this device is trusted for the given card (`<pubkey>:<cardId>`),
 * with a sliding TTL: each trusted visit re-extends the window from now.
 * Storage failures read as untrusted (fail closed).
 * @param {string} trustId
 * @returns {boolean}
 */
export function getTrust(trustId) {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.trust(trustId));
    if (!raw) return false;
    const data = JSON.parse(raw);
    if (!data || !data.ok || Date.now() > data.expires) {
      localStorage.removeItem(STORAGE_KEYS.trust(trustId));
      return false;
    }
    localStorage.setItem(
      STORAGE_KEYS.trust(trustId),
      JSON.stringify({ ok: true, expires: Date.now() + TRUST_TTL_MS })
    );
    return true;
  } catch {
    return false;
  }
}

/**
 * Mark this device as trusted for the given card. Best-effort — storage
 * blocked (public mode) simply means no trust is persisted.
 * @param {string} trustId
 * @returns {void}
 */
export function setTrust(trustId) {
  try {
    localStorage.setItem(
      STORAGE_KEYS.trust(trustId),
      JSON.stringify({ ok: true, expires: Date.now() + TRUST_TTL_MS })
    );
  } catch { /* storage blocked */ }
}

// ---------------------------------------------------------------------------
// URL platform detection (websites vs. social profiles)
// ---------------------------------------------------------------------------

/** host === base or any subdomain of base (www., m., …) */
const isHost = (host, base) => host === base || host.endsWith('.' + base);

/**
 * Known platforms a card's URL field may point at. Detection is purely
 * presentational — it changes the icon shown to recipients and in the editor,
 * never the stored vCard data — so no migration is needed for existing cards.
 * Ordered: first match wins.
 */
const URL_PLATFORMS = [
  // NostCard's own share links: <any host>/<subpath>/card?naddr=… — the path
  // scheme is fixed by the app, the host is not (cards can be served anywhere).
  { key: 'nostcard', icon: '🔐', match: (h, p, u) => /\/card\/?$/.test(p) && u.searchParams.has('naddr') },
  { key: 'nostr',     icon: '⚡', schemes: ['nostr:'], match: h =>
      isHost(h, 'snort.social') || isHost(h, 'primal.net') || isHost(h, 'nos.app') ||
      isHost(h, 'coracle.social') || isHost(h, 'njump.me') || isHost(h, 'nostur.app') ||
      isHost(h, 'iris.to') },
  { key: 'github',    icon: '🐙', match: h => isHost(h, 'github.com') },
  { key: 'linkedin',  icon: '💼', match: h => isHost(h, 'linkedin.com') || isHost(h, 'lnkd.in') },
  { key: 'x',         icon: '𝕏',  match: h => isHost(h, 'x.com') || isHost(h, 'twitter.com') },
  { key: 'instagram', icon: '📸', match: h => isHost(h, 'instagram.com') },
  { key: 'threads',   icon: '🧵', match: h => isHost(h, 'threads.net') || isHost(h, 'threads.com') },
  { key: 'bluesky',   icon: '🦋', match: h => isHost(h, 'bsky.app') },
  { key: 'tiktok',    icon: '🎵', match: h => isHost(h, 'tiktok.com') },
  { key: 'youtube',   icon: '📺', match: h => isHost(h, 'youtube.com') || isHost(h, 'youtu.be') },
  { key: 'facebook',  icon: '📘', match: h => isHost(h, 'facebook.com') || isHost(h, 'fb.com') || isHost(h, 'fb.me') },
  { key: 'telegram',  icon: '✈️', match: h => isHost(h, 't.me') || isHost(h, 'telegram.me') },
  { key: 'whatsapp',  icon: '💬', match: h => isHost(h, 'wa.me') || isHost(h, 'chat.whatsapp.com') },
  { key: 'signal',    icon: '🔒', match: h => isHost(h, 'signal.me') || isHost(h, 'signal.link') },
  { key: 'deltachat', icon: '📨', schemes: ['dcaccount:', 'openpgp4fpr:'], match: h =>
      isHost(h, 'delta.chat') || isHost(h, 'deltachat.de') },
  { key: 'twitch',    icon: '🎮', match: h => isHost(h, 'twitch.tv') },
  { key: 'reddit',    icon: '👽', match: h => isHost(h, 'reddit.com') },
  // Mastodon has no fixed domain — match known instances plus the /@handle
  // profile-path convention shared by most fediverse software.
  { key: 'mastodon',  icon: '🐘', match: (h, p) => /(^|\.)mastodon\./.test(h) || /^\/@/.test(p) },
];

/**
 * Detect which known platform a URL points at, for icon display.
 * Accepts scheme-less input ("github.com/alice") the way a user might type it.
 * @param {string} raw
 * @returns {{ key: string, icon: string, scheme?: string } | null}
 *   the matched platform, or null for plain websites / unparseable input
 */
export function detectUrlPlatform(raw) {
  const val = String(raw || '').trim();
  if (!val) return null;
  for (const p of URL_PLATFORMS) {
    if (p.schemes?.some(s => val.toLowerCase().startsWith(s))) return p;
  }
  let u;
  try { u = new URL(/^[a-z][a-z0-9+.-]*:/i.test(val) ? val : 'https://' + val.replace(/^\/+/, '')); }
  catch { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  const host = u.hostname.toLowerCase();
  for (const p of URL_PLATFORMS) {
    if (p.match(host, u.pathname, u)) return p;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Contact rendering (shared by card.js and the inline viewer in app.js)
// ---------------------------------------------------------------------------

/**
 * Build one contact field row as a DOM element. Href values are filtered to
 * safe schemes (http(s):, tel:, mailto:) — anything else (javascript:, data:,
 * …) is rendered as plain text instead of a link.
 * @param {string|{platform: string, emoji?: string}} icon
 *   emoji label shown in the icon slot, or a platform descriptor rendered as
 *   the real brand SVG (falls back to the emoji if no icon exists)
 * @param {string} type     CSS modifier for the row (`contact-field--<type>`)
 * @param {string} text     displayed value (already user-controlled — set via textContent)
 * @param {string|null} href link target, or null for non-link rows
 * @returns {HTMLElement}
 */
export function contactFieldRow(icon, type, text, href) {
  const row = document.createElement('div');
  row.className = `field-row contact-field contact-field--${type}`;

  const iconEl = document.createElement('span');
  iconEl.className = 'field-icon';
  if (icon && typeof icon === 'object' && icon.platform) {
    const svg = brandIconSvg(icon.platform);
    if (svg) iconEl.innerHTML = svg;          // developer-controlled markup only
    else if (icon.emoji) iconEl.textContent = icon.emoji;
  } else {
    iconEl.textContent = icon;
  }

  const valueEl = document.createElement('span');
  valueEl.className = 'field-value';

  const safeHref = href && /^(https?:|tel:|mailto:)/i.test(href) ? href : null;
  if (safeHref) {
    const a = document.createElement('a');
    a.href        = safeHref;
    a.textContent = text;
    if (safeHref.startsWith('http')) {
      a.target = '_blank';
      a.rel    = 'noopener noreferrer';
    }
    valueEl.appendChild(a);
  } else {
    valueEl.textContent = text;
  }

  row.appendChild(iconEl);
  row.appendChild(valueEl);
  return row;
}

/**
 * Append every populated field of a parsed vCard to a container as contact
 * rows — the loop shared by the recipient page (card.js) and the inline
 * viewer (app.js).
 * @param {HTMLElement} container
 * @param {object} fields parsed vCard fields (see vcard.js parseVCard)
 * @param {(icon: string, type: string, text: string, href: string|null) => HTMLElement} row
 *   row builder (contactFieldRow); injected so callers can subclass if needed
 * @param {{ typeLabel?: (type: string) => string }} [opts]
 *   typeLabel renders a vCard TYPE (e.g. adr type) in the active locale —
 *   injected to keep this module i18n-free
 * @returns {void}
 */
export function appendContactRows(container, fields, row, { typeLabel } = {}) {
  const nameParts = [fields.firstName, fields.lastName].filter(Boolean).join(' ');
  if (nameParts && nameParts !== fields.fn) {
    container.appendChild(row('👤', 'name', nameParts, null));
  }
  for (const tel of (fields.tel || [])) {
    const val = typeof tel === 'string' ? tel : tel.value;
    if (val && val.trim()) container.appendChild(row('📞', 'tel', val.trim(), `tel:${val.trim()}`));
  }
  for (const email of (fields.email || [])) {
    const val = typeof email === 'string' ? email : email.value;
    if (val && val.trim()) container.appendChild(row('✉️', 'email', val.trim(), `mailto:${val.trim()}`));
  }
  const urls = Array.isArray(fields.url) ? fields.url : (fields.url ? [{ value: fields.url }] : []);
  for (const urlItem of urls) {
    const val = typeof urlItem === 'string' ? urlItem : urlItem.value;
    if (val && val.trim()) {
      const platform = detectUrlPlatform(val.trim());
      const key = platform ? platform.key : 'website';
      const emoji = platform ? platform.icon : '🔗';
      container.appendChild(row({ platform: key, emoji }, key, val.trim(), val.trim()));
    }
  }
  const notes = Array.isArray(fields.note) ? fields.note : (fields.note ? [fields.note] : []);
  for (const noteItem of notes) {
    if (noteItem && String(noteItem).trim()) container.appendChild(row('📝', 'note', String(noteItem).trim(), null));
  }
  for (const adr of (fields.adr || [])) {
    const parts = [adr.street, adr.city, adr.region, adr.postcode, adr.country].filter(Boolean).join(', ');
    if (!parts) continue;
    const label = adr.type && adr.type !== 'home' && typeLabel ? typeLabel(adr.type) : '';
    container.appendChild(row('🏠', 'adr', label ? `${label}: ${parts}` : parts, null));
  }
}

// ---------------------------------------------------------------------------
// .vcf download
// ---------------------------------------------------------------------------

/**
 * Trigger a .vcf file download of the given vCard text.
 * @param {string} vcardText
 * @param {string} fn display name — used for the filename
 * @param {{ stripSource?: boolean }} [opts] stripSource removes the SOURCE
 *   line for recipient downloads (the canonical URL lacks the #key and is
 *   useless to a contacts app); the owner's own download keeps it
 * @returns {void}
 */
export function downloadVcf(vcardText, fn, { stripSource = false } = {}) {
  const filename = (fn || 'contact').replace(/[^a-zA-Z0-9_-]/g, '_') + '.vcf';
  const payload  = stripSource
    ? vcardText.replace(/^SOURCE:[^\r\n]*\r?\n?/m, '')
    : vcardText;
  const blob = new Blob([payload], { type: 'text/vcard;charset=utf-8' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Central non-fatal error reporting
// ---------------------------------------------------------------------------

/**
 * Report a non-fatal error from one consistent place. Every catch block that
 * previously did `console.warn('[app] something failed:', err.message)`
 * should call this instead so log shape, prefix and redaction stay uniform.
 *
 * Redaction: pass the Error itself — only `err.message` is ever logged. Never
 * pass raw card/connection objects (they contain nsec / AES keys).
 *
 * @param {unknown} err
 * @param {string} context dot-separated tag, e.g. 'app.editor-refresh'
 * @returns {void}
 */
export function reportError(err, context) {
  const msg = err instanceof Error ? err.message : String(err);
  console.warn(`[${context}]`, msg);
}

// ---------------------------------------------------------------------------
// Debounce
// ---------------------------------------------------------------------------

/**
 * Trailing-edge debounce: rapid calls coalesce into a single call to `fn`
 * once `waitMs` have passed without a new call. Used on publish-style
 * operations (Save, Sync push) so button-mashing produces one relay write
 * with the latest state instead of N identical publishes. `fn` always runs
 * with the most recent arguments.
 * @param {(...args: any[]) => void} fn
 * @param {number} waitMs
 * @returns {(...args: any[]) => void}
 */
export function debounce(fn, waitMs) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => {
      // fn may be async — surface rejections instead of leaving them unhandled
      Promise.resolve().then(() => fn(...args)).catch(err => reportError(err, 'utils.debounce'));
    }, waitMs);
  };
}

// ---------------------------------------------------------------------------
// Attempt rate limiting (localStorage-backed)
// ---------------------------------------------------------------------------

/**
 * Lightweight attempt limiter for expensive local operations (e.g. sync
 * passphrase derivation). Counters live in localStorage per bucket:
 * `{ attempts: number[], lockedUntil: number }`.
 *
 * Honest scope: this is on-device friction against scripted grinding — a
 * determined local attacker can clear storage. It does NOT defend the relay-
 * side snapshot against offline brute force; that protection is the
 * passphrase entropy (8 BIP39 words ≈ 88 bits) plus 600k PBKDF2 iterations.
 * Storage failures read as "allowed" (fail open) so blocked storage never
 * breaks the feature for legitimate users.
 *
 * @param {string} bucket
 * @param {{ max: number, windowMs: number, lockoutMs: number }} opts
 *   max attempts per windowMs before a lockoutMs cooldown starts
 * @returns {{ allowed: boolean, waitMs: number, remaining: number }}
 *   waitMs is set when not allowed; remaining is attempts left this window
 */
export function checkRateLimit(bucket, { max, windowMs, lockoutMs }) {
  const data = readJson(STORAGE_KEYS.rateLimit(bucket), { attempts: [], lockedUntil: 0 });
  const now  = Date.now();
  if (data.lockedUntil > now) {
    return { allowed: false, waitMs: data.lockedUntil - now, remaining: 0 };
  }
  const recent = (data.attempts || []).filter(ts => now - ts < windowMs);
  return { allowed: recent.length < max, waitMs: 0, remaining: Math.max(0, max - recent.length) };
}

/**
 * Record one attempt in a rate-limit bucket. Exceeding `max` attempts inside
 * the window starts the lockout and resets the counter (fresh window after
 * the cooldown).
 * @param {string} bucket
 * @param {{ max: number, windowMs: number, lockoutMs: number }} opts
 * @returns {void}
 */
export function recordRateLimitedAttempt(bucket, { max, windowMs, lockoutMs }) {
  const data = readJson(STORAGE_KEYS.rateLimit(bucket), { attempts: [], lockedUntil: 0 });
  const now  = Date.now();
  data.attempts = (data.attempts || []).filter(ts => now - ts < windowMs);
  data.attempts.push(now);
  if (data.attempts.length >= max) {
    data.lockedUntil = now + lockoutMs;
    data.attempts = [];
  }
  try { writeJson(STORAGE_KEYS.rateLimit(bucket), data); } catch { /* best-effort */ }
}

/**
 * Clear a rate-limit bucket (e.g. after a successful attempt).
 * @param {string} bucket
 * @returns {void}
 */
export function clearRateLimit(bucket) {
  try { localStorage.removeItem(STORAGE_KEYS.rateLimit(bucket)); } catch { /* best-effort */ }
}
