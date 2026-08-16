/**
 * proof.js — Privacy proof-of-concept tool
 *
 * Demonstrates to non-technical users that:
 *   1. The Nostr relay stores only an unreadable encrypted blob
 *   2. Only someone with the #key in the share link can decrypt it
 *   3. After deletion, the relay returns no data for this card
 *
 * Security:
 *   - All user-supplied strings are HTML-escaped before DOM insertion.
 *   - The AES key is read exclusively from location.hash (never from query params).
 *   - nsec is never requested, logged, or handled here.
 */

import { naddrDecode, fetchCard } from './nostr.js';
import { fragmentToKey, decryptVCard } from './crypto.js';
import { parseVCard } from './vcard.js';
import { initI18n, t, setLang, getCurrentLang } from './i18n.js';

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

async function boot() {
  await initI18n();
  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.classList.toggle('lang-btn--active', btn.dataset.lang === getCurrentLang());
    btn.addEventListener('click', () => setLang(btn.dataset.lang));
  });
  window.addEventListener('i18n:changed', () => {
    document.querySelectorAll('.lang-btn').forEach(b => {
      b.classList.toggle('lang-btn--active', b.dataset.lang === getCurrentLang());
    });
  });
}

boot();

// ---------------------------------------------------------------------------
// DOM refs
// ---------------------------------------------------------------------------

const urlInput       = document.getElementById('proof-url-input');
const btnRun         = document.getElementById('btn-run-proof');
const proofResults   = document.getElementById('proof-results');
const relayResult    = document.getElementById('relay-result');
const decryptResult  = document.getElementById('decrypt-result');
const stepDeletion   = document.getElementById('step-deletion');
const btnCheckDel    = document.getElementById('btn-check-deleted');
const deletionResult = document.getElementById('deletion-result');
const errorBanner    = document.getElementById('proof-error');

// Parsed address — populated after a successful run, used for Step 3
let parsedRelays = null;
let parsedPubkey = null;
let parsedCardId = null;

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function htmlEscape(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

function spinnerHtml() {
  return '<div class="spinner" style="margin:24px auto"></div>';
}

function setError(msg) {
  errorBanner.textContent = msg;
  errorBanner.classList.remove('hidden');
}

function clearError() {
  errorBanner.textContent = '';
  errorBanner.classList.add('hidden');
}

// ---------------------------------------------------------------------------
// Step 1 — Fetch raw relay event; display the encrypted blob
// ---------------------------------------------------------------------------

async function runStep1(relays, pubkey, cardId) {
  relayResult.innerHTML = spinnerHtml();

  const event = await fetchCard(relays, pubkey, cardId);

  if (!event) {
    relayResult.innerHTML = `
      <div class="proof-status-box proof-status-warn">
        <span class="proof-status-icon">⚠️</span>
        <div>
          <strong>${t('proof.step1.notFound.title')}</strong>
          <p>${t('proof.step1.notFound.detail')}</p>
        </div>
      </div>`;
    return null;
  }

  const date      = new Date(event.created_at * 1000).toLocaleString();
  const limit     = 100;
  const truncated = htmlEscape(event.content.slice(0, limit));
  const clipped   = event.content.length > limit;

  // Extract plaintext metadata tags the relay can read
  const titleTag  = (event.tags || []).find(t => t[0] === 'title');
  const dTag      = (event.tags || []).find(t => t[0] === 'd');
  const cardName  = titleTag ? titleTag[1] : null;
  const tagCardId = dTag     ? dTag[1]     : null;

  const metaRows = [
    cardName ? `<div class="proof-field-row" style="background:#fef9c3;border-color:#fde68a">
      <span class="proof-field-icon">🏷️</span>
      <span><strong>${t('proof.step1.meta.name')}</strong> ${htmlEscape(cardName)} <em style="font-size:11px;color:#92400e">${t('proof.step1.meta.plaintext')}</em></span>
    </div>` : '',
    tagCardId ? `<div class="proof-field-row" style="background:#fef9c3;border-color:#fde68a">
      <span class="proof-field-icon">🔑</span>
      <span><strong>${t('proof.step1.meta.id')}</strong> <code>${htmlEscape(tagCardId)}</code> <em style="font-size:11px;color:#92400e">${t('proof.step1.meta.plaintext')}</em></span>
    </div>` : '',
    `<div class="proof-field-row" style="background:#fef9c3;border-color:#fde68a">
      <span class="proof-field-icon">🕐</span>
      <span><strong>${t('proof.step1.meta.updated')}</strong> ${htmlEscape(date)} <em style="font-size:11px;color:#92400e">${t('proof.step1.meta.plaintext')}</em></span>
    </div>`,
  ].join('');

  relayResult.innerHTML = `
    <div class="proof-blob-label" style="margin-bottom:8px">${t('proof.step1.label.plaintext')}</div>
    <div class="proof-fields" style="margin-bottom:16px">${metaRows}</div>
    <div class="proof-blob-label">${t('proof.step1.label.blob')}</div>
    <div class="proof-blob-box">
      <code>${truncated}${clipped ? '<span class="proof-ellipsis"> … (truncated)</span>' : ''}</code>
    </div>
    <p class="proof-caption">${t('proof.step1.caption')}</p>`;

  return event;
}

// ---------------------------------------------------------------------------
// Step 2 — Decrypt with the key from the URL fragment; display fields
// ---------------------------------------------------------------------------

async function runStep2(event, key) {
  decryptResult.innerHTML = spinnerHtml();

  let vcardText;
  try {
    vcardText = await decryptVCard(event.content, key);
  } catch {
    decryptResult.innerHTML = `
      <div class="proof-status-box proof-status-error">
        <span class="proof-status-icon">❌</span>
        <div>
          <strong>${t('proof.step2.decrypt.failed.title')}</strong>
          <p>${t('proof.step2.decrypt.failed.detail')}</p>
        </div>
      </div>`;
    return;
  }

  const fields = parseVCard(vcardText);
  let rows = '';

  if (fields.fn) {
    rows += fieldRow('👤', fields.fn);
  }
  for (const t of (fields.tel   || [])) { rows += fieldRow('📞', t.value); }
  for (const e of (fields.email || [])) { rows += fieldRow('✉️', e.value); }
  for (const o of (fields.org   || [])) { rows += fieldRow('🏢', o); }
  for (const ti of (fields.title|| [])) { rows += fieldRow('💼', ti); }
  for (const u of (fields.url   || [])) { rows += fieldRow('🔗', u.value); }
  for (const n of (fields.note  || [])) { rows += fieldRow('📝', n); }

  if (!rows) {
    rows = `<p class="proof-caption">${t('proof.step2.no.fields')}</p>`;
  }

  decryptResult.innerHTML = `
    <div class="proof-fields">${rows}</div>
    <p class="proof-caption">${t('proof.step2.caption')}</p>`;
}

function fieldRow(icon, text) {
  return `<div class="proof-field-row">
    <span class="proof-field-icon">${icon}</span>
    <span>${htmlEscape(text)}</span>
  </div>`;
}

// ---------------------------------------------------------------------------
// Step 3 — Re-fetch to verify deletion
// ---------------------------------------------------------------------------

async function runStep3() {
  deletionResult.innerHTML = spinnerHtml();
  btnCheckDel.disabled = true;

  const event = await fetchCard(parsedRelays, parsedPubkey, parsedCardId);

  if (event) {
    const myCardsLink = `<a href="index.html">${htmlEscape(t('proof.step3.still.link'))}</a>`;
    deletionResult.innerHTML = `
      <div class="proof-status-box proof-status-warn">
        <span class="proof-status-icon">📡</span>
        <div>
          <strong>${t('proof.step3.still.title')}</strong>
          <p>${t('proof.step3.still.detail', { link: myCardsLink })}</p>
        </div>
      </div>`;
  } else {
    deletionResult.innerHTML = `
      <div class="proof-status-box proof-status-ok">
        <span class="proof-status-icon">✅</span>
        <div>
          <strong>${t('proof.step3.removed.title')}</strong>
          <p>${t('proof.step3.removed.detail')}</p>
        </div>
      </div>`;
  }

  btnCheckDel.disabled = false;
}

// ---------------------------------------------------------------------------
// Main — wire up the Run button
// ---------------------------------------------------------------------------

btnRun.addEventListener('click', async () => {
  clearError();
  proofResults.classList.add('hidden');
  stepDeletion.classList.add('hidden');
  deletionResult.innerHTML = '';

  const rawUrl = urlInput.value.trim();

  if (!rawUrl) {
    setError(t('proof.error.empty'));
    return;
  }

  let shareUrl;
  try {
    shareUrl = new URL(rawUrl);
  } catch {
    setError(t('proof.error.invalidUrl'));
    return;
  }

  // Validate scheme to prevent javascript: or data: URLs
  if (shareUrl.protocol !== 'https:' && shareUrl.protocol !== 'http:') {
    setError(t('proof.error.schemeOnly'));
    return;
  }

  const naddr    = shareUrl.searchParams.get('naddr');
  const fragment = shareUrl.hash.slice(1); // strip leading '#'

  if (!naddr) {
    setError(t('proof.error.missingNaddr'));
    return;
  }

  if (!fragment) {
    setError(t('proof.error.missingKey'));
    return;
  }

  let decoded;
  try {
    decoded = naddrDecode(naddr);
  } catch {
    setError(t('proof.error.badNaddr'));
    return;
  }

  let key;
  try {
    key = await fragmentToKey(fragment);
  } catch {
    setError(t('proof.error.badKey'));
    return;
  }

  // Stash for Step 3 re-fetch
  parsedRelays = decoded.relays;
  parsedPubkey = decoded.pubkey;
  parsedCardId = decoded.identifier;

  btnRun.disabled = true;
  proofResults.classList.remove('hidden');

  const event = await runStep1(parsedRelays, parsedPubkey, parsedCardId);

  if (event) {
    await runStep2(event, key);
  } else {
    decryptResult.innerHTML =
      '<p class="proof-caption muted">Nothing to decrypt — card was not found on any relay.</p>';
  }

  stepDeletion.classList.remove('hidden');
  btnRun.disabled = false;
});

btnCheckDel.addEventListener('click', runStep3);

// ---------------------------------------------------------------------------
// Auto-fill — if opened via the "Verify privacy" button the share URL is
// passed as ?url=<encoded>  so the user can run the demo in one click
// ---------------------------------------------------------------------------

(function autofill() {
  try {
    // searchParams.get() already decodes — a second decode would corrupt '%' sequences
    const param = new URL(location.href).searchParams.get('url');
    if (param) {
      urlInput.value = param;
      btnRun.click();
    }
  } catch {
    // ignore — autofill is best-effort
  }
}());
