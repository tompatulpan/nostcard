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
    .replace(/"/g, '&quot;');
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
          <strong>Card not found on relay.</strong>
          <p>It may have already been deleted, or the relays are unreachable right now.</p>
        </div>
      </div>`;
    return null;
  }

  const date      = new Date(event.created_at * 1000).toLocaleString();
  const limit     = 100;
  const truncated = htmlEscape(event.content.slice(0, limit));
  const clipped   = event.content.length > limit;

  relayResult.innerHTML = `
    <div class="proof-relay-meta">Published: ${htmlEscape(date)}</div>
    <div class="proof-blob-label">Raw content stored on relay:</div>
    <div class="proof-blob-box">
      <code>${truncated}${clipped ? '<span class="proof-ellipsis"> … (truncated)</span>' : ''}</code>
    </div>
    <p class="proof-caption">
      This is <em>all</em> the relay ever stores.
      It cannot read your contact information — it only sees this unreadable blob.
    </p>`;

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
          <strong>Decryption failed.</strong>
          <p>The key in the URL does not match this card.
             Without the correct key the data is completely unreadable.</p>
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
    rows = '<p class="proof-caption">Card has no fields yet — save some contact details first.</p>';
  }

  decryptResult.innerHTML = `
    <div class="proof-fields">${rows}</div>
    <p class="proof-caption">
      Only someone with the complete share link (including the part after <code>#</code>)
      can see this.
    </p>`;
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
    deletionResult.innerHTML = `
      <div class="proof-status-box proof-status-warn">
        <span class="proof-status-icon">📡</span>
        <div>
          <strong>Card still found on relay.</strong>
          <p>Delete the card from <a href="index.html">My Cards</a>,
             then click "Check relay now" again.</p>
        </div>
      </div>`;
  } else {
    deletionResult.innerHTML = `
      <div class="proof-status-box proof-status-ok">
        <span class="proof-status-icon">✅</span>
        <div>
          <strong>Card removed from the network.</strong>
          <p>The relay returned nothing. Your contact data is no longer
             accessible via this link.</p>
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
    setError('Please paste a share URL first.');
    return;
  }

  let shareUrl;
  try {
    shareUrl = new URL(rawUrl);
  } catch {
    setError('Invalid URL. Please paste the full share link (starting with https://).');
    return;
  }

  // Validate scheme to prevent javascript: or data: URLs
  if (shareUrl.protocol !== 'https:' && shareUrl.protocol !== 'http:') {
    setError('Only https:// and http:// URLs are accepted.');
    return;
  }

  const naddr    = shareUrl.searchParams.get('naddr');
  const fragment = shareUrl.hash.slice(1); // strip leading '#'

  if (!naddr) {
    setError('URL is missing the naddr= parameter. Make sure you copied the complete share link.');
    return;
  }

  if (!fragment) {
    setError(
      'URL is missing the encryption key (the part after #). ' +
      'Copy the full share link — including everything after the # symbol.'
    );
    return;
  }

  let decoded;
  try {
    decoded = naddrDecode(naddr);
  } catch {
    setError('Could not decode the card address (naddr). The share link may be corrupted.');
    return;
  }

  let key;
  try {
    key = await fragmentToKey(fragment);
  } catch {
    setError('Could not decode the encryption key. The part after # may be corrupted.');
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
    const param = new URL(location.href).searchParams.get('url');
    if (param) {
      urlInput.value = decodeURIComponent(param);
      btnRun.click();
    }
  } catch {
    // ignore — autofill is best-effort
  }
}());
