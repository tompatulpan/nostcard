/**
 * card.js — Recipient page for nostr-vcard
 *
 * Flow:
 *  1. Parse ?naddr= from query string; parse #AES-key from fragment
 *  2. naddrDecode(naddr) → { pubkey, identifier, relays }
 *  3. fragmentToKey(hash) → CryptoKey (non-extractable)
 *  4. fetchCard(relays, pubkey, identifier) → encrypted blob from Nostr relay
 *  5. decryptVCard(blob, key) → plain vCard text
 *  6. Trust gate → render card
 *
 * Security:
 *  - The AES key lives only in location.hash — never sent to any server
 *  - All user data rendered via textContent (never innerHTML with user data)
 *  - Anchor hrefs validated to safe schemes only
 *  - e2e:trusted:<id> TTL: 30 days (stored as { ok: true, expires: <unix ms> })
 */

import { fragmentToKey, decryptVCard } from './crypto.js';
import { parseVCard, buildVCard } from './vcard.js';
import { naddrDecode, fetchCard } from './nostr.js';

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

async function init() {
  const params   = new URLSearchParams(location.search);
  const naddr    = params.get('naddr');
  const fragment = location.hash.slice(1); // strip leading '#'

  if (!naddr || !fragment) {
    return showError(
      'Invalid link',
      'This link is missing required parameters. Make sure you copied the full URL including the #fragment.'
    );
  }

  // Decode naddr → relay hints, pubkey, card ID
  let decoded;
  try {
    decoded = naddrDecode(naddr);
  } catch (err) {
    return showError('Invalid link', 'This link contains a malformed card address. It may have been truncated.');
  }

  const { pubkey, identifier: cardId, relays } = decoded;

  if (!relays || relays.length === 0) {
    return showError('Invalid link', 'The card address contains no relay information. Cannot fetch the card.');
  }

  // Import AES key from fragment
  let key;
  try {
    key = await fragmentToKey(fragment);
  } catch {
    return showError('Invalid key', 'The decryption key in this link is not valid.');
  }

  // Fetch encrypted blob from Nostr relays
  let event;
  try {
    event = await fetchCard(relays, pubkey, cardId);
  } catch (err) {
    return showError('Network error', 'Could not connect to the Nostr relays. Check your connection and try again.');
  }

  if (!event) {
    return showError('Card not found', 'This card could not be found on any of the listed relays. It may have been deleted or not yet published.');
  }

  // Decrypt
  let vcardText;
  try {
    vcardText = await decryptVCard(event.content, key);
  } catch {
    return showError('Decryption failed', 'Could not decrypt this card. The link may be corrupted.');
  }

  const fields = parseVCard(vcardText);

  // ?dl=1 — auto-download mode: skip trust gate, immediately trigger .vcf download
  if (params.get('dl') === '1') {
    downloadVcf(vcardText, fields.fn);

    // Save the clean URL (without ?dl=1) to saved links so the card is accessible later
    try {
      const cleanParams = new URLSearchParams(location.search);
      cleanParams.delete('dl');
      const cleanUrl = `${location.origin}${location.pathname}?${cleanParams}${location.hash}`;
      const SAVED_KEY = 'e2e:saved-links';
      let links = [];
      try { links = JSON.parse(localStorage.getItem(SAVED_KEY) || '[]'); } catch {}
      if (!links.some(l => l.url === cleanUrl)) {
        links.push({ url: cleanUrl, label: fields.fn || 'Contact', savedAt: new Date().toISOString() });
        localStorage.setItem(SAVED_KEY, JSON.stringify(links));
      }
    } catch { /* storage blocked — non-fatal */ }

    showDownloadConfirmation(fields.fn);
    return;
  }

  // Always show the trust gate — owner preview is handled by the inline viewer
  // in app.js and never navigates to card.html, so no mode param is honoured here.
  showTrustGate(cardId, fields, vcardText);
}

// ---------------------------------------------------------------------------
// Trust gate
// ---------------------------------------------------------------------------

const TRUST_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function getTrust(cardId) {
  try {
    const raw = localStorage.getItem(`e2e:trusted:${cardId}`);
    if (!raw) return false;
    const data = JSON.parse(raw);
    if (!data || !data.ok || Date.now() > data.expires) {
      localStorage.removeItem(`e2e:trusted:${cardId}`);
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

function setTrust(cardId) {
  try {
    localStorage.setItem(
      `e2e:trusted:${cardId}`,
      JSON.stringify({ ok: true, expires: Date.now() + TRUST_TTL_MS })
    );
  } catch { /* storage blocked */ }
}

function showTrustGate(cardId, fields, vcardText) {
  if (getTrust(cardId)) {
    // Returning trusted visitor — skip the gate
    renderCard(fields, vcardText, true, false);
    return;
  }

  document.getElementById('screen-loading').classList.add('hidden');
  document.getElementById('screen-trust').classList.remove('hidden');

  document.getElementById('btn-trusted').addEventListener('click', () => {
    setTrust(cardId);
    document.getElementById('screen-trust').classList.add('hidden');
    renderCard(fields, vcardText, true, false);
  });

  document.getElementById('btn-public').addEventListener('click', () => {
    document.getElementById('screen-trust').classList.add('hidden');
    renderCard(fields, vcardText, false, false);
  });
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

function renderCard(fields, vcardText, trusted, ownerPreview) {
  document.title = (fields.fn || 'Contact') + ' — Encrypted Card';

  // Avatar initials
  document.getElementById('contact-avatar').textContent = makeInitials(fields.fn || '');
  document.getElementById('contact-fn').textContent     = fields.fn || '';

  // Subtitle: title + org
  const firstTitle = Array.isArray(fields.title) ? fields.title[0] : fields.title;
  const firstOrg   = Array.isArray(fields.org)   ? fields.org[0]   : fields.org;
  const subtitle   = [firstTitle, firstOrg].filter(Boolean).join(' · ');
  const subtitleEl = document.getElementById('contact-title-org');
  if (subtitleEl) {
    subtitleEl.textContent   = subtitle;
    subtitleEl.style.display = subtitle ? '' : 'none';
  }

  // Fields
  const container = document.getElementById('contact-fields');

  const nameParts = [fields.firstName, fields.lastName].filter(Boolean).join(' ');
  if (nameParts && nameParts !== fields.fn) {
    container.appendChild(fieldRow('👤', 'name', nameParts, null));
  }
  for (const tel of (fields.tel || [])) {
    const val = typeof tel === 'string' ? tel : tel.value;
    if (val && val.trim()) container.appendChild(fieldRow('📞', 'tel', val.trim(), `tel:${val.trim()}`));
  }
  for (const email of (fields.email || [])) {
    const val = typeof email === 'string' ? email : email.value;
    if (val && val.trim()) container.appendChild(fieldRow('✉️', 'email', val.trim(), `mailto:${val.trim()}`));
  }
  for (const urlItem of (Array.isArray(fields.url) ? fields.url : (fields.url ? [{ value: fields.url }] : []))) {
    const val = typeof urlItem === 'string' ? urlItem : urlItem.value;
    if (val && val.trim()) container.appendChild(fieldRow('🔗', 'website', val.trim(), val.trim()));
  }
  for (const noteItem of (Array.isArray(fields.note) ? fields.note : (fields.note ? [fields.note] : []))) {
    if (noteItem && noteItem.trim()) container.appendChild(fieldRow('📝', 'note', noteItem.trim(), null));
  }

  // Download button — trusted and non-owner-preview only
  const downloadBtn = document.getElementById('btn-download');
  if (trusted) {
    downloadBtn.addEventListener('click', () => {
      downloadVcf(vcardText, fields.fn);
      if (!ownerPreview) setTimeout(() => triggerKill('download'), 3000);
    });
  } else {
    downloadBtn.style.display = 'none';
  }

  // Done button — public mode only
  const doneBtn = document.getElementById('btn-done');
  if (!trusted && !ownerPreview) {
    doneBtn.classList.remove('hidden');
    doneBtn.addEventListener('click', () => triggerKill('manual'));
    doneBtn.classList.add('btn-done-public');
    doneBtn.classList.remove('btn-secondary');
  }

  // Save link — trusted devices only; auto-save immediately; show as confirmed
  const saveLinkBtn = document.getElementById('btn-save-link');
  if (trusted && !ownerPreview) {
    saveLinkBtn.classList.remove('hidden');
    const SAVED_KEY = 'e2e:saved-links';
    const currentUrl = location.href; // includes #key fragment
    let links = [];
    try { links = JSON.parse(localStorage.getItem(SAVED_KEY) || '[]'); } catch {}
    const alreadySaved = links.some(l => l.url === currentUrl);
    if (!alreadySaved) {
      links.push({ url: currentUrl, label: fields.fn || 'Contact', savedAt: new Date().toISOString() });
      try { localStorage.setItem(SAVED_KEY, JSON.stringify(links)); } catch {}
    }
    saveLinkBtn.textContent = '✓ Link saved';
    saveLinkBtn.disabled    = true;
  }

  // Public mode: banner + hide bookmark hint
  if (!trusted) {
    document.getElementById('public-mode-banner').classList.remove('hidden');
    const hint = document.querySelector('.update-hint');
    if (hint) hint.style.display = 'none';
  }

  // Auto-kill: tab hidden — public mode only; disabled in owner-preview
  const onVisibility = () => {
    if (document.visibilityState === 'hidden') triggerKill('tab-hidden');
  };
  if (!trusted && !ownerPreview) {
    document.addEventListener('visibilitychange', onVisibility);
  }

  // Auto-kill timeout: 5 min for public, skip for trusted/owner-preview
  let autoKillTimer = null;
  let countdownInterval = null;
  if (!trusted && !ownerPreview) {
    const AUTO_KILL_MS = 5 * 60 * 1000;
    const killAt = Date.now() + AUTO_KILL_MS;

    const countdownEl = document.createElement('p');
    countdownEl.className = 'auto-clear-countdown muted';
    document.querySelector('.card-actions').appendChild(countdownEl);

    countdownInterval = setInterval(() => {
      const remaining = Math.max(0, killAt - Date.now());
      const m = Math.floor(remaining / 60000);
      const s = Math.floor((remaining % 60000) / 1000);
      countdownEl.textContent = `⏱ Auto-clears in ${m}:${String(s).padStart(2, '0')}`;
    }, 1000);

    autoKillTimer = setTimeout(() => triggerKill('timeout'), AUTO_KILL_MS);
  }

  // Idempotent kill function
  function triggerKill(reason) {
    document.removeEventListener('visibilitychange', onVisibility);
    if (autoKillTimer)    clearTimeout(autoKillTimer);
    if (countdownInterval) clearInterval(countdownInterval);

    vcardText = ''; // zero plaintext from closure

    history.replaceState(null, '', location.pathname + location.search);

    const section = document.getElementById('screen-card');
    if (!section) return;
    const messages = {
      manual:       'Session cleared.',
      download:     'Contact saved — session cleared.',
      'tab-hidden': 'Session auto-cleared when you switched away.',
      timeout:      'Session timed out and was auto-cleared.',
    };
    // Use textContent-safe construction — no user data in these messages
    section.innerHTML = `
      <div class="card-panel centered">
        <div style="font-size:3rem">🔒</div>
        <h2>${messages[reason] || 'Session cleared.'}</h2>
        <p class="muted">
          The contact details and decryption key have been removed from this browser session.<br>
          Safe to close this tab.
        </p>
      </div>
    `;
  }

  // vCard QR code
  if (typeof window.qrcode !== 'undefined') {
    try {
      const qr = window.qrcode(0, 'L');
      qr.addData(vcardText);
      qr.make();
      const qrContainer = document.getElementById('vcard-qr-container');
      if (qrContainer) {
        qrContainer.innerHTML = qr.createSvgTag({ scalable: true, cellSize: 4, margin: 4 });
      }
    } catch {
      // silently skip if vCard is too large for QR
    }
  }

  // Show card
  document.getElementById('screen-loading').classList.add('hidden');
  document.getElementById('screen-card').classList.remove('hidden');
}

// ---------------------------------------------------------------------------
// Field row builder
// ---------------------------------------------------------------------------

function fieldRow(icon, type, text, href) {
  const row = document.createElement('div');
  row.className = `field-row contact-field contact-field--${type}`;

  const labelEl = document.createElement('span');
  labelEl.className   = 'field-icon';
  labelEl.textContent = icon;

  const valueEl = document.createElement('span');
  valueEl.className = 'field-value';

  if (href) {
    // Allowlist safe schemes — reject javascript:, data:, vbscript:, etc.
    const safeHref = /^(https?:|tel:|mailto:)/i.test(href) ? href : null;
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
  } else {
    valueEl.textContent = text;
  }

  row.appendChild(labelEl);
  row.appendChild(valueEl);
  return row;
}

// ---------------------------------------------------------------------------
// Auto-download confirmation screen (?dl=1 mode)
// ---------------------------------------------------------------------------

function showDownloadConfirmation(fn) {
  document.getElementById('screen-loading').classList.add('hidden');

  const panel = document.createElement('div');
  panel.className = 'card-panel centered';

  const icon = document.createElement('div');
  icon.style.fontSize = '3rem';
  icon.textContent = '📱';

  const heading = document.createElement('h2');
  heading.textContent = 'Contact download started';

  const p = document.createElement('p');
  p.className = 'muted';
  p.textContent = `Open the downloaded .vcf file to add ${fn || 'the contact'} to your contacts app.`;

  panel.appendChild(icon);
  panel.appendChild(heading);
  panel.appendChild(p);

  const section = document.getElementById('screen-card');
  section.innerHTML = '';
  section.appendChild(panel);
  section.classList.remove('hidden');
}

// ---------------------------------------------------------------------------
// .vcf download
// ---------------------------------------------------------------------------

function downloadVcf(vcardText, fn) {
  const filename = (fn || 'contact').replace(/[^a-zA-Z0-9_-]/g, '_') + '.vcf';
  const blob = new Blob([vcardText], { type: 'text/vcard;charset=utf-8' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Error screen
// ---------------------------------------------------------------------------

function showError(title, detail) {
  document.getElementById('screen-loading').classList.add('hidden');
  document.getElementById('error-title').textContent  = title;
  document.getElementById('error-detail').textContent = detail;
  document.getElementById('screen-error').classList.remove('hidden');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeInitials(name) {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map(w => w[0].toUpperCase())
    .join('');
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

init();
