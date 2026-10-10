/**
 * card.js — Recipient page for NostCard
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
 *  - e2e:trusted:<pubkey>:<cardId> TTL: 30 days (stored as { ok: true, expires: <unix ms> })
 */

import { fragmentToKey, decryptVCard } from './crypto.js';
import { parseVCard, buildVCard } from './vcard.js';
import { naddrDecode, fetchCard, sameCardAddress, isValidRelayUrl, CARD_KIND } from './nostr.js';
import { initI18n, t, setLang, getCurrentLang } from './i18n.js';

/** Escape HTML special characters to prevent XSS in innerHTML strings */
function htmlEscape(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/** Full card URL including the #key — captured before any address-bar scrub. */
let cardFullUrl = null;

// The one storage key a public visit can still write: the language choice
// (setLang persists it). Captured before anything runs so a public session
// can restore the browser to its pre-visit state on exit.
const langBeforeLoad = (() => {
  try { return localStorage.getItem('e2e:lang'); } catch { return null; }
})();

/** Public sessions: undo the only writes this session may have made. */
function restorePublicTraces() {
  try {
    if (langBeforeLoad === null) localStorage.removeItem('e2e:lang');
    else if (localStorage.getItem('e2e:lang') !== langBeforeLoad) localStorage.setItem('e2e:lang', langBeforeLoad);
  } catch {}
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

async function init() {
  await initI18n();

  // Wire up language switcher
  document.querySelectorAll('.lang-btn').forEach(btn => {
    btn.classList.toggle('lang-btn--active', btn.dataset.lang === getCurrentLang());
    btn.addEventListener('click', () => setLang(btn.dataset.lang));
  });
  window.addEventListener('i18n:changed', () => {
    document.querySelectorAll('.lang-btn').forEach(b => {
      b.classList.toggle('lang-btn--active', b.dataset.lang === getCurrentLang());
    });
  });

  const params   = new URLSearchParams(location.search);
  const naddr    = params.get('naddr');
  const fragment = location.hash.slice(1); // strip leading '#'

  // Two-part sharing: the recipient opened part 1 (base link, no #key) —
  // ask them to paste part 2 instead of dead-ending with a generic error.
  if (naddr && !fragment) {
    return showKeyEntry(naddr);
  }

  if (!naddr || !fragment) {
    return showError(
      t('error.invalidLink.title'),
      t('error.invalidLink.missingParams')
    );
  }

  await openCard(naddr, fragment);
}

/**
 * Decode the card address, fetch and decrypt the card, show the trust gate.
 * Called either directly from init() or after the recipient pastes part 2
 * on the key-entry screen.
 */
async function openCard(naddr, fragment) {
  const params = new URLSearchParams(location.search);

  // Capture the full URL (incl. #key) before anything scrubs the address bar —
  // the trusted view offers it as a copy box so the link can be moved from a
  // browser into the installed app (Contacts → paste).
  cardFullUrl = location.href;

  // Decode naddr → relay hints, pubkey, card ID
  let decoded;
  try {
    decoded = naddrDecode(naddr);
  } catch (err) {
    return showError(t('error.invalidLink.title'), t('error.invalidLink.malformedNaddr'));
  }

  // A crafted naddr could point at the wrong event kind or carry unsafe relay
  // URLs — only card-kind addresses with wss:// (or ws:// in dev) hints are used.
  if (decoded.kind !== CARD_KIND) {
    return showError(t('error.invalidLink.title'), t('error.invalidLink.malformedNaddr'));
  }

  const { pubkey, identifier: cardId } = decoded;
  const relays = (decoded.relays || []).filter(isValidRelayUrl);

  if (relays.length === 0) {
    return showError(t('error.invalidLink.title'), t('error.invalidLink.noRelays'));
  }

  // Import AES key from fragment
  let key;
  try {
    key = await fragmentToKey(fragment);
  } catch {
    return showError(t('error.invalidKey.title'), t('error.invalidKey.detail'));
  }

  // Fetch encrypted blob from Nostr relays
  let event;
  try {
    event = await fetchCard(relays, pubkey, cardId);
  } catch (err) {
    return showError(t('error.network.title'), t('error.network.detail'), true);
  }

  if (!event) {
    return showError(t('error.notFound.title'), t('error.notFound.detail'), true);
  }

  // Decrypt
  let vcardText;
  try {
    vcardText = await decryptVCard(event.content, key);
  } catch {
    return showError(t('error.decrypt.title'), t('error.decrypt.detail'));
  }

  const fields = parseVCard(vcardText);

  // Relay-side timestamp (when the owner last published) — used as updatedAt
  // for saved links so the contacts list reflects the card's last real change.
  const relayTs = event.created_at ? new Date(event.created_at * 1000).toISOString() : null;

  // Trust is keyed by pubkey:cardId so a different owner reusing a card ID
  // cannot inherit a previously granted trust flag.
  const trustId = `${pubkey}:${cardId}`;

  // ?dl=1 — auto-download mode; only downloads without prompt on trusted devices
  if (params.get('dl') === '1') {
    const cleanParams = new URLSearchParams(location.search);
    cleanParams.delete('dl');
    const cleanUrl = `${location.origin}${location.pathname}?${cleanParams}${location.hash}`;
    if (getTrust(trustId)) {
      downloadVcf(vcardText, fields.fn);
      showDownloadConfirmation(fields.fn, trustId, cleanUrl, relayTs);
    } else {
      showDownloadGate(fields.fn, trustId, cleanUrl, vcardText, relayTs);
    }
    return;
  }

  // Always show the trust gate — owner preview is handled by the inline viewer
  // in app.js and never navigates to card.html, so no mode param is honoured here.
  showTrustGate(trustId, fields, vcardText, relayTs);
}

// ---------------------------------------------------------------------------
// Key entry — two-part sharing (recipient side)
// ---------------------------------------------------------------------------

/**
 * The base link (part 1) was opened without the #key. Prompt the recipient
 * to paste the key (part 2) they received in a separate message. The pasted
 * key is validated locally, then written into the fragment via
 * history.replaceState — it never travels to any server, and the assembled
 * link keeps working on refresh.
 */
function showKeyEntry(naddr) {
  document.getElementById('screen-loading').classList.add('hidden');

  const section = document.getElementById('screen-keyentry');
  const input   = document.getElementById('keyentry-input');
  const errEl   = document.getElementById('keyentry-error');
  const btn     = document.getElementById('btn-keyentry-open');

  section.classList.remove('hidden');
  input.focus();

  const submit = async () => {
    // Accept the key with or without a leading '#'
    const key = input.value.trim().replace(/^#/, '').trim();
    errEl.classList.add('hidden');

    if (!key) {
      errEl.textContent = t('keyentry.error.empty');
      errEl.classList.remove('hidden');
      return;
    }

    // Validate before touching the address bar — a wrong code stays in the
    // input; nothing is written anywhere until it decodes.
    try {
      await fragmentToKey(key);
    } catch {
      errEl.textContent = t('keyentry.error.invalid');
      errEl.classList.remove('hidden');
      return;
    }

    history.replaceState(null, '', `${location.pathname}${location.search}#${key}`);

    section.classList.add('hidden');
    document.getElementById('screen-loading').classList.remove('hidden');
    await openCard(naddr, key);
  };

  btn.addEventListener('click', submit);
  input.addEventListener('keydown', e => { if (e.key === 'Enter') submit(); });
}

// ---------------------------------------------------------------------------
// Trust gate
// ---------------------------------------------------------------------------

const TRUST_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days (30 * 24 * 60 * 60 * 1000)

function getTrust(trustId) {
  try {
    const raw = localStorage.getItem(`e2e:trusted:${trustId}`);
    if (!raw) return false;
    const data = JSON.parse(raw);
    if (!data || !data.ok || Date.now() > data.expires) {
      localStorage.removeItem(`e2e:trusted:${trustId}`);
      return false;
    }
    // Sliding TTL — each trusted visit extends the window from now
    localStorage.setItem(
      `e2e:trusted:${trustId}`,
      JSON.stringify({ ok: true, expires: Date.now() + TRUST_TTL_MS })
    );
    return true;
  } catch {
    return false;
  }
}

function setTrust(trustId) {
  try {
    localStorage.setItem(
      `e2e:trusted:${trustId}`,
      JSON.stringify({ ok: true, expires: Date.now() + TRUST_TTL_MS })
    );
  } catch { /* storage blocked */ }
}

function showTrustGate(trustId, fields, vcardText, relayTs) {
  if (getTrust(trustId)) {
    // Returning trusted visitor — skip the gate
    renderCard(fields, vcardText, true, false, relayTs);
    return;
  }

  document.getElementById('screen-loading').classList.add('hidden');
  document.getElementById('screen-trust').classList.remove('hidden');

  document.getElementById('btn-trusted').addEventListener('click', () => {
    setTrust(trustId);
    document.getElementById('screen-trust').classList.add('hidden');
    renderCard(fields, vcardText, true, false, relayTs);
  });

  document.getElementById('btn-public').addEventListener('click', () => {
    document.getElementById('screen-trust').classList.add('hidden');
    renderCard(fields, vcardText, false, false, relayTs);
  });
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

function renderCard(fields, vcardText, trusted, ownerPreview, relayTs) {
  document.title = t('page.title.card.loaded', { fn: fields.fn || t('cv.contact.fallback') });

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
  // ADR - address fields
  for (const adr of (fields.adr || [])) {
    const parts = [adr.street, adr.city, adr.region, adr.postcode, adr.country].filter(Boolean).join(', ');
    if (parts) {
      const label = adr.type && adr.type !== 'home' ? t('field.type.' + adr.type) : '';
      const displayText = label ? `${label}: ${parts}` : parts;
      container.appendChild(fieldRow('🏠', 'adr', displayText, null));
    }
  }

  // Download button — trusted and non-owner-preview only
  const downloadBtn = document.getElementById('btn-download');
  if (trusted) {
    downloadBtn.addEventListener('click', () => {
      downloadVcf(vcardText, fields.fn);
      if (!ownerPreview) setTimeout(() => triggerKill('download'), 3000);
    });
    const downloadHint = document.createElement('p');
    downloadHint.className = 'muted';
    downloadHint.style.cssText = 'font-size:0.8rem;margin:0.25rem 0 0;text-align:center';
    downloadHint.textContent = t('cv.download.hint');
    downloadBtn.insertAdjacentElement('afterend', downloadHint);
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
    const idx = links.findIndex(l => sameSharedCardUrl(l.url, currentUrl));
    const ts = relayTs || new Date().toISOString();
    if (idx >= 0) {
      links[idx] = { ...links[idx], url: currentUrl, label: fields.fn || links[idx].label, updatedAt: ts };
    } else {
      links.push({ url: currentUrl, label: fields.fn || 'Contact', savedAt: new Date().toISOString(), updatedAt: ts });
    }
    try { localStorage.setItem(SAVED_KEY, JSON.stringify(links)); } catch {}
    saveLinkBtn.textContent = t('cv.btn.save.link.done');
    saveLinkBtn.disabled    = true;
    const saveLinkHint = document.createElement('p');
    saveLinkHint.className = 'muted';
    saveLinkHint.style.cssText = 'font-size:0.8rem;margin:0.25rem 0 0;text-align:center';
    saveLinkHint.textContent = t('cv.saved.hint');
    saveLinkBtn.insertAdjacentElement('afterend', saveLinkHint);
  }

  // Copyable full link — trusted devices only. The #key in the address bar is
  // awkward to select on mobile; this box hands the link to the installed app
  // (Contacts → paste) or lets it be re-shared. Public mode keeps it hidden,
  // consistent with "nothing is saved on this device".
  if (trusted) {
    const box = document.getElementById('copy-link-box');
    if (box) {
      box.classList.remove('hidden');
      const fullUrl = cardFullUrl || location.href;
      document.getElementById('card-full-url').value = fullUrl;
      document.getElementById('btn-copy-full-url').addEventListener('click', async () => {
        const btn = document.getElementById('btn-copy-full-url');
        try { await navigator.clipboard.writeText(fullUrl); } catch { /* fallback: select */ }
        btn.textContent = t('btn.copied');
        setTimeout(() => { btn.textContent = t('btn.copy'); }, 2000);
      });
    }
  }

  // Public mode: banner + bookmark hint swapped for a "not saved here" warning
  if (!trusted) {
    document.getElementById('public-mode-banner').classList.remove('hidden');
    const hint = document.querySelector('.update-hint');
    if (hint) {
      // Hide the trusted-only bookmark instructions, keep the public warning
      hint.querySelectorAll('.update-hint-title, .update-hint-body:not(.public-warning)').forEach(el => {
        el.style.display = 'none';
      });
      const warning = hint.querySelector('.public-warning');
      if (warning) warning.classList.remove('hidden');
    }
    // Drop the whole query string and #key from the address bar and history
    // right away — the key reopens the card, and even the (public) card
    // address reveals that this visit happened. Nothing of the link remains.
    history.replaceState(null, '', location.pathname);
    // The tab can be closed without a kill (user just closes it) — undo any
    // language-switch write at that point too.
    window.addEventListener('pagehide', restorePublicTraces);
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
      countdownEl.textContent = t('cv.countdown', { m, ss: String(s).padStart(2, '0') });
    }, 1000);

    autoKillTimer = setTimeout(() => triggerKill('timeout'), AUTO_KILL_MS);
  }

  // Idempotent kill function
  function triggerKill(reason) {
    document.removeEventListener('visibilitychange', onVisibility);
    if (autoKillTimer)    clearTimeout(autoKillTimer);
    if (countdownInterval) clearInterval(countdownInterval);

    vcardText = ''; // zero plaintext from closure

    history.replaceState(null, '', location.pathname);
    if (!trusted) restorePublicTraces();

    const section = document.getElementById('screen-card');
    if (!section) return;
    const messages = {
      manual:       t('cv.kill.manual'),
      download:     t('cv.kill.download'),
      'tab-hidden': t('cv.kill.tab'),
      timeout:      t('cv.kill.timeout'),
    };
    // Use textContent-safe construction — no user data in these messages
    section.innerHTML = `
      <div class="card-panel centered">
        <div style="font-size:3rem">🔒</div>
        <h2>${htmlEscape(messages[reason] || t('cv.kill.manual'))}</h2>
        <p class="muted">
          ${htmlEscape(t('cv.kill.detail'))}<br>
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

// Shown when ?dl=1 is opened on a device not yet trusted — requires an
// explicit click before the .vcf is written to disk.
function showDownloadGate(fn, trustId, cleanUrl, vcardText, relayTs) {
  document.getElementById('screen-loading').classList.add('hidden');
  // Non-trusted device: drop the whole link from the address bar/history
  // immediately. cleanUrl was already captured, so saving after an explicit
  // "Yes" still works.
  history.replaceState(null, '', location.pathname);

  const panel = document.createElement('div');
  panel.className = 'card-panel centered';

  const icon = document.createElement('div');
  icon.style.fontSize = '3rem';
  icon.textContent = '⬇️';

  const heading = document.createElement('h2');
  heading.textContent = t('dl.confirm.heading');

  const p = document.createElement('p');
  p.className = 'muted';
  p.textContent = t('dl.confirm.body', { fn: fn || t('cv.contact.fallback') });

  const btn = document.createElement('button');
  btn.className = 'btn btn-primary btn-lg';
  btn.textContent = t('dl.confirm.btn');
  btn.addEventListener('click', () => {
    downloadVcf(vcardText, fn);
    showDownloadConfirmation(fn, trustId, cleanUrl, relayTs);
  });

  panel.appendChild(icon);
  panel.appendChild(heading);
  panel.appendChild(p);
  panel.appendChild(btn);

  const section = document.getElementById('screen-card');
  section.innerHTML = '';
  section.appendChild(panel);
  section.classList.remove('hidden');
}

function showDownloadConfirmation(fn, trustId, cleanUrl, relayTs) {
  document.getElementById('screen-loading').classList.add('hidden');

  const panel = document.createElement('div');
  panel.className = 'card-panel centered';

  const icon = document.createElement('div');
  icon.style.fontSize = '3rem';
  icon.textContent = '📱';

  const heading = document.createElement('h2');
  heading.textContent = t('dl.heading');

  const p = document.createElement('p');
  p.className = 'muted';
  p.textContent = t('dl.body', { fn: fn || t('cv.contact.fallback') });

  panel.appendChild(icon);
  panel.appendChild(heading);
  panel.appendChild(p);

  const saveLink = (label) => {
    try {
      const SAVED_KEY = 'e2e:saved-links';
      let links = [];
      try { links = JSON.parse(localStorage.getItem(SAVED_KEY) || '[]'); } catch {}
      const idx = links.findIndex(l => sameSharedCardUrl(l.url, cleanUrl));
      const ts = relayTs || new Date().toISOString();
      if (idx >= 0) {
        links[idx] = { ...links[idx], url: cleanUrl, label: label || links[idx].label, updatedAt: ts };
      } else {
        links.push({ url: cleanUrl, label: label || 'Contact', savedAt: new Date().toISOString(), updatedAt: ts });
      }
      localStorage.setItem(SAVED_KEY, JSON.stringify(links));
    } catch { /* storage blocked — non-fatal */ }
  };

  // Trust / save prompt — only when device is not yet trusted for this card
  if (!getTrust(trustId)) {
    const trustHeading = document.createElement('p');
    trustHeading.style.cssText = 'margin-top:1.5rem;font-weight:600';
    trustHeading.textContent = t('dl.save.prompt');

    const choices = document.createElement('div');
    choices.className = 'trust-choices';
    choices.style.marginTop = '0.75rem';

    const yesBtn = document.createElement('button');
    yesBtn.className = 'btn btn-trust-yes';
    yesBtn.innerHTML = `<span class="trust-choice-icon">✅</span><span class="trust-choice-label">${htmlEscape(t('dl.yes.label'))}</span><span class="trust-choice-hint">${htmlEscape(t('dl.yes.hint'))}</span>`;

    const noBtn = document.createElement('button');
    noBtn.className = 'btn btn-trust-no';
    noBtn.innerHTML = `<span class="trust-choice-icon">🏛️</span><span class="trust-choice-label">${htmlEscape(t('dl.no.label'))}</span><span class="trust-choice-hint">${htmlEscape(t('dl.no.hint'))}</span>`;

    const replaceChoices = (msg, hint) => {
      choices.innerHTML = '';
      const conf = document.createElement('p');
      conf.className = 'muted';
      conf.textContent = msg;
      choices.appendChild(conf);
      if (hint) {
        const hintEl = document.createElement('p');
        hintEl.className = 'muted';
        hintEl.style.cssText = 'font-size:0.8rem;margin:0.25rem 0 0;text-align:center';
        hintEl.textContent = hint;
        choices.appendChild(hintEl);
      }
    };

    yesBtn.addEventListener('click', () => {
      setTrust(trustId);
      saveLink(fn);
      replaceChoices(t('dl.saved'), t('dl.saved.hint'));
    });

    noBtn.addEventListener('click', () => {
      replaceChoices(t('dl.no.saved'));
    });

    choices.appendChild(yesBtn);
    choices.appendChild(noBtn);
    panel.appendChild(trustHeading);
    panel.appendChild(choices);
  } else {
    // Already trusted — save silently and confirm
    saveLink(fn);
    const saved = document.createElement('p');
    saved.className = 'muted';
    saved.style.marginTop = '1rem';
    saved.textContent = t('dl.saved');
    panel.appendChild(saved);
    const savedHint = document.createElement('p');
    savedHint.className = 'muted';
    savedHint.style.cssText = 'font-size:0.8rem;margin:0.25rem 0 0;text-align:center';
    savedHint.textContent = t('dl.saved.hint');
    panel.appendChild(savedHint);
  }

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
  // Strip the SOURCE line — the canonical URL lacks the #key fragment and
  // cannot be opened by a contacts app without it. Keeping it only confuses.
  const stripped = vcardText.replace(/^SOURCE:[^\r\n]*\r?\n?/m, '');
  const blob = new Blob([stripped], { type: 'text/vcard;charset=utf-8' });
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

function showError(title, detail, retryable = false) {
  document.getElementById('screen-loading').classList.add('hidden');
  document.getElementById('error-title').textContent  = title;
  document.getElementById('error-detail').textContent = detail;

  // "Not found" and network errors are often transient relay flakiness —
  // offer a reload rather than making the recipient believe the card is gone.
  if (retryable) {
    const btn = document.createElement('button');
    btn.className   = 'btn btn-primary';
    btn.style.marginTop = '1rem';
    btn.textContent  = t('error.retry.btn');
    btn.addEventListener('click', () => location.reload());
    document.getElementById('error-detail').insertAdjacentElement('afterend', btn);
  }

  document.getElementById('screen-error').classList.remove('hidden');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Extract the naddr= query param from a share URL, or null if missing/malformed */
function extractNaddrFromUrl(url) {
  try { return new URL(url).searchParams.get('naddr'); } catch { return null; }
}

/** Compares two share URLs by card identity (naddr pubkey+d-tag), not exact string */
function sameSharedCardUrl(urlA, urlB) {
  const a = extractNaddrFromUrl(urlA), b = extractNaddrFromUrl(urlB);
  if (!a || !b) return urlA === urlB;
  return sameCardAddress(a, b);
}

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
