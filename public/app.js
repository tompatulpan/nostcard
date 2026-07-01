/**
 * app.js — Owner app for nostr-vcard
 *
 * State stored in localStorage:
 *   e2e:cards          JSON array of card credential objects
 *   e2e:fields:<id>    per-card cached vCard fields
 *   e2e:saved-links    JSON array of { url, label, savedAt }
 *   e2e:exported:<id>  "1" — marks a card as backed up
 *
 * Each card credential object:
 *   { id, label, nsec, npub, key, relays }
 *
 * AES key encoded in the URL fragment (#) of every share link —
 * never sent to any relay or server.
 *
 * Security:
 *   - nsec is never logged (redacted in all console statements)
 *   - All user input rendered via textContent / htmlEscape()
 *   - Relay URLs validated as wss:// before use
 *   - naddrDecode always wrapped in try/catch
 */

import { generateKey, encryptVCard, decryptVCard, keyToFragment, fragmentToKey, generateRandom } from './crypto.js';
import { buildVCard, parseVCard } from './vcard.js';
import { generateKeypair, publishCard, fetchCard, deleteCard, naddrEncode, naddrDecode, isValidRelayUrl, DEFAULT_RELAYS } from './nostr.js';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let activeCardId = null; // ID of the card open in the editor

// ---------------------------------------------------------------------------
// localStorage helpers
// ---------------------------------------------------------------------------

function getCards() {
  try { return JSON.parse(localStorage.getItem('e2e:cards') || '[]'); } catch { return []; }
}

function saveCards(cards) {
  localStorage.setItem('e2e:cards', JSON.stringify(cards));
}

function getCard(id) {
  return getCards().find(c => c.id === id) || null;
}

function getSavedLinks() {
  try { return JSON.parse(localStorage.getItem('e2e:saved-links') || '[]'); } catch { return []; }
}

function saveSavedLinks(links) {
  localStorage.setItem('e2e:saved-links', JSON.stringify(links));
}

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

async function init() {
  const cards = getCards();
  if (cards.length === 0) {
    if (getSavedLinks().length > 0) {
      showSavedLinks();
    } else {
      showSetup();
    }
    return;
  }
  showCardList();
}

// ---------------------------------------------------------------------------
// Screens
// ---------------------------------------------------------------------------

const ALL_SCREENS = ['screen-setup', 'screen-cards', 'screen-editor', 'screen-saved', 'screen-card-view'];

function showScreen(name) {
  for (const s of ALL_SCREENS) {
    document.getElementById(s).classList.toggle('hidden', s !== name);
  }
  document.getElementById('btn-back-cards').classList.toggle('hidden',  name !== 'screen-editor');
  document.getElementById('btn-delete-card').classList.toggle('hidden', name !== 'screen-editor');
  document.getElementById('cv-btn-back').classList.toggle('hidden',     name !== 'screen-card-view');
}

function showSetup()     { showScreen('screen-setup');     }
function showCardList()  { showScreen('screen-cards');  renderCardList(); }
function showEditor()    { showScreen('screen-editor'); }
function showSavedLinks(){ showScreen('screen-saved');  renderSavedLinks(); }

// ---------------------------------------------------------------------------
// Card list
// ---------------------------------------------------------------------------

function renderCardList() {
  const cards     = getCards();
  const container = document.getElementById('cards-list');
  container.innerHTML = '';

  if (cards.length === 0) {
    container.innerHTML = '<p class="muted">No cards yet. Create your first one above.</p>';
    return;
  }

  for (const card of cards) {
    let fn = '';
    try {
      const cached = localStorage.getItem(`e2e:fields:${card.id}`);
      if (cached) { const f = JSON.parse(cached); fn = f.fn || ''; }
    } catch {}
    const subtitle = fn && fn !== card.label ? fn : '';

    const row = document.createElement('div');
    row.className = 'card-list-row';

    // Relay status badges (pre-saved from last publish, or placeholder)
    let badgesHtml = '';
    const lastStatus = (() => {
      try { return JSON.parse(localStorage.getItem(`e2e:relay-status:${card.id}`) || 'null'); } catch { return null; }
    })();
    if (lastStatus) {
      for (const r of lastStatus) {
        const short = r.relay.replace(/^wss?:\/\//, '').split('/')[0];
        badgesHtml += `<span class="relay-badge relay-badge--${r.ok ? 'ok' : 'fail'}" title="${htmlEscape(r.relay)}">${htmlEscape(short)}</span>`;
      }
    }

    row.innerHTML = `
      <div class="card-list-info">
        <span class="card-list-name">${htmlEscape(card.label)}</span>
        <button class="btn btn-ghost btn-sm btn-card-rename" title="Rename">✎</button>
        <span class="card-list-meta">${subtitle ? htmlEscape(subtitle) + ' · ' : ''}${(card.relays || []).length} relays</span>
        ${badgesHtml ? `<div class="relay-badges">${badgesHtml}</div>` : ''}
      </div>
      <div class="card-list-actions">
        <button class="btn btn-ghost    btn-sm btn-card-view">View</button>
        <button class="btn btn-primary  btn-sm btn-card-edit">Edit</button>
        <button class="btn btn-success  btn-sm btn-card-share">Share</button>
      </div>
    `;

    row.querySelector('.btn-card-view').addEventListener('click', () => viewCardFromList(card));
    row.querySelector('.btn-card-edit').addEventListener('click', () => openEditor(card.id));
    row.querySelector('.btn-card-share').addEventListener('click', () => openShareModalForCard(card));
    row.querySelector('.btn-card-rename').addEventListener('click', () => renameCard(row, card));

    container.appendChild(row);
  }
}

function renameCard(row, card) {
  const nameEl    = row.querySelector('.card-list-name');
  const renameBtn = row.querySelector('.btn-card-rename');
  const current   = card.label;

  const input = document.createElement('input');
  input.type      = 'text';
  input.value     = current;
  input.className = 'card-rename-input';
  nameEl.replaceWith(input);
  renameBtn.textContent = 'Save';
  input.focus();
  input.select();

  const commit = () => {
    const newLabel = input.value.trim() || current;
    const cards    = getCards();
    const idx      = cards.findIndex(c => c.id === card.id);
    if (idx >= 0) { cards[idx].label = newLabel; saveCards(cards); card.label = newLabel; }
    const span = document.createElement('span');
    span.className   = 'card-list-name';
    span.textContent = newLabel;
    input.replaceWith(span);
    renameBtn.textContent = '✎';
    renameBtn.onclick = () => renameCard(row, card);
  };

  renameBtn.onclick = commit;
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter')  commit();
    if (e.key === 'Escape') { input.value = current; commit(); }
  });
}

function viewCardFromList(card) {
  const url = buildShareUrl(card);
  showCardViewScreen(url, 'owner-preview');
}

// ---------------------------------------------------------------------------
// Editor — open
// ---------------------------------------------------------------------------

async function openEditor(id) {
  activeCardId = id;
  showEditor();
  renderRelayManager();

  // Show cached fields immediately
  restoreFields(id);

  // Fetch latest from relay in background and update if newer
  const card = getCard(id);
  if (card) {
    try {
      const nsecBytes = hexToBytes(card.nsec);
      const aesKey    = await importCardKey(card.key);
      const event     = await fetchCard(card.relays, card.npub, id);
      if (event) {
        const vcardText = await decryptVCard(event.content, aesKey);
        const fields    = parseVCard(vcardText);
        localStorage.setItem(`e2e:fields:${id}`, JSON.stringify(fields));
        restoreFields(id);
      }
    } catch (err) {
      console.warn('[app] Could not refresh from relay:', err.message);
    }
  }
}

// ---------------------------------------------------------------------------
// Editor — field rendering helpers
// ---------------------------------------------------------------------------

function restoreFields(id) {
  const raw = localStorage.getItem(`e2e:fields:${id}`);
  if (!raw) return;
  let fields;
  try { fields = JSON.parse(raw); } catch { return; }

  const set = (elId, val) => { const el = document.getElementById(elId); if (el) el.value = val || ''; };
  set('fn',        fields.fn);
  set('firstName', fields.firstName);
  set('lastName',  fields.lastName);

  clearList('tel-list');
  for (const item of (fields.tel || [])) {
    const val  = typeof item === 'string' ? item : item.value;
    const type = typeof item === 'string' ? 'cell' : (item.type || 'cell');
    if (val) addDynamicField('tel-list', 'tel', '+46 70 000 00 00', val, type);
  }

  clearList('email-list');
  for (const item of (fields.email || [])) {
    const val  = typeof item === 'string' ? item : item.value;
    const type = typeof item === 'string' ? 'work' : (item.type || 'work');
    if (val) addDynamicField('email-list', 'email', 'alice@example.com', val, type);
  }

  clearList('org-list');
  for (const val of (Array.isArray(fields.org) ? fields.org : (fields.org ? [fields.org] : []))) {
    if (val) addDynamicField('org-list', 'org', 'Acme Corp', val);
  }

  clearList('title-list');
  for (const val of (Array.isArray(fields.title) ? fields.title : (fields.title ? [fields.title] : []))) {
    if (val) addDynamicField('title-list', 'title', 'Engineer', val);
  }

  clearList('url-list');
  const urls = Array.isArray(fields.url) ? fields.url : (fields.url ? [{ value: fields.url, type: 'work' }] : []);
  for (const item of urls) {
    const val  = typeof item === 'string' ? item : item.value;
    const type = typeof item === 'string' ? 'work' : (item.type || 'work');
    if (val) addDynamicField('url-list', 'url', 'https://example.com', val, type);
  }

  clearList('adr-list');
  for (const item of (fields.adr || [])) {
    addAdrField(item);
  }

  clearList('note-list');
  for (const val of (Array.isArray(fields.note) ? fields.note : (fields.note ? [fields.note] : []))) {
    if (val) addDynamicField('note-list', 'note', 'Optional note visible to recipients', val);
  }
}

function clearList(listId) {
  const el = document.getElementById(listId);
  if (!el) return;
  // Remove all rows, keep the <label> child
  Array.from(el.children).forEach(child => {
    if (child.tagName !== 'LABEL') child.remove();
  });
}

function readFields() {
  const get = id => (document.getElementById(id)?.value || '').trim();

  // TEL
  const tel = [];
  document.querySelectorAll('#tel-list .dynamic-row').forEach(row => {
    const val  = row.querySelector('.dynamic-input')?.value?.trim();
    const type = row.querySelector('.dynamic-type-select')?.value || 'cell';
    if (val) tel.push({ value: val, type });
  });

  // EMAIL
  const email = [];
  document.querySelectorAll('#email-list .dynamic-row').forEach(row => {
    const val  = row.querySelector('.dynamic-input')?.value?.trim();
    const type = row.querySelector('.dynamic-type-select')?.value || 'work';
    if (val) email.push({ value: val, type });
  });

  // ORG
  const org = [];
  document.querySelectorAll('#org-list .dynamic-row').forEach(row => {
    const val = row.querySelector('.dynamic-input')?.value?.trim();
    if (val) org.push(val);
  });

  // TITLE
  const title = [];
  document.querySelectorAll('#title-list .dynamic-row').forEach(row => {
    const val = row.querySelector('.dynamic-input')?.value?.trim();
    if (val) title.push(val);
  });

  // URL
  const url = [];
  document.querySelectorAll('#url-list .dynamic-row').forEach(row => {
    const val  = row.querySelector('.dynamic-input')?.value?.trim();
    const type = row.querySelector('.dynamic-type-select')?.value || 'work';
    if (val) url.push({ value: val, type });
  });

  // ADR
  const adr = [];
  document.querySelectorAll('#adr-list .adr-row').forEach(row => {
    const parts = ['street', 'city', 'region', 'postcode', 'country'].map(
      p => row.querySelector(`.adr-${p}`)?.value?.trim() || ''
    );
    const type = row.querySelector('.dynamic-type-select')?.value || 'home';
    if (parts.some(Boolean)) adr.push({ street: parts[0], city: parts[1], region: parts[2], postcode: parts[3], country: parts[4], type });
  });

  // NOTE
  const note = [];
  document.querySelectorAll('#note-list .dynamic-row').forEach(row => {
    const val = row.querySelector('textarea')?.value?.trim();
    if (val) note.push(val);
  });

  return {
    fn:        get('fn'),
    firstName: get('firstName'),
    lastName:  get('lastName'),
    tel, email, org, title, url, adr, note,
  };
}

// ---------------------------------------------------------------------------
// Dynamic field adders
// ---------------------------------------------------------------------------

const TYPE_OPTIONS = {
  tel:   [['cell','Mobile'],['work','Work'],['home','Home'],['fax','Fax']],
  email: [['work','Work'],['home','Home'],['other','Other']],
  url:   [['work','Work'],['home','Home'],['other','Other']],
};

function addDynamicField(listId, type, placeholder, value = '', selectedType = '') {
  const list = document.getElementById(listId);
  const row  = document.createElement('div');
  row.className = 'dynamic-row';

  const hasType = !!TYPE_OPTIONS[type];
  const inputTag = type === 'note' ? 'textarea' : 'input';
  const inputType = { tel: 'tel', email: 'email', url: 'url' }[type] || 'text';

  const input = document.createElement(inputTag);
  input.className = 'dynamic-input';
  if (inputTag === 'input') { input.type = inputType; input.placeholder = placeholder; }
  else { input.placeholder = placeholder; input.rows = 3; }
  input.value = value;

  const removeBtn = document.createElement('button');
  removeBtn.type      = 'button';
  removeBtn.className = 'btn btn-danger btn-sm';
  removeBtn.textContent = '✕';
  removeBtn.addEventListener('click', () => row.remove());

  if (hasType) {
    const select = document.createElement('select');
    select.className = 'dynamic-type-select';
    for (const [val, label] of TYPE_OPTIONS[type]) {
      const opt = document.createElement('option');
      opt.value = val; opt.textContent = label;
      if (val === (selectedType || TYPE_OPTIONS[type][0][0])) opt.selected = true;
      select.appendChild(opt);
    }
    row.appendChild(input);
    row.appendChild(select);
  } else {
    row.appendChild(input);
  }
  row.appendChild(removeBtn);
  list.appendChild(row);
  input.focus();
}

function addAdrField(prefill = {}) {
  const list = document.getElementById('adr-list');
  const row  = document.createElement('div');
  row.className = 'adr-row dynamic-row';
  row.style.flexDirection = 'column';
  row.style.alignItems    = 'stretch';
  row.style.gap           = '4px';

  const typeRow = document.createElement('div');
  typeRow.style.cssText = 'display:flex;gap:8px;align-items:center;justify-content:space-between';

  const typeLabel = document.createElement('span');
  typeLabel.className   = 'muted';
  typeLabel.textContent = 'Address';
  typeLabel.style.fontSize = '13px';

  const select = document.createElement('select');
  select.className = 'dynamic-type-select';
  for (const [val, label] of [['home','Home'],['work','Work'],['other','Other']]) {
    const opt = document.createElement('option');
    opt.value = val; opt.textContent = label;
    if (val === (prefill.type || 'home')) opt.selected = true;
    select.appendChild(opt);
  }

  const removeBtn = document.createElement('button');
  removeBtn.type      = 'button';
  removeBtn.className = 'btn btn-danger btn-sm';
  removeBtn.textContent = '✕';
  removeBtn.addEventListener('click', () => row.remove());

  typeRow.appendChild(typeLabel);
  typeRow.appendChild(select);
  typeRow.appendChild(removeBtn);
  row.appendChild(typeRow);

  const fields = [
    ['street',  'Street address'],
    ['city',    'City'],
    ['region',  'State / Region'],
    ['postcode','Postcode'],
    ['country', 'Country'],
  ];
  for (const [cls, ph] of fields) {
    const input = document.createElement('input');
    input.type        = 'text';
    input.className   = `dynamic-input adr-${cls}`;
    input.placeholder = ph;
    input.value       = prefill[cls] || '';
    row.appendChild(input);
  }

  list.appendChild(row);
  row.querySelector('.adr-street').focus();
}

// ---------------------------------------------------------------------------
// Create card
// ---------------------------------------------------------------------------

document.getElementById('btn-create-card').addEventListener('click', async () => {
  await promptCreateCard(document.getElementById('btn-create-card'));
});

document.getElementById('btn-new-card').addEventListener('click', async () => {
  await promptCreateCard(document.getElementById('btn-new-card'));
});

async function promptCreateCard(btn) {
  const label = prompt('Card name (e.g. Work, Personal, Minimal):', 'My Card');
  if (label === null) return;
  btn.disabled    = true;
  btn.textContent = 'Creating…';
  try {
    await createCard(label.trim() || 'My Card');
  } catch (err) {
    alert('Failed to create card: ' + err.message);
  } finally {
    btn.disabled    = false;
    btn.textContent = btn.id === 'btn-new-card' ? '+ New Card' : 'Create my card';
  }
}

async function createCard(label, prefillFields = null) {
  const { nsec, npub } = generateKeypair();
  const aesKey  = await generateKey();
  const keyFrag = await keyToFragment(aesKey);
  const id      = generateRandom(8).toLowerCase();
  const relays  = [...DEFAULT_RELAYS];

  const fields    = prefillFields
    ? { ...prefillFields, sourceUrl: canonicalUrl(id, npub, relays) }
    : { fn: label,        sourceUrl: canonicalUrl(id, npub, relays) };
  const vcardText = buildVCard(fields);
  const blob      = await encryptVCard(vcardText, aesKey);

  const results = await publishCard(relays, nsec, id, blob, label);

  const nsecHex = bytesToHex(nsec);
  const cards   = getCards();
  // nsec stored as hex — never in bech32; never logged
  cards.push({ id, label, nsec: nsecHex, npub, key: keyFrag, relays });
  saveCards(cards);

  localStorage.setItem(`e2e:relay-status:${id}`, JSON.stringify(results));
  if (prefillFields) {
    localStorage.setItem(`e2e:fields:${id}`, JSON.stringify(fields));
  }

  activeCardId = id;
  if (!prefillFields) {
    showEditor();
    renderRelayManager();
    restoreFields(id);
  }
}

// ---------------------------------------------------------------------------
// Save (encrypt + publish)
// ---------------------------------------------------------------------------

document.getElementById('btn-save').addEventListener('click', async () => {
  const btn    = document.getElementById('btn-save');
  const status = document.getElementById('save-status');

  if (!activeCardId) return;
  const card = getCard(activeCardId);
  if (!card) return;

  const fields = readFields();
  if (!fields.fn.trim()) {
    status.textContent = 'Full name is required.';
    status.className   = 'status-msg error';
    return;
  }

  btn.disabled       = true;
  status.textContent = 'Publishing…';
  status.className   = 'status-msg';

  try {
    const aesKey    = await importCardKey(card.key);
    const nsecBytes = hexToBytes(card.nsec);

    fields.sourceUrl  = canonicalUrl(activeCardId, card.npub, card.relays);
    const vcardText   = buildVCard(fields);
    const blob        = await encryptVCard(vcardText, aesKey);

    const results = await publishCard(card.relays, nsecBytes, activeCardId, blob, card.label);

    localStorage.setItem(`e2e:fields:${activeCardId}`, JSON.stringify(fields));
    localStorage.setItem(`e2e:relay-status:${activeCardId}`, JSON.stringify(results));

    const allOk = results.every(r => r.ok);
    const okCount = results.filter(r => r.ok).length;
    status.textContent = allOk
      ? `Published ✓ (${okCount}/${results.length} relays)`
      : `Published to ${okCount}/${results.length} relays`;
    status.className = allOk ? 'status-msg success' : 'status-msg';

    // Update relay badges in card list (if shown)
    setTimeout(() => { status.textContent = ''; }, 4000);
  } catch (err) {
    status.textContent = 'Publish failed: ' + err.message;
    status.className   = 'status-msg error';
  } finally {
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// Delete card
// ---------------------------------------------------------------------------

document.getElementById('btn-delete-card').addEventListener('click', async () => {
  if (!activeCardId) return;
  const card = getCard(activeCardId);
  if (!card) return;

  if (!confirm(`Delete "${card.label}"?\n\nThis removes the card from your device and sends a deletion request to all relays. Deletion is best-effort — not all relays guarantee it.\n\nExisting share links will stop working.`)) return;

  const btn = document.getElementById('btn-delete-card');
  btn.disabled = true;

  try {
    const nsecBytes = hexToBytes(card.nsec);
    await deleteCard(card.relays, nsecBytes, activeCardId);
  } catch (err) {
    console.warn('[app] deleteCard error (non-fatal):', err.message);
  }

  const remaining = getCards().filter(c => c.id !== activeCardId);
  saveCards(remaining);
  localStorage.removeItem(`e2e:fields:${activeCardId}`);
  localStorage.removeItem(`e2e:relay-status:${activeCardId}`);

  activeCardId = null;
  btn.disabled = false;

  if (remaining.length === 0) { showSetup(); } else { showCardList(); }
});

// ---------------------------------------------------------------------------
// Share modal
// ---------------------------------------------------------------------------

document.getElementById('btn-open-share').addEventListener('click', () => {
  if (!activeCardId) return;
  const card = getCard(activeCardId);
  if (card) openShareModal(card);
});

function openShareModalForCard(card) {
  openShareModal(card);
}

function openShareModal(card) {
  const shareUrl = buildShareUrl(card);

  document.getElementById('share-label').textContent = card.label;
  document.getElementById('share-url').value         = shareUrl;
  document.getElementById('modal-share').classList.remove('hidden');

  const qrContainer = document.getElementById('qr-container');
  qrContainer.innerHTML = '';
  renderQR(qrContainer, shareUrl);
}

document.getElementById('btn-copy-url').addEventListener('click', async () => {
  const url = document.getElementById('share-url').value;
  try { await navigator.clipboard.writeText(url); } catch { /* fallback: select */ }
  const btn = document.getElementById('btn-copy-url');
  btn.textContent = 'Copied!';
  setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
});

document.getElementById('btn-modal-close').addEventListener('click', () => {
  document.getElementById('modal-share').classList.add('hidden');
});

document.getElementById('btn-save-qr').addEventListener('click', () => {
  const img = document.querySelector('#qr-container img');
  if (!img) return;
  const label = document.getElementById('share-label').textContent || 'qr';
  const a = document.createElement('a');
  a.href     = img.src;
  a.download = `share-qr-${label.replace(/\s+/g, '-').toLowerCase()}.png`;
  a.click();
});

document.getElementById('modal-share').addEventListener('click', e => {
  if (e.target === e.currentTarget) e.currentTarget.classList.add('hidden');
});

// ---------------------------------------------------------------------------
// Inline card viewer
// ---------------------------------------------------------------------------

document.getElementById('btn-view-card').addEventListener('click', () => {
  if (!activeCardId) return;
  const card = getCard(activeCardId);
  if (card) showCardViewScreen(buildShareUrl(card), 'owner-preview');
});

document.getElementById('cv-btn-back').addEventListener('click', () => {
  if (activeCardId) { showEditor(); } else { showCardList(); }
});

document.getElementById('cv-btn-back-error').addEventListener('click', () => {
  if (activeCardId) { showEditor(); } else { showCardList(); }
});

async function showCardViewScreen(url, mode) {
  showScreen('screen-card-view');

  // Reset inline viewer state
  document.getElementById('cv-screen-loading').classList.remove('hidden');
  document.getElementById('cv-screen-trust').classList.add('hidden');
  document.getElementById('cv-screen-error').classList.add('hidden');
  document.getElementById('cv-screen-card').classList.add('hidden');
  document.getElementById('cv-contact-fields').innerHTML = '';

  // Parse url
  const urlObj  = new URL(url);
  const naddr   = urlObj.searchParams.get('naddr');
  const fragment = urlObj.hash.slice(1);

  if (!naddr || !fragment) {
    showCvError('Invalid link', 'Missing naddr or key fragment.');
    return;
  }

  let decoded;
  try { decoded = naddrDecode(naddr); } catch {
    showCvError('Invalid link', 'Malformed naddr.');
    return;
  }

  const { pubkey, identifier: cardId, relays } = decoded;

  let aesKey;
  try { aesKey = await fragmentToKey(fragment); } catch {
    showCvError('Invalid key', 'The decryption key in the link is not valid.');
    return;
  }

  let event;
  try { event = await fetchCard(relays, pubkey, cardId); } catch {
    showCvError('Network error', 'Could not connect to Nostr relays.');
    return;
  }
  if (!event) {
    showCvError('Card not found', 'The card was not found on any relay.');
    return;
  }

  let vcardText;
  try { vcardText = await decryptVCard(event.content, aesKey); } catch {
    showCvError('Decryption failed', 'Could not decrypt this card.');
    return;
  }

  const fields = parseVCard(vcardText);

  if (mode === 'owner-preview') {
    renderCvCard(fields, vcardText, true, true);
  } else {
    showCvTrustGate(cardId, fields, vcardText, url);
  }
}

function showCvError(title, detail) {
  document.getElementById('cv-screen-loading').classList.add('hidden');
  document.getElementById('cv-error-title').textContent  = title;
  document.getElementById('cv-error-detail').textContent = detail;
  document.getElementById('cv-screen-error').classList.remove('hidden');
}

const TRUST_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function getCvTrust(cardId) {
  try {
    const raw = localStorage.getItem(`e2e:trusted:${cardId}`);
    if (!raw) return false;
    const data = JSON.parse(raw);
    if (!data?.ok || Date.now() > data.expires) { localStorage.removeItem(`e2e:trusted:${cardId}`); return false; }
    return true;
  } catch { return false; }
}

function setCvTrust(cardId) {
  try {
    localStorage.setItem(`e2e:trusted:${cardId}`, JSON.stringify({ ok: true, expires: Date.now() + TRUST_TTL_MS }));
  } catch {}
}

function showCvTrustGate(cardId, fields, vcardText, shareUrl) {
  if (getCvTrust(cardId)) {
    autoSaveLink(shareUrl, fields.fn);
    renderCvCard(fields, vcardText, true, false);
    return;
  }
  document.getElementById('cv-screen-loading').classList.add('hidden');
  document.getElementById('cv-screen-trust').classList.remove('hidden');

  document.getElementById('cv-btn-trusted').onclick = () => {
    setCvTrust(cardId);
    autoSaveLink(shareUrl, fields.fn);
    document.getElementById('cv-screen-trust').classList.add('hidden');
    renderCvCard(fields, vcardText, true, false);
  };
  document.getElementById('cv-btn-public').onclick = () => {
    document.getElementById('cv-screen-trust').classList.add('hidden');
    renderCvCard(fields, vcardText, false, false);
  };
}

function autoSaveLink(url, label) {
  const SAVED_KEY = 'e2e:saved-links';
  let links = [];
  try { links = JSON.parse(localStorage.getItem(SAVED_KEY) || '[]'); } catch {}
  if (!links.some(l => l.url === url)) {
    links.push({ url, label: label || 'Contact', savedAt: new Date().toISOString() });
    try { localStorage.setItem(SAVED_KEY, JSON.stringify(links)); } catch {}
  }
}

function renderCvCard(fields, vcardText, trusted, ownerPreview) {
  document.getElementById('cv-screen-loading').classList.add('hidden');

  const initials = makeInitials(fields.fn || '');
  document.getElementById('cv-contact-avatar').textContent = initials;
  document.getElementById('cv-contact-fn').textContent     = fields.fn || '';

  const firstTitle = Array.isArray(fields.title) ? fields.title[0] : fields.title;
  const firstOrg   = Array.isArray(fields.org)   ? fields.org[0]   : fields.org;
  const subtitle   = [firstTitle, firstOrg].filter(Boolean).join(' · ');
  const subtitleEl = document.getElementById('cv-contact-title-org');
  if (subtitle) { subtitleEl.textContent = subtitle; } else { subtitleEl.remove(); }

  const container = document.getElementById('cv-contact-fields');
  const nameParts = [fields.firstName, fields.lastName].filter(Boolean).join(' ');
  if (nameParts && nameParts !== fields.fn) container.appendChild(cvFieldRow('👤', 'name', nameParts, null));
  for (const t of (fields.tel || [])) {
    const v = typeof t === 'string' ? t : t.value;
    if (v?.trim()) container.appendChild(cvFieldRow('📞', 'tel', v.trim(), `tel:${v.trim()}`));
  }
  for (const e of (fields.email || [])) {
    const v = typeof e === 'string' ? e : e.value;
    if (v?.trim()) container.appendChild(cvFieldRow('✉️', 'email', v.trim(), `mailto:${v.trim()}`));
  }
  for (const u of (Array.isArray(fields.url) ? fields.url : (fields.url ? [{ value: fields.url }] : []))) {
    const v = typeof u === 'string' ? u : u.value;
    if (v?.trim()) container.appendChild(cvFieldRow('🔗', 'website', v.trim(), v.trim()));
  }
  for (const n of (Array.isArray(fields.note) ? fields.note : (fields.note ? [fields.note] : []))) {
    if (n?.trim()) container.appendChild(cvFieldRow('📝', 'note', n.trim(), null));
  }

  const dlBtn = document.getElementById('cv-btn-download');
  if (trusted) {
    dlBtn.addEventListener('click', () => {
      downloadVcf(vcardText, fields.fn);
      if (!ownerPreview) setTimeout(() => cvKill('download'), 3000);
    });
  } else {
    dlBtn.style.display = 'none';
  }

  const doneBtn = document.getElementById('cv-btn-done');
  if (!trusted && !ownerPreview) {
    doneBtn.classList.remove('hidden');
    doneBtn.addEventListener('click', () => cvKill('manual'));
    doneBtn.classList.add('btn-done-public');
    doneBtn.classList.remove('btn-secondary');
  }

  const saveLinkBtn = document.getElementById('cv-btn-save-link');
  if (trusted && !ownerPreview) {
    saveLinkBtn.classList.remove('hidden');
    saveLinkBtn.textContent = '✓ Link saved';
    saveLinkBtn.disabled    = true;
  }

  if (!trusted) {
    document.getElementById('cv-public-mode-banner').classList.remove('hidden');
    const hint = document.querySelector('.cv-update-hint');
    if (hint) hint.style.display = 'none';
  }

  let cvKillTimer = null, cvCountdownInterval = null;
  const onVisibility = () => { if (document.visibilityState === 'hidden') cvKill('tab-hidden'); };
  if (!trusted && !ownerPreview) {
    document.addEventListener('visibilitychange', onVisibility);
    const AUTO_KILL_MS = 5 * 60 * 1000;
    const killAt = Date.now() + AUTO_KILL_MS;
    const countdownEl = document.createElement('p');
    countdownEl.className = 'auto-clear-countdown muted';
    document.querySelector('.cv-card-actions').appendChild(countdownEl);
    cvCountdownInterval = setInterval(() => {
      const rem = Math.max(0, killAt - Date.now());
      const m = Math.floor(rem / 60000), s = Math.floor((rem % 60000) / 1000);
      countdownEl.textContent = `⏱ Auto-clears in ${m}:${String(s).padStart(2,'0')}`;
    }, 1000);
    cvKillTimer = setTimeout(() => cvKill('timeout'), AUTO_KILL_MS);
  }

  function cvKill(reason) {
    document.removeEventListener('visibilitychange', onVisibility);
    if (cvKillTimer)          clearTimeout(cvKillTimer);
    if (cvCountdownInterval)  clearInterval(cvCountdownInterval);
    vcardText = '';
    const section = document.getElementById('cv-screen-card');
    if (!section) return;
    const msgs = { manual: 'Session cleared.', download: 'Contact saved — session cleared.', 'tab-hidden': 'Session auto-cleared.', timeout: 'Session timed out.' };
    section.innerHTML = `<div class="card-panel centered"><div style="font-size:3rem">🔒</div><h2>${msgs[reason] || 'Session cleared.'}</h2><p class="muted">Safe to close this tab.</p></div>`;
  }

  if (typeof window.qrcode !== 'undefined') {
    try {
      const qr = window.qrcode(0, 'L');
      qr.addData(vcardText);
      qr.make();
      const c = document.getElementById('cv-vcard-qr-container');
      if (c) c.innerHTML = qr.createSvgTag({ scalable: true, cellSize: 4, margin: 4 });
    } catch {}
  }

  document.getElementById('cv-screen-card').classList.remove('hidden');
}

function cvFieldRow(icon, type, text, href) {
  const row = document.createElement('div');
  row.className = `field-row contact-field contact-field--${type}`;
  const iconEl = document.createElement('span');
  iconEl.className = 'field-icon'; iconEl.textContent = icon;
  const valEl = document.createElement('span');
  valEl.className = 'field-value';
  if (href) {
    const safe = /^(https?:|tel:|mailto:)/i.test(href) ? href : null;
    if (safe) {
      const a = document.createElement('a');
      a.href = safe; a.textContent = text;
      if (safe.startsWith('http')) { a.target = '_blank'; a.rel = 'noopener noreferrer'; }
      valEl.appendChild(a);
    } else { valEl.textContent = text; }
  } else { valEl.textContent = text; }
  row.appendChild(iconEl); row.appendChild(valEl);
  return row;
}

// ---------------------------------------------------------------------------
// Relay manager (editor sidebar)
// ---------------------------------------------------------------------------

document.getElementById('relay-manager-toggle').addEventListener('click', () => {
  const body = document.getElementById('relay-manager-body');
  const icon = document.getElementById('relay-toggle-icon');
  const hidden = body.classList.toggle('hidden');
  icon.textContent = hidden ? '▼' : '▲';
});

document.getElementById('btn-add-relay').addEventListener('click', () => {
  const input = document.getElementById('relay-input');
  const url   = input.value.trim();
  const errEl = document.getElementById('relay-error');
  errEl.classList.add('hidden');

  if (!isValidRelayUrl(url)) {
    errEl.textContent = 'Relay URL must start with wss://';
    errEl.classList.remove('hidden');
    return;
  }

  if (!activeCardId) return;
  const cards = getCards();
  const idx   = cards.findIndex(c => c.id === activeCardId);
  if (idx < 0) return;

  if (cards[idx].relays.includes(url)) {
    errEl.textContent = 'This relay is already in the list.';
    errEl.classList.remove('hidden');
    return;
  }

  cards[idx].relays.push(url);
  saveCards(cards);
  input.value = '';
  renderRelayManager();
});

function renderRelayManager() {
  if (!activeCardId) return;
  const card    = getCard(activeCardId);
  if (!card) return;

  const relays     = card.relays || [];
  const lastStatus = (() => {
    try { return JSON.parse(localStorage.getItem(`e2e:relay-status:${activeCardId}`) || '[]'); } catch { return []; }
  })();
  const statusMap  = Object.fromEntries(lastStatus.map(r => [r.relay, r.ok]));

  const listEl = document.getElementById('relay-list');
  listEl.innerHTML = '';

  for (const relay of relays) {
    const row = document.createElement('div');
    row.className = 'relay-row';

    const statusClass = relay in statusMap
      ? (statusMap[relay] ? 'relay-status-badge--ok' : 'relay-status-badge--fail')
      : 'relay-status-badge--wait';
    const statusText = relay in statusMap ? (statusMap[relay] ? '✓' : '✗') : '—';

    const badge = document.createElement('span');
    badge.className   = `relay-status-badge ${statusClass}`;
    badge.textContent = statusText;

    const urlSpan = document.createElement('span');
    urlSpan.className   = 'relay-row-url';
    urlSpan.textContent = relay;
    urlSpan.title       = relay;

    const removeBtn = document.createElement('button');
    removeBtn.type      = 'button';
    removeBtn.className = 'btn btn-danger btn-sm';
    removeBtn.textContent = '✕';
    removeBtn.addEventListener('click', () => {
      const cards = getCards();
      const idx   = cards.findIndex(c => c.id === activeCardId);
      if (idx >= 0 && cards[idx].relays.length > 1) {
        cards[idx].relays = cards[idx].relays.filter(r => r !== relay);
        saveCards(cards);
        renderRelayManager();
      } else {
        alert('A card must have at least one relay.');
      }
    });

    row.appendChild(badge);
    row.appendChild(urlSpan);
    row.appendChild(removeBtn);
    listEl.appendChild(row);
  }
}

// ---------------------------------------------------------------------------
// Back / Log out
// ---------------------------------------------------------------------------

document.getElementById('btn-back-cards').addEventListener('click', () => {
  activeCardId = null;
  showCardList();
});

document.getElementById('btn-back-to-cards').addEventListener('click', () => {
  showCardList();
});

document.getElementById('btn-go-saved').addEventListener('click', () => {
  showSavedLinks();
});

document.getElementById('btn-clear-all').addEventListener('click', () => {
  if (!confirm('This will remove from this device:\n\n• All card credentials (private keys + encryption keys)\n• All cached contact data\n• All saved cards (received links)\n\nYour cards remain on the relays and can be restored from a backup. Continue?')) return;
  const cards = getCards();
  for (const c of cards) {
    localStorage.removeItem(`e2e:fields:${c.id}`);
    localStorage.removeItem(`e2e:relay-status:${c.id}`);
  }
  localStorage.removeItem('e2e:cards');
  localStorage.removeItem('e2e:saved-links');
  activeCardId = null;
  location.reload();
});

// ---------------------------------------------------------------------------
// Saved links screen
// ---------------------------------------------------------------------------

function renderSavedLinks() {
  const links     = getSavedLinks();
  const container = document.getElementById('saved-links-list');
  container.innerHTML = '';

  if (links.length === 0) {
    container.innerHTML = '<p class="muted">No saved cards yet. Open a card link and choose "My personal device" to save it here.</p>';
    return;
  }

  for (const link of links) {
    const row = document.createElement('div');
    row.className = 'saved-link-row';

    const saved = link.savedAt ? new Date(link.savedAt).toLocaleDateString() : '';

    const info = document.createElement('div');
    info.className = 'saved-link-info';
    const nameEl = document.createElement('span');
    nameEl.className   = 'saved-link-label';
    nameEl.textContent = link.label || 'Contact';
    const dateEl = document.createElement('span');
    dateEl.className   = 'saved-link-date';
    dateEl.textContent = saved;
    info.appendChild(nameEl);
    info.appendChild(dateEl);

    const actions = document.createElement('div');
    actions.className = 'saved-link-actions';

    const openBtn = document.createElement('button');
    openBtn.className   = 'btn btn-primary btn-sm';
    openBtn.textContent = 'Open';
    openBtn.addEventListener('click', () => showCardViewScreen(link.url, 'saved-card'));

    const removeBtn = document.createElement('button');
    removeBtn.className   = 'btn btn-danger btn-sm';
    removeBtn.textContent = 'Remove';
    removeBtn.addEventListener('click', () => {
      const updated = getSavedLinks().filter(l => l.url !== link.url);
      saveSavedLinks(updated);
      renderSavedLinks();
    });

    actions.appendChild(openBtn);
    actions.appendChild(removeBtn);
    row.appendChild(info);
    row.appendChild(actions);
    container.appendChild(row);
  }
}

// ---------------------------------------------------------------------------
// Backup & Restore
// ---------------------------------------------------------------------------

document.getElementById('btn-backup').addEventListener('click', exportBackup);

function exportBackup() {
  const cards      = getCards();
  const savedLinks = getSavedLinks();
  const fields     = {};
  for (const card of cards) {
    const cached = localStorage.getItem(`e2e:fields:${card.id}`);
    if (cached) { try { fields[card.id] = JSON.parse(cached); } catch {} }
  }
  const backup = {
    version:  2,
    exported: new Date().toISOString(),
    cards,       // includes nsec (raw hex) — keep the file secure
    savedLinks,
    fields,
  };
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `nostr-vcard-backup-${backup.exported.slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  for (const card of cards) localStorage.setItem(`e2e:exported:${card.id}`, '1');
}

// File restore (setup screen)
document.getElementById('restore-file-input').addEventListener('change', async e => {
  const file = e.target.files[0];
  if (!file) return;
  try { await importBackup(JSON.parse(await file.text())); } catch { alert('Could not read backup file.'); }
  e.target.value = '';
});

// File restore (cards screen)
document.getElementById('restore-file-input-cards').addEventListener('change', async e => {
  const file = e.target.files[0];
  if (!file) return;
  try { await importBackup(JSON.parse(await file.text())); } catch { alert('Could not read backup file.'); }
  e.target.value = '';
});

// Paste restore — setup
document.getElementById('btn-paste-restore-setup').addEventListener('click', () => {
  document.getElementById('modal-restore').classList.remove('hidden');
});

// Paste restore — cards
document.getElementById('btn-paste-restore-cards').addEventListener('click', () => {
  document.getElementById('modal-restore').classList.remove('hidden');
});

document.getElementById('btn-restore-paste-confirm').addEventListener('click', async () => {
  const raw = document.getElementById('restore-paste-input').value.trim();
  try {
    await importBackup(JSON.parse(raw));
    document.getElementById('modal-restore').classList.add('hidden');
    document.getElementById('restore-paste-input').value = '';
  } catch {
    alert('Invalid JSON — check that you pasted the full backup text.');
  }
});

document.getElementById('btn-restore-paste-cancel').addEventListener('click', () => {
  document.getElementById('modal-restore').classList.add('hidden');
});

async function importBackup(json) {
  let cardPayloads = [], linkPayloads = [], fieldsMap = {};

  if (json?.version === 2 && Array.isArray(json.cards)) {
    // v2 — nostr-vcard native backup
    cardPayloads = json.cards;
    linkPayloads = Array.isArray(json.savedLinks) ? json.savedLinks : [];
    fieldsMap    = (json.fields && typeof json.fields === 'object') ? json.fields : {};
  } else if (json?.version === 1 && Array.isArray(json.cards)) {
    // v1 — legacy Cloudflare app backup; cards have ownerToken, no nsec/npub
    // We import fields + AES keys and generate fresh Nostr keypairs
    if (confirm('This is a legacy backup (v1). We will import your contact data and generate new Nostr identities.\n\nNote: old share links (with ?id=...&tok=...) will NOT work with the new app.')) {
      fieldsMap    = (json.fields && typeof json.fields === 'object') ? json.fields : {};
      linkPayloads = Array.isArray(json.savedLinks) ? json.savedLinks : [];
      let imported = 0;
      for (const payload of json.cards) {
        if (!payload?.id || !payload?.key) continue;
        const label = (fieldsMap[payload.id]?.fn) || payload.label || 'Imported Card';
        try {
          await createCard(label, { ...(fieldsMap[payload.id] || { fn: label }) });
          imported++;
        } catch {}
      }
      alert(`Imported ${imported} card${imported !== 1 ? 's' : ''}. Share new links from the editor.`);
    }
    linkPayloads = Array.isArray(json.savedLinks) ? json.savedLinks : [];
  } else if (Array.isArray(json)) {
    cardPayloads = json;
  } else if (json?.id && json?.nsec && json?.key) {
    cardPayloads = [json];
  } else {
    alert('Unrecognised format. Make sure you are pasting a valid nostr-vcard backup.');
    return;
  }

  const existingIds = new Set(getCards().map(c => c.id));
  let added = 0, skipped = 0, failed = 0;

  for (const payload of cardPayloads) {
    if (!payload?.id || !payload?.nsec || !payload?.key) { failed++; continue; }
    if (existingIds.has(payload.id)) { skipped++; continue; }

    // Validate nsec looks like 64-char hex
    if (!/^[0-9a-f]{64}$/i.test(payload.nsec)) { failed++; continue; }

    // Verify card exists on relays
    let found = false;
    try {
      const event = await fetchCard(payload.relays || DEFAULT_RELAYS, payload.npub, payload.id);
      found = !!event;
    } catch {}

    const cards = getCards();
    cards.push({
      id:     payload.id,
      label:  payload.label || 'Restored Card',
      nsec:   payload.nsec,
      npub:   payload.npub,
      key:    payload.key,
      relays: payload.relays || DEFAULT_RELAYS,
    });
    saveCards(cards);
    existingIds.add(payload.id);

    if (fieldsMap[payload.id]) {
      localStorage.setItem(`e2e:fields:${payload.id}`, JSON.stringify(fieldsMap[payload.id]));
    }

    if (!found) {
      // Card not on relay — offer re-publish if we have fields
      if (fieldsMap[payload.id]) {
        const shouldRepublish = confirm(`Card "${payload.label || payload.id}" was not found on the relay. Re-publish it now?`);
        if (shouldRepublish) {
          try {
            const aesKey    = await importCardKey(payload.key);
            const nsecBytes = hexToBytes(payload.nsec);
            const fields    = fieldsMap[payload.id];
            const vcardText = buildVCard(fields);
            const blob      = await encryptVCard(vcardText, aesKey);
            const results   = await publishCard(payload.relays || DEFAULT_RELAYS, nsecBytes, payload.id, blob, payload.label);
            localStorage.setItem(`e2e:relay-status:${payload.id}`, JSON.stringify(results));
          } catch {}
        }
      }
    }

    added++;
  }

  // Merge saved links
  const existingLinks = getSavedLinks();
  const existingUrls  = new Set(existingLinks.map(l => l.url));
  for (const item of linkPayloads) {
    if (!item?.url?.trim() || existingUrls.has(item.url)) continue;
    existingLinks.push({ url: item.url, label: item.label || 'Contact', savedAt: item.savedAt || new Date().toISOString() });
    existingUrls.add(item.url);
  }
  saveSavedLinks(existingLinks);

  // Restore field cache
  for (const [id, fieldData] of Object.entries(fieldsMap)) {
    if (!localStorage.getItem(`e2e:fields:${id}`)) {
      localStorage.setItem(`e2e:fields:${id}`, JSON.stringify(fieldData));
    }
  }

  alert(`Restore complete: ${added} added, ${skipped} skipped (already present), ${failed} failed.`);

  const cards = getCards();
  if (cards.length > 0) { showCardList(); } else { showSetup(); }
}

// ---------------------------------------------------------------------------
// Dynamic field add buttons
// ---------------------------------------------------------------------------

document.getElementById('btn-add-tel').addEventListener('click', () => addDynamicField('tel-list', 'tel', '+46 70 000 00 00'));
document.getElementById('btn-add-email').addEventListener('click', () => addDynamicField('email-list', 'email', 'alice@example.com'));
document.getElementById('btn-add-org').addEventListener('click', () => addDynamicField('org-list', 'org', 'Acme Corp'));
document.getElementById('btn-add-title').addEventListener('click', () => addDynamicField('title-list', 'title', 'Engineer'));
document.getElementById('btn-add-url').addEventListener('click', () => addDynamicField('url-list', 'url', 'https://example.com'));
document.getElementById('btn-add-adr').addEventListener('click', () => addAdrField());
document.getElementById('btn-add-note').addEventListener('click', () => addDynamicField('note-list', 'note', 'Optional note visible to recipients'));

// ---------------------------------------------------------------------------
// QR code helper
// ---------------------------------------------------------------------------

function renderQR(container, text) {
  if (typeof window.qrcode === 'undefined') return;
  try {
    const qr = window.qrcode(0, 'M');
    qr.addData(text);
    qr.make();

    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = qr.createSvgTag({ scalable: false, cellSize: 4, margin: 4 });
    const svgEl   = tempDiv.querySelector('svg');
    const svgData = new XMLSerializer().serializeToString(svgEl);
    const svgBlob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
    const svgUrl  = URL.createObjectURL(svgBlob);

    const size   = 320;
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = size;
    const ctx    = canvas.getContext('2d');
    const tmpImg = new Image();
    tmpImg.onload = () => {
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, size, size);
      ctx.drawImage(tmpImg, 0, 0, size, size);
      URL.revokeObjectURL(svgUrl);
      const img = document.createElement('img');
      img.src   = canvas.toDataURL('image/png');
      img.alt   = 'QR code';
      img.style.cssText = 'display:block;width:100%;max-width:320px;margin:0 auto;border-radius:4px;';
      container.appendChild(img);
    };
    tmpImg.src = svgUrl;
  } catch {}
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/** Build the full share URL (includes #AES-key fragment) */
function buildShareUrl(card) {
  const naddr = naddrEncode(card.npub, card.id, card.relays);
  return `${location.origin}/card.html?naddr=${naddr}#${card.key}`;
}

/** Canonical URL for vCard SOURCE field (no fragment, no key) */
function canonicalUrl(cardId, npub, relays) {
  const naddr = naddrEncode(npub, cardId, relays);
  return `${location.origin}/card.html?naddr=${naddr}`;
}

/** Import the card's AES key from its stored base64url fragment string */
async function importCardKey(keyFragment) {
  // Need extractable=true for the owner so we can re-encrypt on save
  const raw = base64urlToBytes(keyFragment);
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

/** Escape HTML special characters to prevent XSS in innerHTML strings */
function htmlEscape(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function makeInitials(name) {
  return name.split(/\s+/).filter(Boolean).slice(0, 2).map(w => w[0].toUpperCase()).join('');
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function base64urlToBytes(str) {
  const b64    = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

function downloadVcf(vcardText, fn) {
  const filename = (fn || 'contact').replace(/[^a-zA-Z0-9_-]/g, '_') + '.vcf';
  const blob = new Blob([vcardText], { type: 'text/vcard;charset=utf-8' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

init();
