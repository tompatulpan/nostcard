/**
 * app.js — Owner app for nostr-vcard
 *
 * State stored in localStorage:
 *   e2e:cards          JSON array of card credential objects
 *   e2e:fields:<id>    per-card cached vCard fields
 *   e2e:saved-links    JSON array of { url, label, savedAt }
 *   e2e:exported:<id>  "1" — marks a card as backed up
 *   e2e:sync-identity  JSON { syncNsecHex, syncNpub, syncKeyRaw (base64url), createdAt } — cached passphrase-derived sync identity
 *   e2e:sync-meta      JSON { lastPushedAt, lastPulledAt }
 *   e2e:connections    JSON array of connection objects (see below)
 *   e2e:connection-fields:<id>  per-connection cached decrypted vCard fields
 *
 * Each card credential object:
 *   { id, label, nsec, npub, key, relays }
 *
 * Each connection object (mutual in-person pairing — see pairing.js):
 *   { id, peerLabel, peerNaddr, peerKey, myCardId, pairedAt }
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
import { generateKeypair, derivePublicKey, publishCard, fetchCard, deleteCard, naddrEncode, naddrDecode, sameCardAddress, isValidRelayUrl, DEFAULT_RELAYS, CARD_KIND } from './nostr.js';
import { initI18n, t, setLang, getCurrentLang, applyTranslations } from './i18n.js';
import { generateSyncPassphrase, deriveSyncIdentity, pushSyncData, pullSyncData, deleteSyncData } from './sync.js';
import { generatePairingCode, derivePairingIdentity, publishPairingPayload, fetchPairingPayload, cleanupPairing, PAIR_TTL_MS } from './pairing.js';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

let activeCardId = null; // ID of the card open in the editor
let cvReturnRoute = '/cards'; // where cv-btn-back navigates to after the inline viewer closes

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

function getSyncIdentity() {
  try { return JSON.parse(localStorage.getItem('e2e:sync-identity') || 'null'); } catch { return null; }
}

function saveSyncIdentity(identity) {
  localStorage.setItem('e2e:sync-identity', JSON.stringify(identity));
}

function clearSyncIdentity() {
  localStorage.removeItem('e2e:sync-identity');
  localStorage.removeItem('e2e:sync-meta');
}

function getSyncMeta() {
  try { return JSON.parse(localStorage.getItem('e2e:sync-meta') || '{}'); } catch { return {}; }
}

function saveSyncMeta(meta) {
  localStorage.setItem('e2e:sync-meta', JSON.stringify(meta));
}

function getConnections() {
  try { return JSON.parse(localStorage.getItem('e2e:connections') || '[]'); } catch { return []; }
}

function saveConnections(connections) {
  localStorage.setItem('e2e:connections', JSON.stringify(connections));
}

function getConnectionFields(id) {
  try { return JSON.parse(localStorage.getItem(`e2e:connection-fields:${id}`) || 'null'); } catch { return null; }
}

function saveConnectionFields(id, fields) {
  localStorage.setItem(`e2e:connection-fields:${id}`, JSON.stringify(fields));
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

  // Re-render dynamic content when language changes
  window.addEventListener('i18n:changed', () => {
    document.querySelectorAll('.lang-btn').forEach(b => {
      b.classList.toggle('lang-btn--active', b.dataset.lang === getCurrentLang());
    });
    const screenCards = document.getElementById('screen-cards');
    const screenSaved = document.getElementById('screen-saved');
    if (screenCards && !screenCards.classList.contains('hidden')) renderCardList();
    if (screenSaved && !screenSaved.classList.contains('hidden')) renderSavedLinks();
    if (activeCardId) renderRelayManager();
    // Update type-select option labels and address subfield placeholders without losing user input
    document.querySelectorAll('.dynamic-type-select option').forEach(opt => {
      opt.textContent = t('field.type.' + opt.value);
    });
    document.querySelectorAll('.adr-row .muted').forEach(el => {
      el.textContent = t('field.adr.type.label');
    });
    const adrMap = {
      'adr-street': 'field.adr.street', 'adr-city': 'field.adr.city',
      'adr-region': 'field.adr.region', 'adr-postcode': 'field.adr.postcode',
      'adr-country': 'field.adr.country',
    };
    for (const [cls, key] of Object.entries(adrMap)) {
      document.querySelectorAll(`.${cls}`).forEach(el => { el.placeholder = t(key); });
    }
  });

  route();
}

// ---------------------------------------------------------------------------
// Screens
// ---------------------------------------------------------------------------

const ALL_SCREENS = ['screen-setup', 'screen-cards', 'screen-editor', 'screen-saved', 'screen-card-view', 'screen-pair-start', 'screen-pair-join'];

function showScreen(name) {
  for (const s of ALL_SCREENS) {
    document.getElementById(s).classList.toggle('hidden', s !== name);
  }
  document.getElementById('btn-back-cards').classList.toggle('hidden',  name !== 'screen-editor');
  document.getElementById('btn-delete-card').classList.toggle('hidden', name !== 'screen-editor');
  document.getElementById('cv-btn-back').classList.toggle('hidden',     name !== 'screen-card-view');
}

function showSetup()     { activeCardId = null; showScreen('screen-setup');     }
function showCardList()  { activeCardId = null; showScreen('screen-cards');  renderCardList(); }
function showEditor()    { showScreen('screen-editor'); }
function showSavedLinks(){ activeCardId = null; showScreen('screen-saved');  renderSavedLinks(); }

// ---------------------------------------------------------------------------
// Router — location.hash is the single source of truth for the current screen
// (enables deep links like index.html#/saved and working back/forward)
// ---------------------------------------------------------------------------

/** Navigate to a route (e.g. '/cards', '/editor/abc123', '/saved', '/setup') */
function go(path) {
  if (location.hash === `#${path}`) { route(); } else { location.hash = path; }
}

function route() {
  const hash = location.hash.replace(/^#\/?/, '');
  const [name, param] = hash.split('/');

  if (name === 'editor' && param && getCard(param)) { openEditor(param); return; }
  if (name === 'saved') { showSavedLinks(); return; }
  if (name === 'cards')  { showCardList();  return; }
  if (name === 'setup')  { showSetup();     return; }
  if (name === 'connections') { go('/saved'); return; } // legacy route — merged into Contacts
  if (name === 'pair-join' && param) { showPairJoin(param); return; }
  if (name === 'pair') { showPairStart(); return; }

  // No/invalid hash — pick the sensible default screen and normalize the URL
  const cards = getCards();
  if (cards.length > 0)                                                go('/cards');
  else if (getSavedLinks().length > 0 || getConnections().length > 0)  go('/saved');
  else                                                                   go('/setup');
}

window.addEventListener('hashchange', route);

// ---------------------------------------------------------------------------
// Card list
// ---------------------------------------------------------------------------

function renderCardList() {
  const cards     = getCards();
  const container = document.getElementById('cards-list');
  container.innerHTML = '';

  if (cards.length === 0) {
    container.innerHTML = `<p class="muted">${htmlEscape(t('cards.empty'))}</p>`;
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
        <button class="btn btn-ghost btn-sm btn-card-rename" title="${htmlEscape(t('cards.row.btn.rename.title'))}">✎</button>
        <span class="card-list-meta">${subtitle ? htmlEscape(subtitle) + ' · ' : ''}${htmlEscape(t('cards.relays.count', { n: (card.relays || []).length }))}</span>
        ${badgesHtml ? `<div class="relay-badges">${badgesHtml}</div>` : ''}
      </div>
      <div class="card-list-actions">
        <button class="btn btn-ghost    btn-sm btn-card-view">${htmlEscape(t('cards.row.btn.view'))}</button>
        <button class="btn btn-primary  btn-sm btn-card-edit">${htmlEscape(t('cards.row.btn.edit'))}</button>
        <button class="btn btn-success  btn-sm btn-card-share">${htmlEscape(t('cards.row.btn.share'))}</button>
      </div>
    `;

    row.querySelector('.btn-card-view').addEventListener('click', () => viewCardFromList(card));
    row.querySelector('.btn-card-edit').addEventListener('click', () => go(`/editor/${card.id}`));
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
  cvReturnRoute = '/cards';
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

  // Populate card name field
  const cardForName = getCard(id);
  if (cardForName) {
    const nameInput = document.getElementById('card-name');
    if (nameInput) nameInput.value = cardForName.label || '';
  }

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
    if (val) addDynamicField('tel-list', 'tel', t('editor.tel.placeholder'), val, type);
  }

  clearList('email-list');
  for (const item of (fields.email || [])) {
    const val  = typeof item === 'string' ? item : item.value;
    const type = typeof item === 'string' ? 'work' : (item.type || 'work');
    if (val) addDynamicField('email-list', 'email', t('editor.email.placeholder'), val, type);
  }

  clearList('org-list');
  for (const val of (Array.isArray(fields.org) ? fields.org : (fields.org ? [fields.org] : []))) {
    if (val) addDynamicField('org-list', 'org', t('editor.org.placeholder'), val);
  }

  clearList('title-list');
  for (const val of (Array.isArray(fields.title) ? fields.title : (fields.title ? [fields.title] : []))) {
    if (val) addDynamicField('title-list', 'title', t('editor.jobtitle.placeholder'), val);
  }

  clearList('url-list');
  const urls = Array.isArray(fields.url) ? fields.url : (fields.url ? [{ value: fields.url, type: 'work' }] : []);
  for (const item of urls) {
    const val  = typeof item === 'string' ? item : item.value;
    const type = typeof item === 'string' ? 'work' : (item.type || 'work');
    if (val) addDynamicField('url-list', 'url', t('editor.url.placeholder'), val, type);
  }

  clearList('adr-list');
  for (const item of (fields.adr || [])) {
    addAdrField(item);
  }

  clearList('note-list');
  for (const val of (Array.isArray(fields.note) ? fields.note : (fields.note ? [fields.note] : []))) {
    if (val) addDynamicField('note-list', 'note', t('editor.note.placeholder'), val);
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
      opt.value = val; opt.textContent = t('field.type.' + val);
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
  typeLabel.textContent = t('field.adr.type.label');
  typeLabel.style.fontSize = '13px';

  const select = document.createElement('select');
  select.className = 'dynamic-type-select';
  for (const [val] of [['home'],['work'],['other']]) {
    const opt = document.createElement('option');
    opt.value = val; opt.textContent = t('field.type.' + val);
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

  const adrSubfields = [
    ['street',   t('field.adr.street')],
    ['city',     t('field.adr.city')],
    ['region',   t('field.adr.region')],
    ['postcode', t('field.adr.postcode')],
    ['country',  t('field.adr.country')],
  ];
  for (const [cls, ph] of adrSubfields) {
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
  const label = prompt(t('dialog.create.prompt'), t('dialog.create.default'));
  if (label === null) return;
  btn.disabled    = true;
  btn.textContent = t('status.creating');
  try {
    await createCard(label.trim() || t('dialog.create.default'));
  } catch (err) {
    alert(t('alert.create.failed', { error: err.message }));
  } finally {
    btn.disabled    = false;
    btn.textContent = btn.id === 'btn-new-card' ? t('cards.btn.new') : t('setup.btn.create');
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
    go(`/editor/${id}`);
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
    status.textContent = t('status.fn.required');
    status.className   = 'status-msg error';
    return;
  }

  // Read updated card name
  const newCardName = (document.getElementById('card-name')?.value || '').trim() || card.label;

  btn.disabled       = true;
  status.textContent = t('status.publishing');
  status.className   = 'status-msg';

  try {
    const aesKey    = await importCardKey(card.key);
    const nsecBytes = hexToBytes(card.nsec);

    // Persist updated card name if changed
    if (newCardName !== card.label) {
      const cards = getCards();
      const idx   = cards.findIndex(c => c.id === activeCardId);
      if (idx >= 0) { cards[idx].label = newCardName; saveCards(cards); card.label = newCardName; }
    }

    fields.sourceUrl  = canonicalUrl(activeCardId, card.npub, card.relays);
    const vcardText   = buildVCard(fields);
    const blob        = await encryptVCard(vcardText, aesKey);

    const results = await publishCard(card.relays, nsecBytes, activeCardId, blob, card.label);

    localStorage.setItem(`e2e:fields:${activeCardId}`, JSON.stringify(fields));
    localStorage.setItem(`e2e:relay-status:${activeCardId}`, JSON.stringify(results));

    const allOk = results.every(r => r.ok);
    const okCount = results.filter(r => r.ok).length;
    status.textContent = allOk
      ? t('status.published.all',     { ok: okCount, total: results.length })
      : t('status.published.partial', { ok: okCount, total: results.length });
    status.className = allOk ? 'status-msg success' : 'status-msg';

    // Update relay badges in card list (if shown)
    setTimeout(() => { status.textContent = ''; }, 4000);
  } catch (err) {
    status.textContent = t('status.publish.failed', { error: err.message });
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

  if (!confirm(t('dialog.delete.confirm', { label: card.label }))) return;

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

  go(remaining.length === 0 ? '/setup' : '/cards');
});

// ---------------------------------------------------------------------------
// Key rotation
// ---------------------------------------------------------------------------

document.getElementById('btn-rotate-key').addEventListener('click', async () => {
  if (!activeCardId) return;
  const card = getCard(activeCardId);
  if (!card) return;

  if (!confirm(
    t('dialog.rotate.confirm', { label: card.label })
  )) return;

  const btn    = document.getElementById('btn-rotate-key');
  const status = document.getElementById('save-status');
  btn.disabled       = true;
  status.textContent = t('status.rotating');
  status.className   = 'status-msg';

  try {
    // Generate a fresh AES key
    const newAesKey  = await generateKey();
    const newKeyFrag = await keyToFragment(newAesKey);

    // Re-encrypt the current cached fields with the new key
    const nsecBytes  = hexToBytes(card.nsec);
    const fields     = (() => {
      try { return JSON.parse(localStorage.getItem(`e2e:fields:${activeCardId}`) || 'null'); } catch { return null; }
    })();

    if (!fields) {
      status.textContent = 'No cached fields — save the card first before rotating the key.';
      status.className   = 'status-msg error';
      return;
    }

    fields.sourceUrl = canonicalUrl(activeCardId, card.npub, card.relays);
    const vcardText  = buildVCard(fields);
    const blob       = await encryptVCard(vcardText, newAesKey);

    // Re-publish with the same d-tag (NIP-33 replaces the old event on relays)
    const results = await publishCard(card.relays, nsecBytes, activeCardId, blob, card.label);
    localStorage.setItem(`e2e:relay-status:${activeCardId}`, JSON.stringify(results));

    // Persist the new key; invalidate any stored recipient trust (stale sessions)
    const cards = getCards();
    const idx   = cards.findIndex(c => c.id === activeCardId);
    if (idx >= 0) { cards[idx].key = newKeyFrag; saveCards(cards); }
    localStorage.removeItem(`e2e:trusted:${activeCardId}`); // legacy key format
    localStorage.removeItem(`e2e:trusted:${card.npub}:${activeCardId}`);

    const allOk   = results.every(r => r.ok);
    const okCount = results.filter(r => r.ok).length;
    status.textContent = allOk
      ? `Key rotated ✓ (${okCount}/${results.length} relays) — old links are now invalid`
      : `Key rotated on ${okCount}/${results.length} relays — old links are now invalid`;
    status.className = allOk ? 'status-msg success' : 'status-msg';

    // Open share modal so the owner can immediately copy the new link
    openShareModal({ ...card, key: newKeyFrag });

    setTimeout(() => { status.textContent = ''; }, 6000);
  } catch (err) {
    status.textContent = 'Key rotation failed: ' + err.message;
    status.className   = 'status-msg error';
  } finally {
    btn.disabled = false;
  }
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
  const dlUrl    = buildDownloadUrl(card);

  document.getElementById('share-label').textContent = card.label;
  document.getElementById('share-url').value         = shareUrl;
  document.getElementById('dl-url').value            = dlUrl;
  document.getElementById('modal-share').classList.remove('hidden');

  const qrContainer = document.getElementById('qr-container');
  qrContainer.innerHTML = '';
  renderQR(qrContainer, shareUrl);
}

document.getElementById('btn-copy-url').addEventListener('click', async () => {
  const url = document.getElementById('share-url').value;
  try { await navigator.clipboard.writeText(url); } catch { /* fallback: select */ }
  const btn = document.getElementById('btn-copy-url');
  btn.textContent = t('btn.copied');
  setTimeout(() => { btn.textContent = t('btn.copy'); }, 2000);
});

document.getElementById('btn-copy-dl-url').addEventListener('click', async () => {
  const url = document.getElementById('dl-url').value;
  try { await navigator.clipboard.writeText(url); } catch { /* fallback: select */ }
  const btn = document.getElementById('btn-copy-dl-url');
  btn.textContent = t('btn.copied');
  setTimeout(() => { btn.textContent = t('btn.copy'); }, 2000);
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

document.getElementById('btn-verify-privacy').addEventListener('click', (e) => {
  if (!activeCardId) return;
  const card = getCard(activeCardId);
  if (!card) return;
  const proofUrl = `proof.html?url=${encodeURIComponent(buildShareUrl(card))}`;
  e.currentTarget.href = proofUrl;
});

document.getElementById('cv-btn-back').addEventListener('click', () => {
  go(activeCardId ? `/editor/${activeCardId}` : cvReturnRoute);
});

document.getElementById('cv-btn-back-error').addEventListener('click', () => {
  go(activeCardId ? `/editor/${activeCardId}` : cvReturnRoute);
});

async function showCardViewScreen(url, mode) {
  showScreen('screen-card-view');

  // Reset inline viewer state
  document.getElementById('cv-screen-loading').classList.remove('hidden');
  document.getElementById('cv-screen-trust').classList.add('hidden');
  document.getElementById('cv-screen-error').classList.add('hidden');
  document.getElementById('cv-screen-card').classList.add('hidden');
  document.getElementById('cv-contact-fields').innerHTML = '';
  document.getElementById('cv-contact-avatar').textContent = '';
  document.getElementById('cv-contact-fn').textContent     = '';
  document.getElementById('cv-public-mode-banner').classList.add('hidden');
  document.getElementById('cv-btn-done').classList.add('hidden');
  document.getElementById('cv-btn-save-link').classList.add('hidden');
  document.getElementById('cv-btn-download').style.display = '';

  // Parse url
  const urlObj  = new URL(url);
  const naddr   = urlObj.searchParams.get('naddr');
  const fragment = urlObj.hash.slice(1);

  if (!naddr || !fragment) {
    showCvError(t('error.invalidLink.title'), t('error.invalidLink.missingParams'));
    return;
  }

  let decoded;
  try { decoded = naddrDecode(naddr); } catch {
    showCvError(t('error.invalidLink.title'), t('error.invalidLink.malformedNaddr'));
    return;
  }

  const { pubkey, identifier: cardId, relays } = decoded;

  let aesKey;
  try { aesKey = await fragmentToKey(fragment); } catch {
    showCvError(t('error.invalidKey.title'), t('error.invalidKey.detail'));
    return;
  }

  let event;
  try { event = await fetchCard(relays, pubkey, cardId); } catch {
    showCvError(t('error.network.title'), t('error.network.detail'));
    return;
  }
  if (!event) {
    showCvError(t('error.notFound.title'), t('error.notFound.detail'));
    return;
  }

  let vcardText;
  try { vcardText = await decryptVCard(event.content, aesKey); } catch {
    showCvError(t('error.decrypt.title'), t('error.decrypt.detail'));
    return;
  }

  const fields = parseVCard(vcardText);

  if (mode === 'owner-preview') {
    renderCvCard(fields, vcardText, true, true);
  } else {
    // Trust keyed by pubkey:cardId — see card.js
    showCvTrustGate(`${pubkey}:${cardId}`, fields, vcardText, url);
  }
}

function showCvError(title, detail) {
  document.getElementById('cv-screen-loading').classList.add('hidden');
  document.getElementById('cv-error-title').textContent  = title;
  document.getElementById('cv-error-detail').textContent = detail;
  document.getElementById('cv-screen-error').classList.remove('hidden');
}

const TRUST_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function getCvTrust(trustId) {
  try {
    const raw = localStorage.getItem(`e2e:trusted:${trustId}`);
    if (!raw) return false;
    const data = JSON.parse(raw);
    if (!data?.ok || Date.now() > data.expires) { localStorage.removeItem(`e2e:trusted:${trustId}`); return false; }
    return true;
  } catch { return false; }
}

function setCvTrust(trustId) {
  try {
    localStorage.setItem(`e2e:trusted:${trustId}`, JSON.stringify({ ok: true, expires: Date.now() + TRUST_TTL_MS }));
  } catch {}
}

function showCvTrustGate(trustId, fields, vcardText, shareUrl) {
  if (getCvTrust(trustId)) {
    autoSaveLink(shareUrl, fields.fn);
    renderCvCard(fields, vcardText, true, false);
    return;
  }
  document.getElementById('cv-screen-loading').classList.add('hidden');
  document.getElementById('cv-screen-trust').classList.remove('hidden');

  document.getElementById('cv-btn-trusted').onclick = () => {
    setCvTrust(trustId);
    autoSaveLink(shareUrl, fields.fn);
    document.getElementById('cv-screen-trust').classList.add('hidden');
    renderCvCard(fields, vcardText, true, false);
  };
  document.getElementById('cv-btn-public').onclick = () => {
    document.getElementById('cv-screen-trust').classList.add('hidden');
    renderCvCard(fields, vcardText, false, false);
  };
}

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

function autoSaveLink(url, label) {
  const SAVED_KEY = 'e2e:saved-links';
  let links = [];
  try { links = JSON.parse(localStorage.getItem(SAVED_KEY) || '[]'); } catch {}
  const idx = links.findIndex(l => sameSharedCardUrl(l.url, url));
  if (idx >= 0) {
    // Same card, possibly re-shared with a new key/relay — keep the freshest link, don't duplicate
    links[idx] = { ...links[idx], url, label: label || links[idx].label };
  } else {
    links.push({ url, label: label || 'Contact', savedAt: new Date().toISOString() });
  }
  try { localStorage.setItem(SAVED_KEY, JSON.stringify(links)); } catch {}
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
  if (subtitleEl) {
    subtitleEl.textContent    = subtitle;
    subtitleEl.style.display  = subtitle ? '' : 'none';
  }

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
    saveLinkBtn.textContent = t('cv.btn.save.link.done');
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
      countdownEl.textContent = t('cv.countdown', { m, ss: String(s).padStart(2,'0') });
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
    const msgs = { manual: t('cv.kill.manual'), download: t('cv.kill.download'), 'tab-hidden': t('cv.kill.tab'), timeout: t('cv.kill.timeout') };
    section.innerHTML = `<div class="card-panel centered"><div style="font-size:3rem">🔒</div><h2>${htmlEscape(msgs[reason] || t('cv.kill.manual'))}</h2><p class="muted">${htmlEscape(t('cv.kill.detail'))}</p></div>`;
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
    errEl.textContent = t('relay.error.invalid');
    errEl.classList.remove('hidden');
    return;
  }

  if (!activeCardId) return;
  const cards = getCards();
  const idx   = cards.findIndex(c => c.id === activeCardId);
  if (idx < 0) return;

  if (cards[idx].relays.includes(url)) {
    errEl.textContent = t('relay.error.duplicate');
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
        alert(t('relay.error.minimum'));
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
  go('/cards');
});

document.getElementById('btn-back-to-cards').addEventListener('click', () => {
  go('/cards');
});

document.getElementById('btn-go-saved').addEventListener('click', () => {
  go('/saved');
});

document.getElementById('btn-go-saved-setup').addEventListener('click', () => {
  go('/saved');
});

document.getElementById('btn-clear-all').addEventListener('click', () => {
  if (!confirm(t('dialog.logout.confirm'))) return;
  const cards = getCards();
  for (const c of cards) {
    localStorage.removeItem(`e2e:fields:${c.id}`);
    localStorage.removeItem(`e2e:relay-status:${c.id}`);
  }
  for (const c of getConnections()) {
    localStorage.removeItem(`e2e:connection-fields:${c.id}`);
  }
  localStorage.removeItem('e2e:cards');
  localStorage.removeItem('e2e:saved-links');
  localStorage.removeItem('e2e:connections');
  clearSyncIdentity();
  activeCardId = null;
  location.reload();
});

// ---------------------------------------------------------------------------
// Advanced menu (Sync, Backup, Restore, Log out)
// ---------------------------------------------------------------------------

function openAdvancedModal() {
  document.getElementById('modal-advanced').classList.remove('hidden');
}

document.getElementById('btn-advanced-setup').addEventListener('click', openAdvancedModal);
document.getElementById('btn-advanced-cards').addEventListener('click', openAdvancedModal);
document.getElementById('btn-advanced-saved').addEventListener('click', openAdvancedModal);

document.getElementById('btn-advanced-close').addEventListener('click', () => {
  document.getElementById('modal-advanced').classList.add('hidden');
});

document.getElementById('modal-advanced').addEventListener('click', e => {
  if (e.target === e.currentTarget) e.currentTarget.classList.add('hidden');
});

// ---------------------------------------------------------------------------
// Contacts screen — merged view of paired connections and plain saved links.
// Storage stays separate (e2e:connections / e2e:saved-links); a saved link
// pointing at an already-paired card is hidden so each contact appears once.
// ---------------------------------------------------------------------------

function renderSavedLinks() {
  const connections = getConnections();
  const links       = getSavedLinks();
  const container   = document.getElementById('saved-links-list');
  container.innerHTML = '';

  // Paired entry wins over a plain saved link for the same card
  const unpairedLinks = links.filter(link => {
    const naddr = extractNaddrFromUrl(link.url);
    return !naddr || !connections.some(c => sameCardAddress(c.peerNaddr, naddr));
  });

  if (connections.length === 0 && unpairedLinks.length === 0) {
    container.innerHTML = `<p class="muted">${htmlEscape(t('saved.empty'))}</p>`;
    return;
  }

  for (const conn of connections) renderConnectionRow(container, conn);

  for (const link of unpairedLinks) {
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
    openBtn.textContent = t('btn.open');
    openBtn.addEventListener('click', () => { cvReturnRoute = '/saved'; showCardViewScreen(link.url, 'saved-card'); });

    const removeBtn = document.createElement('button');
    removeBtn.className   = 'btn btn-danger btn-sm';
    removeBtn.textContent = t('btn.remove');
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

  // Re-fetch each peer's card in the background so paired entries stay current
  if (connections.length > 0) refreshConnections(connections);
}

// ---------------------------------------------------------------------------
// Connections (mutual in-person pairing)
// ---------------------------------------------------------------------------

document.getElementById('btn-connections-new').addEventListener('click', () => go('/pair'));

function renderConnectionRow(container, conn) {
  const cached = getConnectionFields(conn.id);

  const row = document.createElement('div');
  row.className = 'card-list-row';
  row.dataset.connId = conn.id;
  row.innerHTML = `
    <div class="card-list-info">
      <span class="card-list-name">${htmlEscape(conn.peerLabel || 'Connection')} <span class="relay-badge relay-badge--ok" title="${htmlEscape(t('contacts.badge.paired.title'))}">${htmlEscape(t('contacts.badge.paired'))}</span></span>
      <span class="card-list-meta conn-meta">${htmlEscape(cached?.fn || t('connections.notYetFetched'))}</span>
    </div>
    <div class="card-list-actions">
      <button class="btn btn-primary btn-sm btn-conn-view">${htmlEscape(t('btn.open'))}</button>
      <button class="btn btn-danger  btn-sm btn-conn-remove">${htmlEscape(t('btn.remove'))}</button>
    </div>
  `;
  row.querySelector('.btn-conn-view').addEventListener('click', () => viewConnection(conn));
  row.querySelector('.btn-conn-remove').addEventListener('click', () => removeConnection(conn.id));
  container.appendChild(row);
}

async function refreshConnections(connections) {
  for (const conn of connections) {
    try {
      const decoded   = naddrDecode(conn.peerNaddr);
      const event     = await fetchCard(decoded.relays, decoded.pubkey, decoded.identifier);
      if (!event) continue;
      const aesKey    = await fragmentToKey(conn.peerKey);
      const vcardText = await decryptVCard(event.content, aesKey);
      const fields    = parseVCard(vcardText);
      saveConnectionFields(conn.id, fields);

      const metaEl = document.querySelector(`.card-list-row[data-conn-id="${conn.id}"] .conn-meta`);
      if (metaEl) metaEl.textContent = fields.fn || '';
    } catch (err) {
      console.warn('[app] connection refresh failed (non-fatal):', err.message);
    }
  }
}

function viewConnection(conn) {
  const url = `${location.origin}/card?naddr=${encodeURIComponent(conn.peerNaddr)}#${encodeURIComponent(conn.peerKey)}`;
  cvReturnRoute = '/saved';
  showCardViewScreen(url, 'owner-preview');
}

function removeConnection(id) {
  if (!confirm(t('dialog.connection.remove.confirm'))) return;
  saveConnections(getConnections().filter(c => c.id !== id));
  localStorage.removeItem(`e2e:connection-fields:${id}`);
  renderSavedLinks();
}

/** Render a compact list of the user's own cards with a "use this card" action */
function renderCardPicker(container, onPick) {
  const cards = getCards();
  container.innerHTML = '';
  if (cards.length === 0) {
    container.innerHTML = `<p class="muted">${htmlEscape(t('cards.empty'))}</p>`;
    return;
  }
  for (const card of cards) {
    const row = document.createElement('div');
    row.className = 'card-list-row';
    row.innerHTML = `
      <div class="card-list-info"><span class="card-list-name">${htmlEscape(card.label)}</span></div>
      <div class="card-list-actions"><button class="btn btn-primary btn-sm">${htmlEscape(t('pair.btn.useCard'))}</button></div>
    `;
    row.querySelector('button').addEventListener('click', () => onPick(card));
    container.appendChild(row);
  }
}

// ---------------------------------------------------------------------------
// Pairing — initiate (generate QR/link, poll for the peer's response)
// ---------------------------------------------------------------------------

/** Add a connection, or update the existing one if this peer card is already paired (dedupes by card identity, not exact naddr string — a relay-list edit or re-pairing shouldn't create a duplicate) */
function upsertConnection(peerPayload, myCardId) {
  const connections = getConnections();
  const peerLabel = String(peerPayload.label || 'Connection').slice(0, 100);
  const idx = connections.findIndex(c => sameCardAddress(c.peerNaddr, peerPayload.naddr));
  if (idx >= 0) {
    connections[idx] = {
      ...connections[idx],
      peerLabel: peerLabel,
      peerNaddr: peerPayload.naddr,
      peerKey:   peerPayload.key,
    };
    saveConnections(connections);
    return connections[idx];
  }

  const conn = {
    id:        generateRandom(8),
    peerLabel,
    peerNaddr: peerPayload.naddr,
    peerKey:   peerPayload.key,
    myCardId,
    pairedAt:  new Date().toISOString(),
  };
  connections.push(conn);
  saveConnections(connections);
  return conn;
}

/**
 * Validate a peer pairing payload before trusting it: the naddr must decode to a
 * card-kind address and the key must be exactly 32 base64url bytes — rejects
 * crafted payloads that could smuggle extra URL parameters or junk into storage.
 */
function isValidPeerPayload(p) {
  if (!p || typeof p.naddr !== 'string' || typeof p.key !== 'string') return false;
  if (!/^[A-Za-z0-9_-]{43}$/.test(p.key)) return false;
  try { return naddrDecode(p.naddr).kind === CARD_KIND; } catch { return false; }
}

/**
 * Verify a card is actually retrievable from its relays before handing its
 * address out to a pairing peer — a card that only ever exists locally
 * (e.g. publish silently failed on every relay at creation time) would
 * otherwise pair "successfully" but show "Card not found" for the other side.
 * Attempts one republish from cached fields if the relay fetch comes up empty.
 * @returns {Promise<boolean>}
 */
async function ensureCardPublished(card) {
  try {
    const event = await fetchCard(card.relays, card.npub, card.id);
    if (event) return true;
  } catch { /* fall through to republish attempt */ }

  const cachedRaw = localStorage.getItem(`e2e:fields:${card.id}`);
  if (!cachedRaw) return false;

  try {
    const fields    = JSON.parse(cachedRaw);
    fields.sourceUrl = canonicalUrl(card.id, card.npub, card.relays);
    const aesKey    = await importCardKey(card.key);
    const nsecBytes = hexToBytes(card.nsec);
    const vcardText = buildVCard(fields);
    const blob      = await encryptVCard(vcardText, aesKey);
    const results   = await publishCard(card.relays, nsecBytes, card.id, blob, card.label);
    localStorage.setItem(`e2e:relay-status:${card.id}`, JSON.stringify(results));
    return results.some(r => r.ok);
  } catch {
    return false;
  }
}

let pairStartState = null; // { pairNsec, pollInterval, countdownInterval, fetching, completing }

function showPairStart() {
  activeCardId = null;
  showScreen('screen-pair-start');
  stopPairStartPolling();
  document.getElementById('pair-start-pick').classList.remove('hidden');
  document.getElementById('pair-start-active').classList.add('hidden');
  document.getElementById('pair-start-expired').classList.add('hidden');
  document.getElementById('pair-start-status').textContent = '';
  renderCardPicker(document.getElementById('pair-start-card-list'), card => beginPairStart(card));
}

function stopPairStartPolling() {
  if (pairStartState) {
    clearInterval(pairStartState.pollInterval);
    clearInterval(pairStartState.countdownInterval);
    pairStartState = null;
  }
}

async function beginPairStart(card) {
  document.getElementById('pair-start-pick').classList.add('hidden');
  document.getElementById('pair-start-active').classList.remove('hidden');
  const statusEl = document.getElementById('pair-start-status');
  statusEl.textContent = t('pair.start.checking');
  statusEl.className   = 'status-msg';

  const published = await ensureCardPublished(card);
  if (!published) {
    statusEl.textContent = t('pair.card.unpublished');
    statusEl.className   = 'status-msg error';
    document.getElementById('pair-start-active').classList.add('hidden');
    document.getElementById('pair-start-pick').classList.remove('hidden');
    return;
  }
  statusEl.textContent = '';

  const code = generatePairingCode();
  const { pairNsec, pairNpub, pairKeyRaw } = await derivePairingIdentity(code);

  const payload = { naddr: naddrEncode(card.npub, card.id, card.relays), key: card.key, label: card.label };
  try {
    await publishPairingPayload(DEFAULT_RELAYS, pairNsec, pairKeyRaw, 'a', payload);
  } catch (err) {
    statusEl.textContent = t('pair.start.publish.failed', { error: err.message });
    statusEl.className   = 'status-msg error';
    return;
  }

  const link = `${location.origin}${location.pathname}#/pair-join/${code}`;
  document.getElementById('pair-start-link').value = link;
  const qrContainer = document.getElementById('pair-start-qr');
  qrContainer.innerHTML = '';
  renderQR(qrContainer, link);

  // Own state object, captured by both intervals below — protects against a
  // slow in-flight fetch overlapping with the next tick (which would otherwise
  // create duplicate connections), and against a stale interval from a
  // previously-regenerated code still resolving after this one replaced it.
  const myState = { pairNsec, pollInterval: null, countdownInterval: null, fetching: false, completing: false };

  const killAt = Date.now() + PAIR_TTL_MS;
  const countdownEl = document.getElementById('pair-start-countdown');
  myState.countdownInterval = setInterval(() => {
    const remaining = Math.max(0, killAt - Date.now());
    if (remaining <= 0) { onPairStartExpired(); return; }
    const m = Math.floor(remaining / 60000), s = Math.floor((remaining % 60000) / 1000);
    countdownEl.textContent = t('pair.countdown', { m, ss: String(s).padStart(2, '0') });
  }, 1000);

  myState.pollInterval = setInterval(async () => {
    if (pairStartState !== myState || myState.fetching || myState.completing) return;
    myState.fetching = true;
    try {
      const found = await fetchPairingPayload(DEFAULT_RELAYS, pairNpub, pairKeyRaw, 'b');
      if (found && pairStartState === myState && !myState.completing) {
        if (!isValidPeerPayload(found.payload)) {
          console.warn('[app] rejected malformed pairing response');
          return;
        }
        myState.completing = true;
        // Anyone holding the code can write slot b — an explicit accept makes a
        // hijacked handshake visible instead of silently stored.
        const label = String(found.payload.label || 'Connection').slice(0, 100);
        if (confirm(t('dialog.pair.accept.confirm', { label }))) {
          await completePairStart(pairNsec, found.payload, card.id);
        } else {
          stopPairStartPolling();
          try { await cleanupPairing(DEFAULT_RELAYS, pairNsec); } catch { /* best-effort */ }
          showPairStart();
        }
      }
    } catch (err) {
      console.warn('[app] pairing poll error (non-fatal):', err.message);
    } finally {
      myState.fetching = false;
    }
  }, 3000);

  pairStartState = myState;
}

function onPairStartExpired() {
  stopPairStartPolling();
  document.getElementById('pair-start-active').classList.add('hidden');
  document.getElementById('pair-start-expired').classList.remove('hidden');
}

async function completePairStart(pairNsec, peerPayload, myCardId) {
  stopPairStartPolling();

  upsertConnection(peerPayload, myCardId);

  try { await cleanupPairing(DEFAULT_RELAYS, pairNsec); } catch { /* best-effort */ }

  go('/saved');
}

document.getElementById('btn-pair-start-cancel').addEventListener('click', async () => {
  if (pairStartState) {
    const { pairNsec } = pairStartState;
    stopPairStartPolling();
    try { await cleanupPairing(DEFAULT_RELAYS, pairNsec); } catch { /* best-effort */ }
  }
  go('/saved');
});

document.getElementById('btn-pair-start-copy').addEventListener('click', async () => {
  const value = document.getElementById('pair-start-link').value;
  try { await navigator.clipboard.writeText(value); } catch { /* fallback: select */ }
  const btn = document.getElementById('btn-pair-start-copy');
  btn.textContent = t('btn.copied');
  setTimeout(() => { btn.textContent = t('btn.copy'); }, 2000);
});

document.getElementById('btn-pair-start-regenerate').addEventListener('click', () => showPairStart());

// ---------------------------------------------------------------------------
// Pairing — join (scanned the QR/opened the link)
// ---------------------------------------------------------------------------

async function showPairJoin(code) {
  activeCardId = null;
  showScreen('screen-pair-join');
  document.getElementById('pair-join-loading').classList.remove('hidden');
  document.getElementById('pair-join-found').classList.add('hidden');
  document.getElementById('pair-join-success').classList.add('hidden');
  document.getElementById('pair-join-nocards').classList.add('hidden');
  document.getElementById('pair-join-error').classList.add('hidden');

  // The code is a channel secret — remove it from the address bar and history
  // as soon as it's been captured (same hygiene as the #key fragment in card.js)
  history.replaceState(null, '', location.pathname + '#/saved');

  if (!/^[a-zA-Z0-9]+$/.test(code)) {
    return showPairJoinError(t('pair.join.error.badCode'));
  }

  let identity, offer;
  try {
    identity = await derivePairingIdentity(code);
    offer    = await fetchPairingPayload(DEFAULT_RELAYS, identity.pairNpub, identity.pairKeyRaw, 'a');
  } catch {
    return showPairJoinError(t('pair.join.error.detail'));
  }
  if (!offer || !isValidPeerPayload(offer.payload)) return showPairJoinError(t('pair.join.error.detail'));

  document.getElementById('pair-join-loading').classList.add('hidden');

  if (getCards().length === 0) {
    document.getElementById('pair-join-nocards').classList.remove('hidden');
    document.getElementById('btn-pair-join-create-card').onclick = () => go('/cards');
    return;
  }

  document.getElementById('pair-join-found').classList.remove('hidden');
  document.getElementById('pair-join-found-body').textContent = t('pair.join.found', { label: offer.payload.label || 'Connection' });
  renderCardPicker(document.getElementById('pair-join-card-list'), card => {
    // Hide immediately so a double-click/tap can't submit two publishes and duplicate the connection
    document.getElementById('pair-join-found').classList.add('hidden');
    confirmPairJoin(identity, offer.payload, card);
  });
}

function showPairJoinError(detail) {
  document.getElementById('pair-join-loading').classList.add('hidden');
  document.getElementById('pair-join-error-detail').textContent = detail;
  document.getElementById('pair-join-error').classList.remove('hidden');
}

async function confirmPairJoin(identity, peerPayload, myCard) {
  document.getElementById('pair-join-loading').classList.remove('hidden');

  const published = await ensureCardPublished(myCard);
  if (!published) {
    document.getElementById('pair-join-loading').classList.add('hidden');
    showPairJoinError(t('pair.card.unpublished'));
    return;
  }

  const myPayload = { naddr: naddrEncode(myCard.npub, myCard.id, myCard.relays), key: myCard.key, label: myCard.label };
  try {
    await publishPairingPayload(DEFAULT_RELAYS, identity.pairNsec, identity.pairKeyRaw, 'b', myPayload);
  } catch {
    document.getElementById('pair-join-loading').classList.add('hidden');
    showPairJoinError(t('pair.join.error.detail'));
    return;
  }

  upsertConnection(peerPayload, myCard.id);

  document.getElementById('pair-join-loading').classList.add('hidden');
  document.getElementById('pair-join-success-heading').textContent = t('pair.join.success', { label: peerPayload.label || 'Connection' });
  document.getElementById('pair-join-success').classList.remove('hidden');
}

document.getElementById('btn-pair-join-done').addEventListener('click', () => go('/saved'));

// ---------------------------------------------------------------------------
// Backup & Restore
// ---------------------------------------------------------------------------

document.getElementById('btn-backup').addEventListener('click', exportBackup);

function exportBackup() {
  const cards       = getCards();
  const savedLinks  = getSavedLinks();
  const connections = getConnections();
  const fields      = {};
  for (const card of cards) {
    const cached = localStorage.getItem(`e2e:fields:${card.id}`);
    if (cached) { try { fields[card.id] = JSON.parse(cached); } catch {} }
  }
  const backup = {
    version:  3,
    exported: new Date().toISOString(),
    cards,       // includes nsec (raw hex) — keep the file secure
    savedLinks,
    connections, // includes peerKey (AES key) — keep the file secure
    fields,
  };
  downloadJson(backup, `nostr-vcard-backup-${backup.exported.slice(0, 10)}.json`);
  for (const card of cards) localStorage.setItem(`e2e:exported:${card.id}`, '1');
}

function downloadJson(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// File restore (Advanced menu)
document.getElementById('restore-file-input').addEventListener('change', async e => {
  const file = e.target.files[0];
  if (!file) return;
  try { await importBackup(JSON.parse(await file.text())); } catch { alert(t('alert.backup.error')); }
  e.target.value = '';
});

// Paste restore (Advanced menu)
document.getElementById('btn-paste-restore').addEventListener('click', () => {
  document.getElementById('modal-advanced').classList.add('hidden');
  document.getElementById('modal-restore').classList.remove('hidden');
});

document.getElementById('btn-restore-paste-confirm').addEventListener('click', async () => {
  const raw = document.getElementById('restore-paste-input').value.trim();
  try {
    await importBackup(JSON.parse(raw));
    document.getElementById('modal-restore').classList.add('hidden');
    document.getElementById('restore-paste-input').value = '';
  } catch {
    alert(t('alert.json.error'));
  }
});

document.getElementById('btn-restore-paste-cancel').addEventListener('click', () => {
  document.getElementById('modal-restore').classList.add('hidden');
});

async function importBackup(json, { navigate = true } = {}) {
  let cardPayloads = [], linkPayloads = [], fieldsMap = {}, connectionPayloads = [];

  if (json?.version === 3 && Array.isArray(json.cards)) {
    // v3 — nostr-vcard native backup (adds connections)
    cardPayloads       = json.cards;
    linkPayloads       = Array.isArray(json.savedLinks) ? json.savedLinks : [];
    fieldsMap          = (json.fields && typeof json.fields === 'object') ? json.fields : {};
    connectionPayloads = Array.isArray(json.connections) ? json.connections : [];
  } else if (json?.version === 2 && Array.isArray(json.cards)) {
    // v2 — nostr-vcard native backup
    cardPayloads = json.cards;
    linkPayloads = Array.isArray(json.savedLinks) ? json.savedLinks : [];
    fieldsMap    = (json.fields && typeof json.fields === 'object') ? json.fields : {};
  } else if (json?.version === 1 && Array.isArray(json.cards)) {
    // v1 — legacy Cloudflare app backup; cards have ownerToken, no nsec/npub
    // We import fields + AES keys and generate fresh Nostr keypairs
    if (confirm(t('dialog.v1import.confirm'))) {
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
      alert(t('alert.import.v1', { n: imported, s: imported !== 1 ? 's' : '' }));
    }
    linkPayloads = Array.isArray(json.savedLinks) ? json.savedLinks : [];
  } else if (Array.isArray(json)) {
    cardPayloads = json;
  } else if (json?.id && json?.nsec && json?.key) {
    cardPayloads = [json];
  } else {
    alert(t('alert.unknown.format'));
    return;
  }

  const existingIds = new Set(getCards().map(c => c.id));
  let added = 0, skipped = 0, failed = 0;

  for (const payload of cardPayloads) {
    if (!payload?.id || !payload?.nsec || !payload?.key) { failed++; continue; }
    if (existingIds.has(payload.id)) { skipped++; continue; }

    // Validate nsec looks like 64-char hex
    if (!/^[0-9a-f]{64}$/i.test(payload.nsec)) { failed++; continue; }

    // Derive npub from nsec — never trust the value stored in the file
    let npub;
    try { npub = derivePublicKey(hexToBytes(payload.nsec)); } catch { failed++; continue; }

    // Keep only valid wss:// relay URLs; fall back to defaults
    const validRelays = Array.isArray(payload.relays) ? payload.relays.filter(isValidRelayUrl) : [];
    const relayList   = validRelays.length > 0 ? validRelays : [...DEFAULT_RELAYS];

    // Verify card exists on relays
    let found = false;
    try {
      const event = await fetchCard(relayList, npub, payload.id);
      found = !!event;
    } catch {}

    const cards = getCards();
    cards.push({
      id:     payload.id,
      label:  payload.label || 'Restored Card',
      nsec:   payload.nsec,
      npub,
      key:    payload.key,
      relays: relayList,
    });
    saveCards(cards);
    existingIds.add(payload.id);

    if (fieldsMap[payload.id]) {
      localStorage.setItem(`e2e:fields:${payload.id}`, JSON.stringify(fieldsMap[payload.id]));
    }

    if (!found) {
      // Card not on relay — offer re-publish if we have fields
      if (fieldsMap[payload.id]) {
        const shouldRepublish = confirm(t('dialog.republish.confirm', { label: payload.label || payload.id }));
        if (shouldRepublish) {
          try {
            const aesKey    = await importCardKey(payload.key);
            const nsecBytes = hexToBytes(payload.nsec);
            const fields    = fieldsMap[payload.id];
            const vcardText = buildVCard(fields);
            const blob      = await encryptVCard(vcardText, aesKey);
            const results   = await publishCard(relayList, nsecBytes, payload.id, blob, payload.label);
            localStorage.setItem(`e2e:relay-status:${payload.id}`, JSON.stringify(results));
          } catch {}
        }
      }
    }

    added++;
  }

  // Merge saved links (dedupe by card identity, not exact URL string)
  const existingLinks = getSavedLinks();
  let linksAdded = 0;
  for (const item of linkPayloads) {
    if (!item?.url?.trim()) continue;
    if (existingLinks.some(l => sameSharedCardUrl(l.url, item.url))) continue;
    // Reject arbitrary-scheme injection; http:// only allowed on localhost (dev)
    if (!isSafeLinkUrl(item.url)) continue;
    existingLinks.push({ url: item.url, label: item.label || 'Contact', savedAt: item.savedAt || new Date().toISOString() });
    linksAdded++;
  }
  saveSavedLinks(existingLinks);

  // Merge connections (dedupe by card identity, not local id — same peer paired
  // from another device shouldn't produce a second entry)
  const existingConnections = getConnections();
  const existingConnIds     = new Set(existingConnections.map(c => c.id));
  let connsAdded = 0;
  for (const item of connectionPayloads) {
    if (!item?.id) continue;
    if (!isValidPeerPayload({ naddr: item.peerNaddr, key: item.peerKey })) continue;
    if (existingConnIds.has(item.id)) continue;
    if (existingConnections.some(c => sameCardAddress(c.peerNaddr, item.peerNaddr))) continue;
    existingConnections.push({
      id:        item.id,
      peerLabel: String(item.peerLabel || 'Connection').slice(0, 100),
      peerNaddr: item.peerNaddr,
      peerKey:   item.peerKey,
      myCardId:  item.myCardId || null,
      pairedAt:  item.pairedAt || new Date().toISOString(),
    });
    existingConnIds.add(item.id);
    connsAdded++;
  }
  saveConnections(existingConnections);

  // Restore field cache
  for (const [id, fieldData] of Object.entries(fieldsMap)) {
    if (!localStorage.getItem(`e2e:fields:${id}`)) {
      localStorage.setItem(`e2e:fields:${id}`, JSON.stringify(fieldData));
    }
  }

  const linksPart = linksAdded > 0 ? t('alert.links.imported', { n: linksAdded, s: linksAdded !== 1 ? 's' : '' }) : '';
  const connsPart = connsAdded > 0 ? t('alert.connections.imported', { n: connsAdded, s: connsAdded !== 1 ? 's' : '' }) : '';
  alert(t('alert.restore.done', { added, s: added !== 1 ? 's' : '', skipped, failed, links: linksPart + connsPart }));

  // Sync pulls stay on the current screen (e.g. Saved Cards) instead of jumping to My Cards
  if (!navigate) return;

  const cards = getCards();
  go(cards.length > 0 ? '/cards' : '/setup');
}

// ---------------------------------------------------------------------------
// Sync (cross-device, via passphrase-derived Nostr identity)
// ---------------------------------------------------------------------------

function buildSyncPayload() {
  const cards       = getCards();
  const savedLinks  = getSavedLinks();
  const connections = getConnections();
  const fields      = {};
  for (const card of cards) {
    const cached = localStorage.getItem(`e2e:fields:${card.id}`);
    if (cached) { try { fields[card.id] = JSON.parse(cached); } catch {} }
  }
  return { version: 3, exported: new Date().toISOString(), cards, savedLinks, connections, fields };
}

/** Re-render whichever list screen (My Cards / Contacts) is currently visible, without navigating */
function refreshVisibleList() {
  const screenCards = document.getElementById('screen-cards');
  const screenSaved = document.getElementById('screen-saved');
  if (screenCards && !screenCards.classList.contains('hidden')) renderCardList();
  if (screenSaved && !screenSaved.classList.contains('hidden')) renderSavedLinks();
}

function setSyncStatus(msg, isError) {
  const el = document.getElementById('sync-status');
  el.textContent = msg;
  el.className   = isError ? 'status-msg error' : 'status-msg success';
}

function openSyncModal() {
  const identity = getSyncIdentity();
  document.getElementById('sync-setup-section').classList.toggle('hidden', !!identity);
  document.getElementById('sync-passphrase-reveal').classList.add('hidden');
  document.getElementById('sync-manage-section').classList.toggle('hidden', !identity);
  if (identity) {
    const meta = getSyncMeta();
    const parts = [];
    if (meta.lastPushedAt) parts.push(t('sync.status.lastPushed', { time: new Date(meta.lastPushedAt).toLocaleString() }));
    if (meta.lastPulledAt) parts.push(t('sync.status.lastPulled', { time: new Date(meta.lastPulledAt).toLocaleString() }));
    document.getElementById('sync-status').textContent = parts.join(' · ');
    document.getElementById('sync-status').className   = 'status-msg';
  }
  document.getElementById('modal-sync').classList.remove('hidden');
}

document.getElementById('btn-adv-sync').addEventListener('click', () => {
  document.getElementById('modal-advanced').classList.add('hidden');
  openSyncModal();
});

document.getElementById('btn-sync-close').addEventListener('click', () => {
  document.getElementById('modal-sync').classList.add('hidden');
});

document.getElementById('modal-sync').addEventListener('click', e => {
  if (e.target === e.currentTarget) e.currentTarget.classList.add('hidden');
});

async function setupSyncIdentity(passphrase) {
  const { syncNsec, syncNpub, syncKeyRaw } = await deriveSyncIdentity(passphrase);
  saveSyncIdentity({
    syncNsecHex: bytesToHex(syncNsec),
    syncNpub,
    syncKeyRaw:  bytesToBase64url(syncKeyRaw),
    createdAt:   new Date().toISOString(),
  });
  return { syncNsec, syncNpub, syncKeyRaw };
}

document.getElementById('btn-sync-generate').addEventListener('click', async () => {
  const btn = document.getElementById('btn-sync-generate');
  btn.disabled = true;
  try {
    const passphrase = generateSyncPassphrase();
    const { syncNsec, syncKeyRaw } = await setupSyncIdentity(passphrase);

    document.getElementById('sync-passphrase-value').value = passphrase;
    document.getElementById('sync-passphrase-reveal').classList.remove('hidden');
    const qrContainer = document.getElementById('sync-qr-container');
    qrContainer.innerHTML = '';
    renderQR(qrContainer, passphrase);

    const results = await pushSyncData(DEFAULT_RELAYS, syncNsec, syncKeyRaw, buildSyncPayload());
    saveSyncMeta({ ...getSyncMeta(), lastPushedAt: new Date().toISOString() });

    document.getElementById('sync-setup-section').classList.add('hidden');
    document.getElementById('sync-manage-section').classList.remove('hidden');
    const allOk = results.every(r => r.ok);
    setSyncStatus(allOk ? t('sync.status.pushed') : t('sync.status.pushed.partial'), !allOk);
  } catch (err) {
    alert(t('alert.sync.error', { error: err.message }));
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('btn-sync-join').addEventListener('click', async () => {
  const input = document.getElementById('sync-join-passphrase-input');
  const passphrase = input.value.trim();
  if (!passphrase) return;
  const btn = document.getElementById('btn-sync-join');
  btn.disabled = true;
  try {
    const { syncNpub, syncKeyRaw } = await setupSyncIdentity(passphrase);
    input.value = '';

    const pulled = await pullSyncData(DEFAULT_RELAYS, syncNpub, syncKeyRaw);
    if (!pulled) {
      setSyncStatus(t('sync.status.nothingFound'), true);
    } else {
      await importBackup(pulled.payload, { navigate: false });
      refreshVisibleList();
      saveSyncMeta({ ...getSyncMeta(), lastPulledAt: new Date().toISOString() });
    }

    document.getElementById('sync-setup-section').classList.add('hidden');
    document.getElementById('sync-manage-section').classList.remove('hidden');
    if (pulled) setSyncStatus(t('sync.status.pulled'), false);
  } catch (err) {
    alert(t('alert.sync.error', { error: err.message }));
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('btn-sync-copy-passphrase').addEventListener('click', async () => {
  const value = document.getElementById('sync-passphrase-value').value;
  try { await navigator.clipboard.writeText(value); } catch {}
  const btn = document.getElementById('btn-sync-copy-passphrase');
  btn.textContent = t('btn.copied');
  setTimeout(() => { btn.textContent = t('btn.copy'); }, 2000);
});

document.getElementById('btn-sync-push').addEventListener('click', async () => {
  const identity = getSyncIdentity();
  if (!identity) return;
  const btn = document.getElementById('btn-sync-push');
  btn.disabled = true;
  try {
    const syncNsec   = hexToBytes(identity.syncNsecHex);
    const syncKeyRaw = base64urlToBytes(identity.syncKeyRaw);
    const results    = await pushSyncData(DEFAULT_RELAYS, syncNsec, syncKeyRaw, buildSyncPayload());
    saveSyncMeta({ ...getSyncMeta(), lastPushedAt: new Date().toISOString() });
    const allOk = results.every(r => r.ok);
    setSyncStatus(allOk ? t('sync.status.pushed') : t('sync.status.pushed.partial'), !allOk);
  } catch (err) {
    setSyncStatus(t('alert.sync.error', { error: err.message }), true);
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('btn-sync-pull').addEventListener('click', async () => {
  const identity = getSyncIdentity();
  if (!identity) return;
  const btn = document.getElementById('btn-sync-pull');
  btn.disabled = true;
  try {
    const syncKeyRaw = base64urlToBytes(identity.syncKeyRaw);
    const pulled = await pullSyncData(DEFAULT_RELAYS, identity.syncNpub, syncKeyRaw);
    if (!pulled) {
      setSyncStatus(t('sync.status.nothingFound'), true);
    } else {
      await importBackup(pulled.payload, { navigate: false });
      refreshVisibleList();
      saveSyncMeta({ ...getSyncMeta(), lastPulledAt: new Date().toISOString() });
      setSyncStatus(t('sync.status.pulled'), false);
    }
  } catch (err) {
    setSyncStatus(t('alert.sync.error', { error: err.message }), true);
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('btn-sync-delete').addEventListener('click', async () => {
  const identity = getSyncIdentity();
  if (!identity) return;
  if (!confirm(t('dialog.sync.delete.confirm'))) return;
  const btn = document.getElementById('btn-sync-delete');
  btn.disabled = true;
  try {
    await deleteSyncData(DEFAULT_RELAYS, hexToBytes(identity.syncNsecHex));
    clearSyncIdentity();
    document.getElementById('modal-sync').classList.add('hidden');
    alert(t('alert.sync.deleted'));
  } catch (err) {
    setSyncStatus(t('alert.sync.error', { error: err.message }), true);
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('btn-sync-rotate').addEventListener('click', async () => {
  if (!confirm(t('dialog.sync.rotate.confirm'))) return;
  clearSyncIdentity();
  document.getElementById('sync-setup-section').classList.remove('hidden');
  document.getElementById('sync-manage-section').classList.add('hidden');
  document.getElementById('sync-passphrase-reveal').classList.add('hidden');
});

// ---------------------------------------------------------------------------
// Dynamic field add buttons
// ---------------------------------------------------------------------------

document.getElementById('btn-add-tel').addEventListener('click', () => addDynamicField('tel-list', 'tel', t('editor.tel.placeholder')));
document.getElementById('btn-add-email').addEventListener('click', () => addDynamicField('email-list', 'email', t('editor.email.placeholder')));
document.getElementById('btn-add-org').addEventListener('click', () => addDynamicField('org-list', 'org', t('editor.org.placeholder')));
document.getElementById('btn-add-title').addEventListener('click', () => addDynamicField('title-list', 'title', t('editor.jobtitle.placeholder')));
document.getElementById('btn-add-url').addEventListener('click', () => addDynamicField('url-list', 'url', t('editor.url.placeholder')));
document.getElementById('btn-add-adr').addEventListener('click', () => addAdrField());
document.getElementById('btn-add-note').addEventListener('click', () => addDynamicField('note-list', 'note', t('editor.note.placeholder')));

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
  return `${location.origin}/card?naddr=${naddr}#${card.key}`;
}

/** Build the auto-download URL (?dl=1) — triggers .vcf download on open */
function buildDownloadUrl(card) {
  const naddr = naddrEncode(card.npub, card.id, card.relays);
  return `${location.origin}/card?naddr=${naddr}&dl=1#${card.key}`;
}

/** Canonical URL for vCard SOURCE field (no fragment, no key) */
function canonicalUrl(cardId, npub, relays) {
  const naddr = naddrEncode(npub, cardId, relays);
  return `${location.origin}/card?naddr=${naddr}`;
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
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
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

function bytesToBase64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/** https:// always allowed; http:// only on localhost (dev), to reject arbitrary-scheme injection */
function isSafeLinkUrl(url) {
  try {
    const u = new URL(url);
    if (u.protocol === 'https:') return true;
    return u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1');
  } catch { return false; }
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
