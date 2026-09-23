# Copilot Instructions — NostCard

## Project purpose

A zero-knowledge, client-side encrypted contact card (vCard) sharing app backed by the Nostr protocol.
Owners publish encrypted contact data as Nostr events to public relays. Recipients open a link in any browser — no app install, no account. The server (relay) stores only ciphertext and can never read the contact data.

Key properties:
- **No central server** — encrypted blobs live on public Nostr relays (wss://relay.damus.io, wss://relay.nostr.band, wss://nos.lol by default)
- **No vendor lock-in** — any Nostr relay works; owners can add custom or self-hosted relays
- **End-to-end encryption** — AES-256-GCM, Web Crypto API only; AES key travels exclusively in the URL fragment (`#`) which browsers never send to servers
- **Pure static site** — no backend, no build step required; hosted on Cloudflare Pages, GitHub Pages, Netlify, or any static host

---

## High-level user flow

### Sender (card owner)

```
1. Open index.html
2. Create a card → enter a label
   - App generates: Nostr keypair (nsec/npub), AES-256-GCM key, 8-char card ID
   - Empty vCard is encrypted and published to default Nostr relays
3. Edit card fields (name, phone, email, address, …) → Save
   - App encrypts updated vCard and re-publishes as a NIP-33 replaceable event
   - Old event is automatically replaced on each relay (same d-tag)
4. Share → copy the share URL or download the QR code
   - URL format: https://<host>/card?naddr=<naddr1...>#<AES-key-base64url>
   - The #key fragment is never sent to any server
5. Optionally manage relays, rename, or delete the card
6. Export backup JSON to preserve nsec + AES key across devices
```

### Receiver (contact recipient)

```
1. Receive the share URL (message, QR scan, NFC, …)
2. Open URL in any browser — no app install, no account required
3. Browser fetches the encrypted Nostr event from the relays listed in naddr
4. AES key is read from the URL fragment (#) — never leaves the browser
5. App decrypts the vCard blob locally using Web Crypto API
6. Trust gate prompt:
   - Trusted device  → full card + Download .vcf + Save link
   - Public device   → full card visible; auto-cleared after 5 min inactivity
7. Trusted device: link is auto-saved to local "Saved cards" list immediately
8. Download .vcf to add the contact directly to phone/desktop Contacts
```

---

## File structure

```
nostcard/
  .github/
    copilot-instructions.md   ← this file
  public/
    index.html                owner UI (multi-card management, editor, share)
    card.html                 recipient read-only view
    app.js                    owner logic (ESM module)
    card.js                   recipient logic (ESM module)
    nostr.js                  Nostr layer: publish, fetch, naddr encode/decode
    crypto.js                 AES-256-GCM helpers (Web Crypto API)
    vcard.js                  vCard 3.0 builder and parser
    style.css                 shared styles
    qrcode.js                 QR code library (copied from previous project)
  package.json                nostr-tools dependency + optional dev server
```

No `worker/`, no `wrangler.toml`, no `dist/`. Serve `public/` directly as static files.

---

## Tech stack

- **Vanilla ESM** — no framework (React, Vue, etc.), no TypeScript, no bundler required
- **nostr-tools v2** (`@nostr/tools`) — the only runtime dependency; import from CDN via `esm.sh` for zero-build-step operation
- **Web Crypto API** — all encryption/decryption; no external crypto library
- **WebSocket** — browser-native; `SimplePool` from nostr-tools handles relay connections
- **localStorage** — all owner state; no cookies, no server sessions

CDN import pattern (no build step):
```js
import { generateSecretKey, getPublicKey, finalizeEvent } from 'https://esm.sh/@nostr/tools@^2/pure';
import { SimplePool } from 'https://esm.sh/@nostr/tools@^2/pool';
import * as nip19 from 'https://esm.sh/@nostr/tools@^2/nip19';
```

When a build step is added later, change imports to bare specifiers (`@nostr/tools/pure` etc.) and add `package.json` with `"@nostr/tools": "^2.0.0"`.

---

## Nostr event schema

### Card event (NIP-33 Addressable Replaceable Event)

```json
{
  "kind": 30402,
  "content": "<base64(IV[12bytes] + AES-256-GCM ciphertext)>",
  "tags": [
    ["d", "<card-id>"],
    ["title", "<card label, e.g. Work Card>"]
  ],
  "pubkey": "<owner npub hex>",
  "created_at": "<unix timestamp>",
  "id": "<event id>",
  "sig": "<schnorr signature>"
}
```

- **Kind 30402** is in the NIP-33 addressable range (30000–39999); relays keep only the latest event per `(pubkey, kind, d-tag)` triple — this is how "update card" works for free
- **`d` tag** = the card ID (8 random lowercase alphanumeric chars); stays constant across updates
- **`content`** = the encrypted blob (same format as the existing app's Cloudflare KV blob)
- **`title` tag** = human-readable card label; plaintext is acceptable (it is not sensitive data)

### Deletion event (NIP-09)

```json
{
  "kind": 5,
  "content": "deleted",
  "tags": [
    ["a", "30402:<npub-hex>:<card-id>"]
  ]
}
```

Well-behaved relays will stop serving the addressed event. Deletion is best-effort — not guaranteed.

---

## Recipient URL format

```
https://<host>/card?naddr=<naddr1...>#<AES-key-base64url>
```

- `naddr` is the NIP-19 bech32 encoding of `{ kind: 30402, pubkey, identifier: cardId, relays[] }`
- `#<AES-key>` is the base64url-encoded raw AES-256-GCM key (same format as the existing app)
- The fragment (`#...`) is never transmitted to any server — it exists only in the browser

The canonical card URL stored in the vCard `SOURCE` field (no fragment, no key):
```
https://<host>/card?naddr=<naddr1...>
```

---

## Crypto layer — `crypto.js`

Copy `crypto.js` from the existing `e2e-vcard-sharing` project unchanged. It exports:

```js
generateKey()                      // → CryptoKey (AES-256-GCM, 256-bit, extractable)
encryptVCard(vcardText, key)       // → Promise<string>  base64(IV[12] + ciphertext)
decryptVCard(base64Blob, key)      // → Promise<string>  plain vCard text
keyToFragment(key)                 // → Promise<string>  base64url for URL fragment
fragmentToKey(fragment)            // → Promise<CryptoKey> non-extractable for recipients
generateRandom(length)             // → string  crypto-random alphanumeric (used for card IDs)
```

Do **not** switch to NIP-44 (ChaCha20) encryption. The AES-256-GCM layer is correct, proven, and independent of Nostr key material. The Nostr keypair is used only for event signing, not for encrypting the blob.

---

## Nostr layer — `nostr.js`

Exports the following functions. Import nostr-tools internally; do not expose nostr-tools types directly.

```js
// Generate a fresh Nostr keypair for a card
generateKeypair()
// → { nsec: Uint8Array, npub: string (hex) }

// Publish/update a card event to all relays
publishCard(relays, nsec, cardId, encryptedBlob, label)
// → Promise<{ relay: string, ok: boolean }[]>  — one result per relay

// Fetch a card event from relays (returns latest matching event or null)
fetchCard(relays, npub, cardId)
// → Promise<{ content: string, created_at: number } | null>

// Publish a NIP-09 deletion event
deleteCard(relays, nsec, cardId)
// → Promise<void>

// Encode card address as naddr string
naddrEncode(npub, cardId, relays)
// → string  e.g. "naddr1qq9kummnw3..."

// Decode naddr string
naddrDecode(naddr)
// → { kind: number, pubkey: string, identifier: string, relays: string[] }
```

Internal implementation notes:
- Use `SimplePool` for all relay operations; close the pool after each operation
- `publishCard` calls `pool.publish(relays, event)` — collect results with `Promise.allSettled`
- `fetchCard` calls `pool.get(relays, { kinds: [30402], authors: [npub], "#d": [cardId] })`
- Always set a reasonable timeout (10s) on `pool.get()` to avoid hanging
- `finalizeEvent(template, nsec)` from `@nostr/tools/pure` handles hashing + signing

---

## vCard layer — `vcard.js`

Copy `vcard.js` from the existing `e2e-vcard-sharing` project unchanged. It exports:

```js
buildVCard(fields)    // → vCard 3.0 string
parseVCard(text)      // → fields object
```

vCard 3.0 (RFC 2426) is used for iOS/Android compatibility. Do not switch to vCard 4.0.

The `SOURCE` field in the built vCard must use the canonical URL (`?naddr=...`) without the fragment key.

---

## localStorage schema

```
e2e:cards            JSON array of card credential objects (see below)
e2e:fields:<id>      JSON — cached vCard fields for a card (fn, tel, email, org, etc.)
e2e:trusted:<id>     "yes" — trust gate bypass flag for a card on this device
e2e:saved-links      JSON array of { url, label, savedAt } — recipient's saved card links
e2e:exported:<id>    "1" — marks a card as having been backed up
```

### Card credential object

```json
{
  "id":     "abc12345",
  "label":  "Work Card",
  "nsec":   "<hex string — Nostr private key>",
  "npub":   "<hex string — Nostr public key>",
  "key":    "<base64url — AES-256-GCM key>",
  "relays": ["wss://relay.damus.io", "wss://relay.nostr.band", "wss://nos.lol"]
}
```

The `nsec` is a raw hex-encoded 32-byte secp256k1 private key (as returned by `generateSecretKey()` from nostr-tools). Do not use bech32 `nsec1...` encoding for storage — store raw hex, convert for display only.

---

## Owner UI — `app.js` / `index.html`

### Screens (same structure as existing app)

- **setup** — shown when no cards exist; button to create first card
- **cards** — list of all cards with actions (Edit, Share, View, Rename)
- **editor** — form to edit vCard fields for the active card; Save button; Share section; Relay manager
- **saved** — list of saved recipient links (cards shared with you)
- **card-view** — inline SPA card viewer (same as recipient view, embedded in owner app)

### Card list row

Each row shows: label, FN subtitle (from cached fields), relay publish status (✓ / ✗ per relay). Actions: View, Edit, Share, Rename. No recipient count (no tokens exist).

### Card creation

1. Prompt for label
2. `generateKeypair()` → store `nsec`, `npub`
3. `generateKey()` → store `key`
4. `generateRandom(8).toLowerCase()` → `id`
5. Build minimal vCard (`fn: label`)
6. `encryptVCard()` → blob
7. `publishCard(defaultRelays, nsec, id, blob, label)`
8. Save to localStorage; navigate to editor

### Card save (update)

1. Read form fields → `buildVCard()` → `encryptVCard()`
2. `publishCard(card.relays, card.nsec, card.id, blob, card.label)`
3. NIP-33 semantics: the new event automatically replaces the old one on each relay (same `d` tag)
4. Cache fields in `e2e:fields:<id>`

### Share modal

Same UX as the existing app:
- Display the full share URL (`?naddr=...#AES-key`)
- Copy to clipboard button
- QR code rendered as PNG (right-click copyable)
- QR download button
- Close on backdrop click

No "recipient name" input field, no token creation — the URL itself is the share credential.

### Card delete

1. Prompt for confirmation
2. `deleteCard(card.relays, card.nsec, card.id)` — sends NIP-09 deletion event
3. Remove from localStorage
4. Navigate back to card list

### Relay manager (in editor screen)

A small UI section (collapsible) showing the relay list for the active card.
- List current relays with a remove (✕) button per relay
- Input + "Add relay" button; validate `wss://...` URL format before adding
- Changes take effect on next Save
- Default relays applied at card creation: `wss://relay.damus.io`, `wss://relay.nostr.band`, `wss://nos.lol`

### Owner card preview

"View" button opens the inline card viewer (`showCardViewScreen(url, 'owner-preview')`).
The URL is constructed as: `${location.origin}/card?naddr=${naddrEncode(card.npub, card.id, card.relays)}#${card.key}`
Owner-preview mode skips the trust gate and auto-clear timer.

---

## vCard field editor

Identical to the existing app. Dynamic field lists with add/remove and type selectors:

| Field   | Input type | Type options                          |
|---------|------------|---------------------------------------|
| FN      | text       | — (single field)                      |
| First / Last name | text | — (two separate inputs)           |
| TEL     | tel        | Mobile, Work, Home, Fax               |
| EMAIL   | email      | Work, Home, Other                     |
| ORG     | text       | — (no type selector)                  |
| TITLE   | text       | — (no type selector)                  |
| URL     | url        | Work, Home, Other                     |
| ADR     | text (6 inputs) | Work, Home, Other (street, city, region, postcode, country) |
| NOTE    | textarea   | — (no type selector)                  |

The `ADR` field maps to vCard 3.0 `ADR` structured value: `;;street;city;region;postcode;country`.
Render as six separate text inputs (street, city, region/state, postcode, country) in the editor.
Display as a single formatted block in the recipient card view.

---

## Recipient UI — `card.js` / `card.html`

### Fetch flow

```
1. Parse `?naddr=` from location.search
2. naddrDecode(naddr) → { pubkey, identifier, relays, kind }
3. Parse `#AES-key` from location.hash
4. fragmentToKey(hashFragment) → CryptoKey
5. fetchCard(relays, pubkey, identifier) → event.content (encrypted blob)
6. decryptVCard(blob, key) → vcardText
7. parseVCard(vcardText) → fields
8. Show trust gate → render card
```

Error states: invalid link, missing fragment, decryption failed, relay timeout (card not found).

### Trust gate (same as existing app)

When a card URL is opened on an untrusted/public device:
- **Trusted device** — show full contact, Download .vcf button, Save link button; remember choice in `e2e:trusted:<id>`
- **Public/shared device** — show contact but no download; auto-clear after 5 minutes of inactivity or on tab hide; countdown timer shown

The trust choice is stored per card-id in localStorage and expires after 30 days (implement TTL on the "yes" value: store `{ ok: true, expires: <timestamp> }` instead of plain `"yes"`).

### Auto-clear (public mode)

- 5-minute countdown timer shown in the card view
- `visibilitychange` event: clear immediately if tab becomes hidden
- On clear: wipe DOM fields, replace with "Session cleared 🔒" message + Back button
- Owner-preview mode: auto-clear is disabled

### Card rendering

Same as existing app:
- Avatar circle with initials
- Full name + title/org subtitle
- Field rows: 📞 tel (clickable `tel:` link), ✉️ email (`mailto:`), 🔗 URL (opens in new tab with `rel="noopener noreferrer"`), 📝 note
- QR code of vCard text (for scanning into phone Contacts)

### Save link (recipient)

On **trusted devices**, auto-save the full URL to `e2e:saved-links` immediately after the trust gate is accepted — do not wait for a button click. The "💾 Save link" button should be rendered pre-checked and disabled (`✓ Link saved`) to confirm it was saved. This covers the common case of a bookmarked link being reopened without any interaction.

On **public devices**, hide the Save link button entirely (no persistent storage for public sessions).

Deduplication: before saving, check whether the URL already exists in `e2e:saved-links`; skip the write if it does.

The saved URL must include the `#AES-key` fragment so the card can be re-opened later.

### Download .vcf (trusted mode only)

Download the plaintext vCard as `<fn>.vcf`. Trigger auto-clear 3 seconds after download.

---

## Saved links screen

A list of saved recipient URLs. Each row: label, saved date, Open button, Remove button.
"Open" calls `showCardViewScreen(url, 'saved-card')` — the same inline card viewer.

---

## Backup & restore

### Export

JSON file containing:
```json
{
  "version": 2,
  "exported": "<ISO timestamp>",
  "cards": [ <card credential objects including nsec> ],
  "savedLinks": [ { "url": "...", "label": "...", "savedAt": "..." } ],
  "fields": { "<card-id>": { <cached vCard fields> } }
}
```

Version 2 distinguishes from the old Cloudflare-based backup format (version 1 had `ownerToken` instead of `nsec`/`npub`).

### Import

Accept file or paste. Supported formats:
- **Version 2** backup (this app) — full restore
- **Version 1** backup (old Cloudflare app) — import fields + AES keys; generate new Nostr keypair and re-publish to relays; warn user that old share links (with `?id=...&tok=...`) are not compatible
- Array of card objects — legacy credential list

On import:
1. Check if card ID already exists in localStorage → skip (don't overwrite)
2. Validate nsec is present and valid hex
3. Attempt `fetchCard` to confirm the event is still on relays → show "found" / "not on relays" status
4. If not on relays but fields are available → offer "Re-publish" button
5. Merge saved links (deduplicate by URL)

---

## Security rules

1. **The AES key must never leave the browser as part of a network request.** The fragment (`#key`) is stripped by browsers before HTTP requests. Never include the key in query parameters, headers, or request bodies.

2. **`nsec` must never be logged.** No `console.log` of card objects containing `nsec`. Redact before logging if needed.

3. **Validate `naddr` before use.** Call `naddrDecode` in a try/catch; show a user-facing error on parse failure rather than crashing.

4. **Sanitise all user-supplied strings** before inserting into the DOM. Use `element.textContent` for plain text. When constructing HTML strings, escape `&`, `<`, `>`, `"` via an `htmlEscape()` helper. Never use `innerHTML` with unescaped user data.

5. **URL validation for relay inputs.** Only accept `wss://` or `ws://` (dev only) URLs when the user adds a custom relay. Reject others with a visible error.

6. **Anchor tag href validation.** Before setting `a.href`, verify the URL starts with `https:`, `http:`, `tel:`, or `mailto:`. Never set arbitrary `javascript:` or `data:` hrefs.

7. **Content-Security-Policy header** (configure on the static host):
   ```
   Content-Security-Policy: default-src 'self'; connect-src 'self' wss:; script-src 'self' https://esm.sh; style-src 'self' 'unsafe-inline'
   ```

8. **No server-side key material.** The relay sees only the signed Nostr event with encrypted `content`. The relay cannot derive the AES key.

9. **`e2e:trusted:<id>` TTL.** Store as `{ ok: true, expires: <unix ms> }`. Treat as expired (and delete) if `Date.now() > expires`. Default TTL: 30 days.

---

## What NOT to do

- Do **not** use NIP-44 (ChaCha20) for the vCard blob. The AES-256-GCM layer is independent of Nostr keys and must remain so.
- Do **not** add server-side token validation. There are no per-recipient tokens. A valid URL with the correct `#key` is sufficient to decrypt.
- Do **not** store the AES key in `sessionStorage`, cookies, or anywhere that might be sent to a server.
- Do **not** use `document.write()`, `eval()`, or `new Function()`.
- Do **not** add a framework (React, Vue, Svelte). Keep it vanilla ESM.
- Do **not** add a bundler (webpack, vite) unless explicitly requested. The CDN import pattern keeps the project zero-config.
- Do **not** use `innerHTML` with user-controlled strings — use `textContent` or DOM methods.
- Do **not** store `nsec` in bech32 format (`nsec1...`). Store as raw hex; convert to bech32 only for display or export if needed.

---

## Default relay list

```js
export const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://relay.nostr.band',
  'wss://nos.lol',
];
```

Defined once in `nostr.js` and imported by `app.js`. Users can override per card via the relay manager in the editor.

---

## Code style

- ESM modules with named exports; no default exports
- `async/await` throughout; no `.then()` chains
- `try/catch` for all Nostr and crypto operations; always surface a user-facing error message
- `const` by default; `let` only when reassignment is required; never `var`
- DOM element IDs match the pattern used in the existing app (`screen-*`, `btn-*`, `modal-*`) for consistency
- Helper functions at the bottom of the file; event listeners wired at the bottom of each section
- No TypeScript; no JSDoc required (but welcome for exported functions in `nostr.js` and `crypto.js`)

---

## Differences from the previous Cloudflare-based app

| Feature | Old app (Cloudflare) | This app (Nostr) |
|---|---|---|
| Blob storage | Cloudflare KV | Nostr relays |
| Owner auth | ownerToken (32-char random, SHA-256 stored) | Nostr nsec (secp256k1 private key, signs events) |
| Share URL | `?id=...&tok=...#AES-key` | `?naddr=...#AES-key` |
| Per-recipient tokens | Yes | No — single link per card |
| Token revocation | Yes | No — rotate key + reshare |
| Access logs (IP, country) | Yes | No |
| Anomaly detection | Yes | No |
| Rate limiting | Worker-enforced | None (rely on relay limits) |
| Card update | PUT to Worker | Publish new NIP-33 event (relay auto-replaces) |
| Card delete | DELETE to Worker | NIP-09 deletion event (best-effort) |
| Self-hostable | No (Cloudflare only) | Yes (any Nostr relay) |
| No server to operate | No (worker required) | Yes |

The recipient and owner UI experience is otherwise identical.
