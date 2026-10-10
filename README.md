# NostCard

Decentralized, zero-knowledge, client-side encrypted contact card (vCard) sharing via the Nostr protocol.

Owners publish AES-256-GCM encrypted contact data as signed Nostr events to public relays.  
Recipients open a single link in any browser — no app install, no account, no central server.

**Live demo:** <https://tompatulpan.github.io/nostcard>

## Decentralized — any client works

The card data lives on Nostr relays, not on any particular website. NostCard is just one client: the same encrypted events can be read by any deployment of this app (any host, even `localhost`) or by any Nostr client that understands `kind:36350` events. If this app or its hosting domain disappears, your cards survive on the relays — see [Accessing a card without the original domain](#accessing-a-card-without-the-original-domain).

## How it works

- The **AES key** lives exclusively in the URL fragment (`#key`) — browsers never send it to any server.
- The **encrypted blob** is stored on public Nostr relays as a NIP-33 addressable event (kind 36350).
- The **relay** only ever sees ciphertext. It cannot read the contact data.
- Updating a card re-publishes a new event; relays auto-replace it (same `d` tag). No API token needed.

### Signing identity

Each card is signed by its own Nostr keypair, generated in your browser. At creation you can instead paste an existing private key (`nsec…` or 64-char hex) to sign the card with your real Nostr identity — recipients can then verify the card against your known `npub` on any Nostr client. The public key is visible on the relays either way; using your main identity publicly links the card to it.

## Using the app

1. **Create a card** — a fresh Nostr identity and AES encryption key are generated inside your browser. Nothing is sent anywhere yet.
2. **Fill in your details** and press *Save & publish* — the card is encrypted (AES-256-GCM) and published to public relays.
3. **Share it** (see below) — recipients open a plain link in any browser. No app, no account.
4. **Keep it live** — saving again updates the same card, so every shared link always shows your latest details.

Your keys never leave your browser except inside the links you share. Use *Advanced → Backup* to move to another device.

## Ways to share a card

- **Share link** — the decryption key rides in the `#fragment`. Anyone with the full link can view the card.
- **QR code** — the share dialog renders the link as a scannable QR code.
- **Add-to-contacts link** — opens with a `?dl=1` parameter and downloads the card as a `.vcf` file straight into the contacts app.
- **In-person pairing** — *+ Connect* starts a mutual exchange: one person shows a QR, the other scans it, and both pick which card to share back. Codes stop working after 30 minutes and the exchange is scrubbed from the relays afterwards (best-effort). Treat a pairing code like a password — if it may have been photographed, rotate the card key.

## Trust models

The share link **is the password** — anyone holding the full link can read the card. For extra safety, send the base link and the `#key` through two different channels (e.g. email + Signal).

When a recipient opens a card, the app asks where they are, and the answer controls what is stored on that device:

| Choice | What happens |
| --- | --- |
| **My personal device** | Link saved locally, device remembered for 30 days, `.vcf` download allowed, bookmarking encouraged. |
| **Shared / public computer** | Nothing saved. Session auto-clears on tab switch, after 5 minutes, or on "Done". Download disabled. |

Owner controls:

- **Rotate key** — re-encrypts with a new key and re-publishes; all old links stop working immediately.
- **Delete card** — removes local credentials and sends a NIP-09 deletion request (best-effort; an archived relay may keep a copy).
- **Verify privacy** — a built-in proof page shows exactly what a relay sees versus what the key unlocks.

The app ships with a full in-app help page at `index.html#/help`.

## Quick start (local dev)

```bash
npm install
npm run dev          # serves public/ at http://localhost:8123
```

No build step. nostr-tools is bundled into `public/vendor/nostr-tools.js` (rebuild with `npm run build:vendor`) — no CDN is used at runtime.

`npm run dev` enforces the same security headers as production via `public/serve.json`. Production headers live in `public/_headers` (Cloudflare Pages).

---

## Deployment

### Cloudflare Pages

```bash
# First time: authenticate
npx wrangler login

# Create the Pages project (once)
npx wrangler pages project create nostcard

# Deploy or update (every time)
npm run deploy
```

The deploy script runs `wrangler pages deploy public --project-name nostcard`.  
Your site is live at `https://nostcard.pages.dev` (or a custom domain you configure in the Cloudflare dashboard).

**Cloudflare dashboard (no CLI):**  
Go to [pages.cloudflare.com](https://pages.cloudflare.com) → Create project → Direct Upload → drag & drop the `public/` folder.

---

### GitHub Pages

The repo ships with a deploy workflow (`.github/workflows/deploy.yml`) that publishes `public/` on every push to `main`.

1. Push the repo to GitHub.
2. Go to **Settings → Pages → Build and deployment → Source** → select **GitHub Actions**.
3. GitHub serves the site at `https://<username>.github.io/<repo>/` and redeploys automatically on every push.

**Working deployment:** <https://tompatulpan.github.io/nostcard>

---

### Netlify

```bash
# CLI deploy
npm install -g netlify-cli
netlify deploy --dir public --prod
```

Or connect the GitHub repo in the Netlify dashboard and set **Publish directory** to `public`. Leave Build command empty.

---

### Any static host (nginx, Caddy, Apache, …)

Copy the contents of `public/` to your web root. No server-side logic required.

Set the security headers from `public/_headers` in your host config — CSP (`script-src 'self'`, `connect-src 'self' wss:`, etc.), `X-Content-Type-Options`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`. `_headers` is the source of truth for the exact policy.

---

## Accessing a card without the original domain

The card data lives on Nostr relays, not on your hosting domain. If the original URL host goes down, the encrypted blob is still available on every relay the card was published to.

### Option 1 — Open with any other deployment of this app

Host the `public/` folder anywhere (even `localhost`) and construct the card URL manually:

```
http://localhost:8123/card?naddr=<naddr1...>#<AES-key>
```

The `naddr` encodes the relays, so the new host will fetch the blob from the same Nostr relays.  
The `#AES-key` must come from the original share URL (the fragment is never stored server-side).

### Option 2 — Fetch the event with any Nostr client and decrypt locally

1. Decode the `naddr` from the share URL with any NIP-19 decoder (e.g. [nostr.band](https://nostr.band) or `nip19.decode()`).
2. Query the listed relays for `kind:36350` with the matching `pubkey` and `d` tag.
3. Take the `content` field (base64 blob), decode the AES key from the URL fragment, and decrypt with AES-256-GCM.

### Option 3 — Save the card as a .vcf while the link is live

On a trusted device, the recipient view offers a **Download .vcf** button. This saves the plaintext contact permanently to the device, independent of any relay or host.

---

## Security notes

- The AES key is **only** in the URL `#fragment` — never in query params, never sent to a server.
- `nsec` (Nostr private key) is stored as raw hex in `localStorage`. Never logged.
- All user strings are DOM-sanitised (`textContent` / explicit escaping). No `innerHTML` with user data.
- Trust gate TTL: trusted-device flag expires after 30 days.

## File structure

```
public/
  index.html   owner UI
  card.html    recipient read-only view
  app.js       owner logic
  card.js      recipient logic
  nostr.js     Nostr layer (publish, fetch, naddr encode/decode)
  crypto.js    AES-256-GCM helpers (Web Crypto API)
  vcard.js     vCard 3.0 builder / parser
  style.css    shared styles
  qrcode.js    QR code library
```
