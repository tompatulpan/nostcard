# nostr-vcard

Zero-knowledge, client-side encrypted contact card (vCard) sharing via the Nostr protocol.

Owners publish AES-256-GCM encrypted contact data as signed Nostr events to public relays.  
Recipients open a single link in any browser — no app install, no account, no central server.

## How it works

- The **AES key** lives exclusively in the URL fragment (`#key`) — browsers never send it to any server.
- The **encrypted blob** is stored on public Nostr relays as a NIP-33 addressable event (kind 30402).
- The **relay** only ever sees ciphertext. It cannot read the contact data.
- Updating a card re-publishes a new event; relays auto-replace it (same `d` tag). No API token needed.

## Quick start (local dev)

```bash
npm install
npm run dev          # serves public/ at http://localhost:8788
```

No build step. The app imports nostr-tools directly from `https://esm.sh` at runtime.

---

## Deployment

### Cloudflare Pages

```bash
# First time: authenticate
npx wrangler login

# Create the Pages project (once)
npx wrangler pages project create nostr-vcard

# Deploy (every time)
npm run deploy
```

The deploy script runs `wrangler pages deploy public --project-name nostr-vcard`.  
Your site is live at `https://nostr-vcard.pages.dev` (or a custom domain you configure in the Cloudflare dashboard).

**Cloudflare dashboard (no CLI):**  
Go to [pages.cloudflare.com](https://pages.cloudflare.com) → Create project → Direct Upload → drag & drop the `public/` folder.

---

### GitHub Pages

1. Push the repo to GitHub.
2. Go to **Settings → Pages → Source** → select `main` branch, folder `/public`.
3. GitHub serves the static files at `https://<username>.github.io/<repo>/`.

No build action needed — just point Pages at the `public/` directory.

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

Recommended `Content-Security-Policy` header (set in your host config):

```
Content-Security-Policy: default-src 'self'; connect-src 'self' wss:; script-src 'self' https://esm.sh; style-src 'self' 'unsafe-inline'
```

---

## Accessing a card without the original domain

The card data lives on Nostr relays, not on your hosting domain. If the original URL host goes down, the encrypted blob is still available on every relay the card was published to.

### Option 1 — Open with any other deployment of this app

Host the `public/` folder anywhere (even `localhost`) and construct the card URL manually:

```
http://localhost:8788/card?naddr=<naddr1...>#<AES-key>
```

The `naddr` encodes the relays, so the new host will fetch the blob from the same Nostr relays.  
The `#AES-key` must come from the original share URL (the fragment is never stored server-side).

### Option 2 — Fetch the event with any Nostr client and decrypt locally

1. Decode the `naddr` from the share URL with any NIP-19 decoder (e.g. [nostr.band](https://nostr.band) or `nip19.decode()`).
2. Query the listed relays for `kind:30402` with the matching `pubkey` and `d` tag.
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
