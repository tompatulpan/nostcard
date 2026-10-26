// Build entry for public/vendor/nostr-tools.js — see package.json "build:vendor"
// verifyEvent (not verifySignature) is the export name in nostr-tools 2.x.
export { generateSecretKey, getPublicKey, finalizeEvent, verifyEvent } from 'nostr-tools/pure';
export { SimplePool } from 'nostr-tools/pool';
export * as nip19 from 'nostr-tools/nip19';
