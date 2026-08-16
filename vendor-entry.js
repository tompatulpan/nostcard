// Build entry for public/vendor/nostr-tools.js — see package.json "build:vendor"
export { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure';
export { SimplePool } from 'nostr-tools/pool';
export * as nip19 from 'nostr-tools/nip19';
