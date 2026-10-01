/**
 * test-relay.mjs — minimal NIP-01 Nostr relay for local testing.
 *
 * Usage:  node tools/test-relay.mjs [port]   (default 48777)
 *
 * Implements just what NostCard needs to test its Nostr layer end-to-end,
 * deterministically and offline:
 *   - NIP-01 EVENT / REQ / CLOSE / NOTICE, OK replies, EOSE
 *   - filters: ids, authors, kinds, since, until, limit, and '#d'-style tag filters
 *   - NIP-33 replaceable events work because REQ returns all versions and the
 *     client (SimplePool.get) picks the newest by created_at
 *
 * Signature verification is NOT performed — this is a test double, never
 * expose it publicly. The app accepts ws:// only on localhost (nostr.js
 * isValidRelayUrl), so it plugs straight into the editor's relay manager
 * during `npm run dev`.
 */
import { WebSocketServer } from 'ws';

const PORT = Number(process.argv[2] || 48777);
const events = new Map();      // id -> event
const subs = new Map();        // subId -> { filters, ws }

const matchesFilter = (ev, f) => {
  if (f.ids && !f.ids.includes(ev.id)) return false;
  if (f.authors && !f.authors.includes(ev.pubkey)) return false;
  if (f.kinds && !f.kinds.includes(ev.kind)) return false;
  if (f.since && ev.created_at <= f.since) return false;
  if (f.until && ev.created_at > f.until) return false;
  if (f['#e'] && !f['#e'].some(t => ev.tags.some(tag => tag[0] === 'e' && tag[1] === t))) return false;
  if (f['#d'] && !f['#d'].some(t => ev.tags.some(tag => tag[0] === 'd' && tag[1] === t))) return false;
  if (f['#a'] && !f['#a'].some(t => ev.tags.some(tag => tag[0] === 'a' && tag[1] === t))) return false;
  return true;
};

const matchingEvents = (filters) => {
  const all = [...events.values()];
  const matched = all.filter(ev => filters.some(f => matchesFilter(ev, f)));
  matched.sort((a, b) => b.created_at - a.created_at);
  const limit = Math.min(...filters.map(f => f.limit || Infinity).filter(Number.isFinite));
  return Number.isFinite(limit) ? matched.slice(0, limit) : matched;
};

const wss = new WebSocketServer({ port: PORT }, () => {
  console.log(`test relay listening on ws://127.0.0.1:${PORT} (no signature verification — local testing only)`);
});

wss.on('connection', ws => {
  ws.on('message', raw => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (msg[0] === 'EVENT') {
      const ev = msg[1];
      if (!ev || typeof ev !== 'object') {
        ws.send(JSON.stringify(['OK', 'x', false, 'invalid event']));
        return;
      }
      const isNew = !events.has(ev.id);
      if (isNew) events.set(ev.id, ev);
      ws.send(JSON.stringify(['OK', ev.id, true]));

      // Live-stream to matching open subscriptions
      if (isNew) {
        for (const [subId, sub] of subs) {
          if (sub.ws !== ws) continue;
          if (sub.filters.some(f => matchesFilter(ev, f))) {
            sub.ws.send(JSON.stringify(['EVENT', subId, ev]));
          }
        }
      }
      return;
    }

    if (msg[0] === 'REQ') {
      const subId = msg[1];
      const filters = msg.slice(2).filter(f => f && typeof f === 'object');
      subs.set(subId, { filters, ws });
      for (const ev of matchingEvents(filters)) {
        ws.send(JSON.stringify(['EVENT', subId, ev]));
      }
      ws.send(JSON.stringify(['EOSE', subId]));
      return;
    }

    if (msg[0] === 'CLOSE') {
      subs.delete(msg[1]);
      return;
    }

    ws.send(JSON.stringify(['NOTICE', 'unsupported message type']));
  });

  ws.on('close', () => {
    for (const [subId, sub] of subs) {
      if (sub.ws === ws) subs.delete(subId);
    }
  });
});
