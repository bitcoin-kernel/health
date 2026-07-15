// Trustless block-by-hash transfer over WebRTC — a browser peer that fetches
// blocks from, and serves cached blocks to, other browsers. No block API in the
// path: you request a block *by hash*, and verify the bytes hash back to it, so
// a lying peer is caught (exactly the guarantee the esplora fetch relies on).
//
// The connection layer mirrors the proven kernel `mesh.js` against the same
// JSS content-addressed signaling (announce/offer/answer, non-trickle ICE, STUN
// candidates baked into each SDP — the tracker relays offers/answers but NOT ICE
// candidates). Symmetric: every peer batches offers AND answers every offer it
// receives, keyed by the signaling `from` id. Runs on the MAIN thread (WebRTC
// isn't available in Workers) and fills the OPFS BlockStore the worker reads.
import { dsha256, reverseHex } from './engine/codec/hash.js';

const CHUNK = 64 * 1024;
const HIGH_WATER = 4 * 1024 * 1024;
const OFFER_BATCH = 4;            // offers per announce — the tracker fans them to distinct peers
const REANNOUNCE_MS = 90_000;     // re-announce to discover new peers / refill slots
const OFFER_TTL = 60_000;         // drop an unanswered offer after this
const DEFAULT_ICE = [{ urls: 'stun:stun.l.google.com:19302' }];
const rid = () => Math.random().toString(36).slice(2, 12);

// block hash = dsha256 of the 80 header bytes, byte-reversed (display order)
export const blockHashOf = (bytes) => reverseHex(dsha256(bytes.subarray(0, 80)));

// non-trickle: wait until all STUN candidates are gathered into the SDP
function iceComplete(pc) {
  return new Promise((res) => {
    if (pc.iceGatheringState === 'complete') return res();
    const check = () => { if (pc.iceGatheringState === 'complete') { pc.removeEventListener('icegatheringstatechange', check); res(); } };
    pc.addEventListener('icegatheringstatechange', check);
    setTimeout(res, 8000);
  });
}

export class PeerSource {
  constructor({ signalUrl, room = 'b17c0100b10c48ea1710', store, iceServers, onStatus = () => {} }) {
    this.tracker = signalUrl;
    this.swarm = room;
    this.store = store;
    this.iceServers = (iceServers && iceServers.length) ? iceServers : DEFAULT_ICE;
    this.onStatus = onStatus;
    this.peers = new Map();          // peerId (signaling `from`) -> entry { pc, ch, have, inbound, inboundReq }
    this.pendingOffers = new Map();  // offer_id -> pc (offers awaiting an answer)
    this.reqSeq = 0; this.served = 0; this.received = 0; this.synced = 0;
    this.syncing = false; this.syncDirty = false; this.syncTimer = null;
    this.haveTimer = null; this.reannounceTimer = null;
    this.closed = false; this.ws = null;
  }

  start() {
    if (!this.tracker) return;
    this._connect();
    this.haveTimer = setInterval(() => this._broadcastHave(), 15000);
  }
  close() {
    this.closed = true;
    clearInterval(this.haveTimer); clearInterval(this.reannounceTimer); clearTimeout(this.syncTimer);
    try { this.ws?.close(); } catch {}
    for (const e of this.peers.values()) { try { e.ch?.close(); } catch {} try { e.pc?.close(); } catch {} }
    this.peers.clear();
  }
  status() {
    return { room: this.swarm, connected: this.peers.size, peers: [...this.peers.keys()],
      served: this.served, received: this.received, synced: this.synced, syncing: this.syncing,
      ws: this.ws ? this.ws.readyState : -1 };
  }
  _emit() { try { this.onStatus(this.status()); } catch {} }

  // ---- signaling (JSS content-addressed room) ----
  _connect() {
    if (this.closed) return;
    let ws;
    try { ws = this.ws = new WebSocket(this.tracker); } catch { setTimeout(() => this._connect(), 3000); return; }
    ws.onopen = () => { this._announce(); this.reannounceTimer = setInterval(() => this._announce(), REANNOUNCE_MS); this._emit(); };
    ws.onmessage = (e) => { let m; try { m = JSON.parse(e.data); } catch { return; } this._onSignal(m); };
    ws.onerror = () => {};
    ws.onclose = () => { clearInterval(this.reannounceTimer); this._emit(); if (!this.closed) setTimeout(() => this._connect(), 3000); };
  }
  _ws(m) { if (this.ws && this.ws.readyState === 1) this.ws.send(JSON.stringify(m)); }

  async _makeOffer() {
    const pc = new RTCPeerConnection({ iceServers: this.iceServers });
    pc._ch = pc.createDataChannel('blocks');
    await pc.setLocalDescription(await pc.createOffer());
    await iceComplete(pc);
    return { pc, sdp: pc.localDescription.sdp };
  }

  async _announce() {
    if (!this.ws || this.ws.readyState !== 1) return;
    const offers = [];
    for (let i = 0; i < OFFER_BATCH; i++) {
      try {
        const { pc, sdp } = await this._makeOffer();
        const offer_id = rid();
        this.pendingOffers.set(offer_id, pc);
        setTimeout(() => { if (this.pendingOffers.delete(offer_id)) { try { pc.close(); } catch {} } }, OFFER_TTL);
        offers.push({ offer_id, sdp });
      } catch {}
    }
    if (offers.length) this._ws({ type: 'announce', resource: this.swarm, offers });
  }

  async _onSignal(m) {
    if (m.resource !== this.swarm) return;
    if (m.type === 'offer' && m.from && typeof m.sdp === 'string') {
      // a peer wants to connect to us — answer (we receive their data channel)
      try {
        const pc = new RTCPeerConnection({ iceServers: this.iceServers });
        pc.ondatachannel = (ev) => this._adopt(m.from, pc, ev.channel);
        await pc.setRemoteDescription({ type: 'offer', sdp: m.sdp });
        await pc.setLocalDescription(await pc.createAnswer());
        await iceComplete(pc);
        this._ws({ type: 'answer', resource: this.swarm, to: m.from, offer_id: m.offer_id, sdp: pc.localDescription.sdp });
      } catch {}
    } else if (m.type === 'answer' && m.offer_id && typeof m.sdp === 'string') {
      const pc = this.pendingOffers.get(m.offer_id);
      if (pc) {
        this.pendingOffers.delete(m.offer_id);
        try { await pc.setRemoteDescription({ type: 'answer', sdp: m.sdp }); this._adopt(m.from, pc, pc._ch); }
        catch { try { pc.close(); } catch {} }
      }
    }
  }

  // Register a peer (keyed by signaling id) once its channel opens — same path
  // for offerer and answerer, so both sides see each other.
  _adopt(peerId, pc, ch) {
    ch.binaryType = 'arraybuffer';
    ch.bufferedAmountLowThreshold = 256 * 1024;
    const entry = { pc, ch, peerId, have: new Map(), inbound: null, inboundReq: null };
    const register = () => { this.peers.set(peerId, entry); this._sendHave(entry); this._scheduleSync(); this._emit(); };
    const drop = () => { if (this.peers.get(peerId) === entry) { this.peers.delete(peerId); this._emit(); } };
    if (ch.readyState === 'open') register(); else ch.addEventListener('open', register);
    ch.addEventListener('close', drop);
    ch.onmessage = (ev) => this._onChannel(entry, ev.data);
    pc.onconnectionstatechange = () => { if (['failed', 'disconnected', 'closed'].includes(pc.connectionState)) drop(); };
  }

  // ---- data channel: control (JSON strings) + binary block chunks ----
  _chSend(entry, obj) { try { if (entry.ch.readyState === 'open') entry.ch.send(JSON.stringify(obj)); } catch {} }

  _onChannel(entry, data) {
    if (typeof data === 'string') {
      let m; try { m = JSON.parse(data); } catch { return; }
      this._onControl(entry, m);
    } else {
      const inb = entry.inbound; if (!inb) return;
      const u8 = new Uint8Array(data);
      inb.chunks.push(u8); inb.received += u8.length;
    }
  }

  _onControl(entry, m) {
    switch (m.t) {
      case 'have': for (const [h, ht] of (m.list || [])) entry.have.set(h, ht); this._scheduleSync(); break;
      case 'getblock': this._serve(entry, m); break;
      case 'blockmeta': entry.inbound = { hash: m.hash, size: m.size, chunks: [], received: 0 }; break;
      case 'blockend': this._finishInbound(entry); break;
      case 'noblock': { const p = entry.inboundReq; if (p) { entry.inboundReq = null; p.resolve(null); } break; }
      default: break;
    }
  }

  _sendHave(entry) {
    if (!this.store) return;
    this.store.list().then((l) => this._chSend(entry, { t: 'have', list: l.slice(-100).map((b) => [b.hash, b.height]) })).catch(() => {});
  }
  _broadcastHave() { for (const e of this.peers.values()) this._sendHave(e); }

  // ---- serving a block we hold ----
  async _serve(entry, m) {
    let rec = null; try { rec = await this.store.findByHash(m.hash); } catch {}
    if (!rec) return this._chSend(entry, { t: 'noblock', id: m.id, hash: m.hash });
    let bytes = null; try { bytes = await this.store.get(rec.height, rec.hash); } catch {}
    if (!bytes) return this._chSend(entry, { t: 'noblock', id: m.id, hash: m.hash });
    this._chSend(entry, { t: 'blockmeta', id: m.id, hash: m.hash, size: bytes.length });
    const ch = entry.ch;
    for (let off = 0; off < bytes.length; off += CHUNK) {
      if (ch.readyState !== 'open') return;
      if (ch.bufferedAmount > HIGH_WATER) await new Promise((r) => ch.addEventListener('bufferedamountlow', r, { once: true }));
      ch.send(bytes.subarray(off, off + CHUNK));
    }
    this._chSend(entry, { t: 'blockend', id: m.id });
    this.served++; this._emit();
  }

  // ---- requesting a block, verifying it, caching it ----
  _finishInbound(entry) {
    const inb = entry.inbound, req = entry.inboundReq;
    entry.inbound = null; entry.inboundReq = null;
    if (!inb || !req) return;
    const bytes = new Uint8Array(inb.received);
    let off = 0; for (const c of inb.chunks) { bytes.set(c, off); off += c.length; }
    if (bytes.length < 80 || blockHashOf(bytes) !== req.hash) { req.resolve(null); return; } // liar / corrupt → reject
    if (this.store && req.height != null) this.store.put(req.height, req.hash, bytes).catch(() => {});
    this.received++; this._emit();
    req.resolve(bytes);
  }

  // Fetch a block by hash from a peer that advertises it. Verified bytes or null.
  requestBlock(hash, height = null, timeoutMs = 20000) {
    let entry = null, h = height;
    for (const e of this.peers.values()) {
      if (e.ch?.readyState === 'open' && !e.inboundReq && e.have.has(hash)) { entry = e; if (h == null) h = e.have.get(hash); break; }
    }
    if (!entry) return Promise.resolve(null);
    return new Promise((resolve) => {
      const done = (v) => { clearTimeout(timer); resolve(v); };
      const timer = setTimeout(() => { entry.inboundReq = null; entry.inbound = null; done(null); }, timeoutMs);
      entry.inboundReq = { hash, height: h, resolve: done };
      this._chSend(entry, { t: 'getblock', id: 'r' + (this.reqSeq++), hash });
    });
  }

  // ---- catch-up: pull every block our peers advertise that we don't have ----
  _scheduleSync() {
    if (this.syncing) { this.syncDirty = true; return; }
    clearTimeout(this.syncTimer);
    this.syncTimer = setTimeout(() => this._sync(), 300);
  }
  async _sync() {
    if (!this.store || this.closed) return;
    this.syncing = true; this.syncDirty = false; this._emit();
    try {
      const want = new Map();
      for (const e of this.peers.values()) for (const [h, ht] of e.have) if (!want.has(h)) want.set(h, ht);
      for (const [hash, height] of want) {
        if (this.closed) break;
        if (await this.store.has(height, hash)) continue;
        const bytes = await this.requestBlock(hash, height);
        if (bytes) { this.synced++; this._emit(); }
      }
    } finally {
      this.syncing = false; this._emit();
      if (this.syncDirty) this._scheduleSync();
    }
  }

  // convenience for the two-tab test: pull one block a peer advertises, verify it.
  async testFetch() {
    for (const e of this.peers.values()) for (const [hash, height] of e.have) {
      const bytes = await this.requestBlock(hash, height);
      return { hash, height, ok: !!bytes, bytes: bytes ? bytes.length : 0 };
    }
    return { ok: false, reason: 'no peer advertises any block yet' };
  }
}
