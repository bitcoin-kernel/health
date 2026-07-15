// Trustless block-by-hash transfer over WebRTC — a browser peer that fetches
// blocks from, and serves cached blocks to, other browsers. No block API in the
// path: you request a block *by hash*, and verify the bytes hash back to it, so
// a lying peer is caught (exactly the guarantee the esplora fetch relies on).
//
// Signaling is a room rendezvous on a JSS-compatible /.webrtc server (SDP
// announce/offer/answer over a WebSocket) — the same protocol browser-node's
// peer-rtc.js uses. The signaling server is untrusted rendezvous, never a data
// path. Runs on the MAIN thread (WebRTC isn't available in Workers) and fills
// the OPFS BlockStore the validator worker already reads through.
//
// This is phase 1: prove the pipe. It is a self-contained module — start it,
// point it at a room, and use requestBlock(hash) / it serves from the store.
import { dsha256, reverseHex } from './engine/codec/hash.js';

const CHUNK = 64 * 1024;
const HIGH_WATER = 4 * 1024 * 1024;
const DEFAULT_ICE = [{ urls: 'stun:stun.l.google.com:19302' }];

// block hash = dsha256 of the 80 header bytes, byte-reversed (display order)
export const blockHashOf = (bytes) => reverseHex(dsha256(bytes.subarray(0, 80)));

export class PeerSource {
  constructor({ signalUrl, room = 'b17c0100b10c48ea1710', store, iceServers = DEFAULT_ICE, onStatus = () => {} }) {
    this.signalUrl = signalUrl;
    this.room = room;
    this.store = store;
    this.iceServers = iceServers;
    this.onStatus = onStatus;
    this.selfId = 'p' + Math.random().toString(36).slice(2, 12);
    this.peers = new Map();   // peerId -> { dc, pc, offerer, have:Map<hash,height>, inbound }
    this.pendingPc = new Map(); // offer_id -> { pc, dc, offerer }  (pre-hello)
    this.handledOffers = new Set(); // offer_ids we've already answered (ignore re-announces)
    this.reqSeq = 0;
    this.served = 0; this.received = 0; this.synced = 0;
    this.syncing = false; this.syncDirty = false; this.syncTimer = null; this.haveTimer = null;
    this.closed = false;
    this.ws = null;
  }

  start() {
    if (!this.signalUrl) return;
    this.#connectWs();
    this.haveTimer = setInterval(() => this.#broadcastHave(), 15000); // re-advertise as our cache grows
  }
  close() {
    this.closed = true;
    clearInterval(this.haveTimer); clearTimeout(this.syncTimer);
    try { this.ws?.close(); } catch {}
    for (const p of this.peers.values()) { try { p.dc?.close(); } catch {} try { p.pc?.close(); } catch {} }
    this.peers.clear();
  }
  status() {
    return { self: this.selfId, room: this.room, connected: this.peers.size,
      peers: [...this.peers.keys()], served: this.served, received: this.received, synced: this.synced,
      syncing: this.syncing, ws: this.ws ? this.ws.readyState : -1 };
  }
  #emit() { try { this.onStatus(this.status()); } catch {} }

  // ---- signaling (room rendezvous) ----
  #connectWs() {
    if (this.closed) return;
    let ws;
    try { ws = this.ws = new WebSocket(this.signalUrl); } catch { setTimeout(() => this.#connectWs(), 3000); return; }
    ws.onopen = () => {
      ws.send(JSON.stringify({ type: 'announce', resource: this.room, offers: [] })); // join as answerer
      this.#makeOffer(); // and announce an offer so fresh peers find us
      this.#emit();
    };
    ws.onmessage = (ev) => this.#onSignal(ev);
    ws.onerror = () => {};
    ws.onclose = () => { this.#emit(); if (!this.closed) setTimeout(() => this.#connectWs(), 3000); };
  }

  async #onSignal(ev) {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.resource !== this.room) return;
    if (m.type === 'offer' && typeof m.sdp === 'string' && m.from !== this.selfId) {
      await this.#answer(m);
    } else if (m.type === 'answer' && typeof m.sdp === 'string') {
      const rec = this.pendingPc.get(m.offer_id);
      if (rec && !rec.pc.currentRemoteDescription) {
        try { await rec.pc.setRemoteDescription({ type: 'answer', sdp: m.sdp }); } catch {}
      }
    }
  }

  async #makeOffer() {
    if (this.closed || this.ws?.readyState !== 1) return;
    const pc = new RTCPeerConnection({ iceServers: this.iceServers });
    const dc = pc.createDataChannel('blocks');
    const offerId = this.selfId + '.' + Math.random().toString(36).slice(2, 10); // embeds our id so the answerer can compare
    this.pendingPc.set(offerId, { pc, dc, offerer: true });
    this.#wireChannel(dc, pc, true);
    await pc.setLocalDescription(await pc.createOffer());
    await this.#iceComplete(pc);
    const send = () => { if (this.ws?.readyState === 1) this.ws.send(JSON.stringify({ type: 'announce', resource: this.room, from: this.selfId, offers: [{ sdp: pc.localDescription.sdp, offer_id: offerId }] })); };
    send();
    // retry a few times so a peer that joins slightly later still sees the offer
    let tries = 0; const t = setInterval(() => { if (this.closed || tries++ > 6 || dc.readyState === 'open') return clearInterval(t); send(); }, 2500);
  }

  async #answer(m) {
    // Asymmetric handshake: only the higher-id peer answers an offer, so each
    // pair forms exactly ONE connection (offerer = lower id) — no duplicates, no
    // dedup race. The offerer's id is embedded in offer_id.
    const offererId = String(m.offer_id || '').split('.')[0];
    if (!offererId || this.selfId <= offererId) return;
    if (this.handledOffers.has(m.offer_id)) return; // ignore re-announced offer
    this.handledOffers.add(m.offer_id);
    const pc = new RTCPeerConnection({ iceServers: this.iceServers });
    let dc = null;
    pc.ondatachannel = (e) => { dc = e.channel; this.#wireChannel(dc, pc, false); };
    try {
      await pc.setRemoteDescription({ type: 'offer', sdp: m.sdp });
      await pc.setLocalDescription(await pc.createAnswer());
      await this.#iceComplete(pc);
      this.ws.send(JSON.stringify({ type: 'answer', resource: this.room, to: m.from, from: this.selfId, offer_id: m.offer_id, sdp: pc.localDescription.sdp }));
    } catch { try { pc.close(); } catch {} }
  }

  #iceComplete(pc) {
    return new Promise((res) => {
      if (pc.iceGatheringState === 'complete') return res();
      const check = () => { if (pc.iceGatheringState === 'complete') { pc.removeEventListener('icegatheringstatechange', check); res(); } };
      pc.addEventListener('icegatheringstatechange', check);
      setTimeout(res, 8000); // don't hang forever on a stalled gather
    });
  }

  // ---- data channel ----
  #wireChannel(dc, pc, offerer) {
    dc.binaryType = 'arraybuffer';
    dc.bufferedAmountLowThreshold = 256 * 1024;
    const conn = { dc, pc, offerer, peerId: null, have: new Map(), inbound: null };
    dc.onopen = () => { this.#send(dc, { t: 'hello', id: this.selfId }); this.#sendHave(dc); };
    dc.onclose = () => { if (conn.peerId && this.peers.get(conn.peerId)?.dc === dc) { this.peers.delete(conn.peerId); this.#emit(); } };
    dc.onmessage = (ev) => this.#onChannel(conn, ev.data);
    pc.oniceconnectionstatechange = () => { if (['failed', 'closed'].includes(pc.iceConnectionState)) { try { pc.close(); } catch {} } };
  }

  #onChannel(conn, data) {
    if (typeof data === 'string') {
      let m; try { m = JSON.parse(data); } catch { return; }
      this.#onControl(conn, m);
    } else {
      // binary chunk for the current inbound transfer on this connection
      const inb = conn.inbound; if (!inb) return;
      const u8 = new Uint8Array(data);
      inb.chunks.push(u8); inb.received += u8.length;
    }
  }

  #onControl(conn, m) {
    switch (m.t) {
      case 'hello': this.#onHello(conn, m.id); break;
      case 'have': for (const [h, ht] of (m.list || [])) conn.have.set(h, ht); if (conn.peerId && this.peers.get(conn.peerId)) this.peers.get(conn.peerId).have = conn.have; this.#scheduleSync(); break;
      case 'getblock': this.#serve(conn, m); break;
      case 'blockmeta': conn.inbound = { reqId: m.id, hash: m.hash, size: m.size, chunks: [], received: 0 }; break;
      case 'blockend': this.#finishInbound(conn); break;
      case 'noblock': { const p = conn.inboundReq; if (p) { p.resolve(null); conn.inboundReq = null; } break; }
      default: break;
    }
  }

  // The asymmetric handshake yields one connection per pair; keep the first and
  // close any stray duplicate (both sides keep the same physical connection).
  #onHello(conn, peerId) {
    conn.peerId = peerId;
    const existing = this.peers.get(peerId);
    if (existing && existing !== conn) { try { conn.dc?.close(); } catch {} try { conn.pc?.close(); } catch {} return; }
    this.peers.set(peerId, conn);
    this.#emit();
  }

  #broadcastHave() {
    for (const p of this.peers.values()) if (p.dc?.readyState === 'open') this.#sendHave(p.dc);
  }

  // ---- catch-up: pull every block our peers advertise that we don't have ----
  #scheduleSync() {
    if (this.syncing) { this.syncDirty = true; return; }
    clearTimeout(this.syncTimer);
    this.syncTimer = setTimeout(() => this.#sync(), 300); // coalesce bursts of have messages
  }
  async #sync() {
    if (!this.store || this.closed) return;
    this.syncing = true; this.syncDirty = false; this.#emit();
    try {
      const want = new Map(); // union of all peers' advertised blocks: hash -> height
      for (const p of this.peers.values()) for (const [h, ht] of p.have) if (!want.has(h)) want.set(h, ht);
      for (const [hash, height] of want) {
        if (this.closed) break;
        if (await this.store.has(height, hash)) continue;         // already cached
        const bytes = await this.requestBlock(hash, height);       // verified + cached on success
        if (bytes) { this.synced++; this.#emit(); }
      }
    } finally {
      this.syncing = false; this.#emit();
      if (this.syncDirty) this.#scheduleSync(); // new advertisements arrived mid-sync
    }
  }

  #sendHave(dc) {
    if (!this.store) return;
    this.store.list().then((l) => {
      const list = l.slice(-100).map((b) => [b.hash, b.height]);
      this.#send(dc, { t: 'have', list });
    }).catch(() => {});
  }

  #send(dc, obj) { try { if (dc.readyState === 'open') dc.send(JSON.stringify(obj)); } catch {} }

  // ---- serving a block we hold ----
  async #serve(conn, m) {
    const dc = conn.dc;
    let rec = null;
    try { rec = await this.store.findByHash(m.hash); } catch {}
    if (!rec) { this.#send(dc, { t: 'noblock', id: m.id, hash: m.hash }); return; }
    let bytes = null;
    try { bytes = await this.store.get(rec.height, rec.hash); } catch {}
    if (!bytes) { this.#send(dc, { t: 'noblock', id: m.id, hash: m.hash }); return; }
    this.#send(dc, { t: 'blockmeta', id: m.id, hash: m.hash, size: bytes.length });
    for (let off = 0; off < bytes.length; off += CHUNK) {
      if (dc.readyState !== 'open') return;
      if (dc.bufferedAmount > HIGH_WATER) await new Promise((r) => { dc.addEventListener('bufferedamountlow', r, { once: true }); });
      dc.send(bytes.subarray(off, off + CHUNK));
    }
    this.#send(dc, { t: 'blockend', id: m.id });
    this.served++; this.#emit();
  }

  // ---- requesting a block, verifying it, caching it ----
  #finishInbound(conn) {
    const inb = conn.inbound; const req = conn.inboundReq;
    conn.inbound = null; conn.inboundReq = null;
    if (!inb || !req) return;
    const bytes = new Uint8Array(inb.received);
    let off = 0; for (const c of inb.chunks) { bytes.set(c, off); off += c.length; }
    if (bytes.length < 80 || blockHashOf(bytes) !== req.hash) { req.resolve(null); return; } // liar / corrupt → reject
    if (this.store && req.height != null) this.store.put(req.height, req.hash, bytes).catch(() => {});
    this.received++; this.#emit();
    req.resolve(bytes);
  }

  // Fetch a block by hash from a peer that advertises it. Returns verified bytes
  // or null (no peer has it, or the bytes failed the hash check).
  requestBlock(hash, height = null, timeoutMs = 20000) {
    let conn = null, h = height;
    for (const p of this.peers.values()) {
      if (p.dc?.readyState === 'open' && p.have.has(hash)) { conn = p; if (h == null) h = p.have.get(hash); break; }
    }
    if (!conn) return Promise.resolve(null);
    return new Promise((resolve) => {
      const id = 'r' + (this.reqSeq++);
      const done = (v) => { clearTimeout(timer); resolve(v); };
      const timer = setTimeout(() => { conn.inboundReq = null; conn.inbound = null; done(null); }, timeoutMs);
      conn.inboundReq = { hash, height: h, resolve: done };
      this.#send(conn.dc, { t: 'getblock', id, hash });
    });
  }

  // convenience for the two-tab test: pull one block a peer advertises, verify it.
  async testFetch() {
    for (const p of this.peers.values()) {
      for (const [hash, height] of p.have) {
        const bytes = await this.requestBlock(hash, height);
        return { hash, height, ok: !!bytes, bytes: bytes ? bytes.length : 0 };
      }
    }
    return { ok: false, reason: 'no peer advertises any block yet' };
  }
}
