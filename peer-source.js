// Trustless block-by-hash transfer over WebRTC — a browser peer that fetches
// blocks from, and serves cached blocks to, other browsers. No block API in the
// path: you request a block *by hash*, and verify the bytes hash back to it, so
// a lying peer is caught (exactly the guarantee the esplora fetch relies on).
//
// The connection layer is the proven `MeshCore` library (extracted from the
// play-grounds/webrtc lab). This file is purely the block protocol that rides
// over each peer's data channel: control JSON (have / getblock / blockmeta /
// blockend / noblock) plus binary block chunks. Runs on the MAIN thread (WebRTC
// isn't available in Workers) and fills the OPFS BlockStore the worker reads.
import { dsha256, reverseHex } from './engine/codec/hash.js';
import { MeshCore } from './webrtc-mesh.js';

const CHUNK = 64 * 1024;
const HIGH_WATER = 4 * 1024 * 1024;
const HDR_BATCH = 500; // headers per getheaders reply (500 × 160 hex chars = 80 KB message)

// block hash = dsha256 of the 80 header bytes, byte-reversed (display order)
export const blockHashOf = (bytes) => reverseHex(dsha256(bytes.subarray(0, 80)));

// Build an RTCPeerConnection iceServers list from a saved webrtc config:
// STUN always, plus the configured TURN server (with credentials) if any.
// undefined (no TURN) lets MeshCore fall back to its STUN-only default.
export function iceServersFrom(cfg) {
  if (!cfg?.turn) return undefined;
  const turn = { urls: cfg.turn };
  if (cfg.turnUser) { turn.username = cfg.turnUser; turn.credential = cfg.turnCred || ''; }
  return [{ urls: 'stun:stun.l.google.com:19302' }, turn];
}

export class PeerSource {
  constructor({ signalUrl, room = 'b17c0100b10c48ea1710', store, cacheBudget = 0, headers = null, iceServers, onStatus = () => {}, onBlock = () => {}, onTip = () => {} }) {
    this.store = store;
    this.cacheBudget = cacheBudget; // rolling byte budget; 0 = unlimited
    this.headers = headers;         // HeaderChain — serves/advertises the header chain when set
    this.onTip = onTip;             // (peerId, {height, hash, start}) on a peer's header-tip advert
    this.pruneTimer = null;
    this.onStatus = onStatus;
    this.onBlock = onBlock; // (hash, height) when a block's bytes arrive from a peer
    this.state = new Map();   // peerId -> { have:Map, inbound, inboundReq }
    this.receivedHashes = new Set(); // block hashes obtained from a peer this session (for provenance)
    this.reqSeq = 0; this.served = 0; this.received = 0; this.synced = 0;
    this.syncing = false; this.syncDirty = false; this.syncTimer = null; this.haveTimer = null;
    this.closed = false;
    this.core = new MeshCore({
      url: signalUrl, room, iceServers, channelLabel: 'blocks',
      onPeer: (id) => this._onPeer(id),
      onDrop: (id) => this._onDrop(id),
      onData: (id, data) => this._onData(id, data),
      onChange: () => this._emit(),
    });
  }

  start() { if (!this.core.url) return; this.core.start(); this.haveTimer = setInterval(() => this._broadcastHave(), 15000); }
  close() {
    this.closed = true;
    clearInterval(this.haveTimer); clearTimeout(this.syncTimer); clearTimeout(this.pruneTimer);
    this.core.stop(); this.state.clear();
  }
  _schedulePrune() {
    if (!this.store || !this.cacheBudget) return;
    clearTimeout(this.pruneTimer);
    this.pruneTimer = setTimeout(() => { this.store.prune(this.cacheBudget).catch(() => {}); }, 3000);
  }
  status() {
    const c = this.core.status();
    return { room: c.room, connected: c.connected, ws: c.ws, peers: c.peers,
      served: this.served, received: this.received, synced: this.synced, syncing: this.syncing };
  }
  _emit() { try { this.onStatus(this.status()); } catch {} }

  // ---- peer lifecycle (from MeshCore) ----
  _onPeer(id) { this.state.set(id, { have: new Map(), inbound: null, inboundReq: null }); this._sendHave(id); this._scheduleSync(); }
  _onDrop(id) {
    const st = this.state.get(id);
    this.state.delete(id);
    if (st?.inboundReq) st.inboundReq.resolve(null); // don't leave requests hanging until their timeouts
    if (st?.hdrReq) { const r = st.hdrReq; st.hdrReq = null; r.resolve(null); }
  }
  _onData(id, data) {
    const st = this.state.get(id); if (!st) return;
    if (typeof data === 'string') { let m; try { m = JSON.parse(data); } catch { return; } this._onControl(id, st, m); }
    else if (st.inbound) {
      const u8 = new Uint8Array(data);
      st.inbound.chunks.push(u8); st.inbound.received += u8.length;
      if (st.inbound.received > st.inbound.size) { // lying peer: more bytes than advertised
        st.inbound = null;
        const req = st.inboundReq;
        if (req) { st.inboundReq = null; req.resolve(null); }
      }
    }
  }
  _send(id, obj) { this.core.send(id, JSON.stringify(obj)); }

  _onControl(id, st, m) {
    switch (m.t) {
      case 'have':
        for (const [h, ht] of (m.list || [])) st.have.set(h, ht);
        if (m.tip && Number.isInteger(m.tip.height) && typeof m.tip.hash === 'string') {
          st.tip = m.tip;
          try { this.onTip(id, m.tip); } catch {}
        }
        this._scheduleSync();
        break;
      case 'getblock': this._serve(id, st, m); break;
      case 'getheaders': this._serveHeaders(id, m); break;
      case 'headers': {
        const r = st.hdrReq;
        if (!r) break;
        st.hdrReq = null;
        const ok = Number.isInteger(m.start) && typeof m.hex === 'string' && m.hex.length > 0
          && m.hex.length % 160 === 0 && m.hex.length <= HDR_BATCH * 160 && /^[0-9a-f]+$/.test(m.hex);
        r.resolve(ok ? { start: m.start, count: m.hex.length / 160, hex: m.hex } : null);
        break;
      }
      case 'blockmeta': {
        // only buffer a transfer we asked for, with a sane size (≤ 4 MB consensus max + slack)
        const req = st.inboundReq;
        st.inbound = (req && req.hash === m.hash && m.size >= 80 && m.size <= 4_200_000)
          ? { hash: m.hash, size: m.size, chunks: [], received: 0 } : null;
        break;
      }
      case 'blockend': this._finishInbound(id, st); break;
      case 'noblock': { const p = st.inboundReq; if (p) { st.inboundReq = null; p.resolve(null); } break; }
      default: break;
    }
  }

  _sendHave(id) {
    if (!this.store) return;
    this.store.list().then((l) => {
      const msg = { t: 'have', list: l.slice(-100).map((b) => [b.hash, b.height]) };
      const s = this.headers?.stats();
      if (s) msg.tip = { height: s.tip, hash: s.tipHash, start: s.start }; // header-chain advert (self-certifying on receipt)
      this._send(id, msg);
    }).catch(() => {});
  }

  // ---- header chain sharing (headers are self-certifying: the receiving
  // side re-validates PoW/linkage/difficulty, so serving needs no trust) ----
  async _serveHeaders(id, m) {
    let r = null;
    if (this.headers && Number.isInteger(m.from)) {
      const count = Math.min(Math.max(1, m.count | 0), HDR_BATCH);
      try { r = await this.headers.getRangeHex(m.from, count); } catch {}
    }
    this._send(id, r ? { t: 'headers', start: r.start, hex: r.hex } : { t: 'headers', start: null, hex: '' });
  }

  bestTip() {
    let best = null;
    for (const s of this.state.values()) if (s.tip && (!best || s.tip.height > best.height)) best = s.tip;
    return best;
  }

  // Fetch up to `count` headers from any peer advertising a header tip.
  // Resolves {start, count, hex} (validated shape only — content is verified
  // by HeaderChain.extend on the caller's side) or null.
  requestHeaders(from, count = HDR_BATCH, timeoutMs = 10000) {
    for (const [id, st] of this.state) {
      if (st.tip && !st.hdrReq && this.core.channel(id)?.readyState === 'open') {
        return new Promise((resolve) => {
          const done = (v) => { clearTimeout(timer); resolve(v); };
          const timer = setTimeout(() => { st.hdrReq = null; done(null); }, timeoutMs);
          st.hdrReq = { resolve: done };
          this._send(id, { t: 'getheaders', from, count });
        });
      }
    }
    return Promise.resolve(null);
  }
  _broadcastHave() { for (const id of this.state.keys()) this._sendHave(id); }

  // ---- serving a block we hold ----
  async _serve(id, st, m) {
    let rec = null; try { rec = await this.store.findByHash(m.hash); } catch {}
    if (!rec) return this._send(id, { t: 'noblock', id: m.id, hash: m.hash });
    let bytes = null; try { bytes = await this.store.get(rec.height, rec.hash); } catch {}
    if (!bytes) return this._send(id, { t: 'noblock', id: m.id, hash: m.hash });
    this._send(id, { t: 'blockmeta', id: m.id, hash: m.hash, size: bytes.length });
    const ch = this.core.channel(id);
    if (!ch) return;
    for (let off = 0; off < bytes.length; off += CHUNK) {
      if (ch.readyState !== 'open') return;
      if (ch.bufferedAmount > HIGH_WATER) await new Promise((r) => {
        ch.addEventListener('bufferedamountlow', r, { once: true });
        ch.addEventListener('close', r, { once: true }); // a closed channel never drains
      });
      ch.send(bytes.subarray(off, off + CHUNK));
    }
    this._send(id, { t: 'blockend', id: m.id });
    this.served++; this._emit();
  }

  // ---- requesting a block, verifying it, caching it ----
  _finishInbound(id, st) {
    const inb = st.inbound, req = st.inboundReq;
    st.inbound = null; st.inboundReq = null;
    if (!inb || !req) return;
    const bytes = new Uint8Array(inb.received);
    let off = 0; for (const c of inb.chunks) { bytes.set(c, off); off += c.length; }
    if (bytes.length < 80 || blockHashOf(bytes) !== req.hash) { req.resolve(null); return; } // liar / corrupt → reject
    if (this.store && req.height != null) this.store.put(req.height, req.hash, bytes).then(() => this._schedulePrune()).catch((e) => {
      if (!this._putWarned) { this._putWarned = true; console.warn('[peer-source] block store write failed — catch-up will not re-pull this session', e); }
    });
    this.receivedHashes.add(req.hash); // provenance: this block came from a peer
    this.received++; this._emit();
    try { this.onBlock(req.hash, req.height); } catch {}
    req.resolve(bytes);
  }

  // Fetch a block by hash from a peer that advertises it. Verified bytes or null.
  requestBlock(hash, height = null, timeoutMs = 20000) {
    let id = null, st = null, h = height;
    for (const [pid, s] of this.state) {
      if (!s.inboundReq && s.have.has(hash) && this.core.channel(pid)?.readyState === 'open') { id = pid; st = s; if (h == null) h = s.have.get(hash); break; }
    }
    if (!st) return Promise.resolve(null);
    return new Promise((resolve) => {
      const done = (v) => { clearTimeout(timer); resolve(v); };
      const timer = setTimeout(() => { st.inboundReq = null; st.inbound = null; done(null); }, timeoutMs);
      st.inboundReq = { hash, height: h, resolve: done };
      this._send(id, { t: 'getblock', id: 'r' + (this.reqSeq++), hash });
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
      for (const s of this.state.values()) for (const [h, ht] of s.have) if (!want.has(h)) want.set(h, ht);
      // pruning floor: once the store is at budget, a block older than the
      // oldest kept height would be evicted the moment it lands — skip it
      let floor = -1;
      if (this.cacheBudget) {
        try { const s = await this.store.stats(); if (s.bytes >= this.cacheBudget && s.minHeight != null) floor = s.minHeight; } catch {}
      }
      for (const [hash, height] of want) {
        if (this.closed) break;
        if (height < floor) continue;
        if (this.receivedHashes.has(hash)) continue; // already pulled this session — never re-pull, even if the store write failed
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
    for (const [, s] of this.state) for (const [hash, height] of s.have) {
      const bytes = await this.requestBlock(hash, height);
      return { hash, height, ok: !!bytes, bytes: bytes ? bytes.length : 0 };
    }
    return { ok: false, reason: 'no peer advertises any block yet' };
  }
}
