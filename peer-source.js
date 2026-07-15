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

// block hash = dsha256 of the 80 header bytes, byte-reversed (display order)
export const blockHashOf = (bytes) => reverseHex(dsha256(bytes.subarray(0, 80)));

export class PeerSource {
  constructor({ signalUrl, room = 'b17c0100b10c48ea1710', store, iceServers, onStatus = () => {} }) {
    this.store = store;
    this.onStatus = onStatus;
    this.state = new Map();   // peerId -> { have:Map, inbound, inboundReq }
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
    clearInterval(this.haveTimer); clearTimeout(this.syncTimer);
    this.core.stop(); this.state.clear();
  }
  status() {
    const c = this.core.status();
    return { room: c.room, connected: c.connected, ws: c.ws, peers: c.peers,
      served: this.served, received: this.received, synced: this.synced, syncing: this.syncing };
  }
  _emit() { try { this.onStatus(this.status()); } catch {} }

  // ---- peer lifecycle (from MeshCore) ----
  _onPeer(id) { this.state.set(id, { have: new Map(), inbound: null, inboundReq: null }); this._sendHave(id); this._scheduleSync(); }
  _onDrop(id) { this.state.delete(id); }
  _onData(id, data) {
    const st = this.state.get(id); if (!st) return;
    if (typeof data === 'string') { let m; try { m = JSON.parse(data); } catch { return; } this._onControl(id, st, m); }
    else if (st.inbound) { const u8 = new Uint8Array(data); st.inbound.chunks.push(u8); st.inbound.received += u8.length; }
  }
  _send(id, obj) { this.core.send(id, JSON.stringify(obj)); }

  _onControl(id, st, m) {
    switch (m.t) {
      case 'have': for (const [h, ht] of (m.list || [])) st.have.set(h, ht); this._scheduleSync(); break;
      case 'getblock': this._serve(id, st, m); break;
      case 'blockmeta': st.inbound = { hash: m.hash, size: m.size, chunks: [], received: 0 }; break;
      case 'blockend': this._finishInbound(id, st); break;
      case 'noblock': { const p = st.inboundReq; if (p) { st.inboundReq = null; p.resolve(null); } break; }
      default: break;
    }
  }

  _sendHave(id) {
    if (!this.store) return;
    this.store.list().then((l) => this._send(id, { t: 'have', list: l.slice(-100).map((b) => [b.hash, b.height]) })).catch(() => {});
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
      if (ch.bufferedAmount > HIGH_WATER) await new Promise((r) => ch.addEventListener('bufferedamountlow', r, { once: true }));
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
    if (this.store && req.height != null) this.store.put(req.height, req.hash, bytes).catch(() => {});
    this.received++; this._emit();
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
    for (const [, s] of this.state) for (const [hash, height] of s.have) {
      const bytes = await this.requestBlock(hash, height);
      return { hash, height, ok: !!bytes, bytes: bytes ? bytes.length : 0 };
    }
    return { ok: false, reason: 'no peer advertises any block yet' };
  }
}
