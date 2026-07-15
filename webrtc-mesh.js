// webrtc-mesh.js — proven, app-agnostic WebRTC mesh over JSS content-addressed
// signaling. Extracted from the play-grounds/webrtc lab, where every layer was
// verified across Brave, Firefox and mobile (host/srflx/prflx paths, ~1ms RTT).
//
// The contract: symmetric handshake — every peer batches offers AND answers
// every offer it receives — with candidates baked into the SDP (non-trickle,
// because the tracker relays offers/answers but NOT ICE candidates), keyed by
// the signaling `from` id. App code supplies hooks (onPeer/onDrop/onData) and
// runs its own protocol over each peer's data channel via send()/channel().
//
// Room names are hashed to a hex resource so any human label works with hex-only
// trackers like JSS; a raw hex room passes through unchanged (for interop).

const DEFAULT_ICE = [{ urls: 'stun:stun.l.google.com:19302' }];
const rid = () => Math.random().toString(36).slice(2, 12);

export async function toHexResource(room) {
  if (/^[a-f0-9]{8,128}$/i.test(room)) return room.toLowerCase();
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('mesh:' + room));
  return [...new Uint8Array(buf)].slice(0, 16).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// non-trickle: resolve once all STUN candidates are gathered into the local SDP
function iceComplete(pc, ms = 8000) {
  return new Promise((res) => {
    if (pc.iceGatheringState === 'complete') return res();
    const check = () => { if (pc.iceGatheringState === 'complete') { pc.removeEventListener('icegatheringstatechange', check); res(); } };
    pc.addEventListener('icegatheringstatechange', check);
    setTimeout(res, ms);
  });
}

// getStats → the selected candidate pair, i.e. HOW this link actually connected
// (host↔host = LAN, srflx = NAT traversal, relay = TURN). Purely diagnostic.
async function selectedPair(pc) {
  try {
    const stats = await pc.getStats();
    const byId = new Map(); let transport = null; const pairs = [];
    stats.forEach((r) => { byId.set(r.id, r); if (r.type === 'transport') transport = r; if (r.type === 'candidate-pair') pairs.push(r); });
    let pair = transport?.selectedCandidatePairId ? byId.get(transport.selectedCandidatePairId) : null;
    if (!pair) pair = pairs.find((p) => p.selected) || pairs.find((p) => p.nominated && p.state === 'succeeded') || pairs.find((p) => p.state === 'succeeded');
    if (!pair) return null;
    const L = byId.get(pair.localCandidateId), R = byId.get(pair.remoteCandidateId);
    return { path: `${L?.candidateType ?? '?'} → ${R?.candidateType ?? '?'}`, state: pair.state, rtt: pair.currentRoundTripTime != null ? Math.round(pair.currentRoundTripTime * 1000) : null };
  } catch { return null; }
}

export class MeshCore {
  constructor({ url, room = '', iceServers, channelLabel = 'data', batch = 4,
    onPeer = () => {}, onDrop = () => {}, onData = () => {}, onChange = () => {} }) {
    this.url = url; this.room = room; this.channelLabel = channelLabel; this.batch = batch;
    this.iceServers = (iceServers && iceServers.length) ? iceServers : DEFAULT_ICE;
    this.onPeer = onPeer; this.onDrop = onDrop; this.onData = onData; this.onChange = onChange;
    this.peers = new Map();     // signaling id -> { id, pc, ch, pair }
    this.pending = new Map();   // offer_id -> pc (offers awaiting an answer)
    this.resource = null; this.ws = null; this.closed = false;
    this.reannounceTimer = null; this.statsTimer = null;
  }

  async start() {
    if (!this.url) return;
    this.closed = false;
    this.resource = await toHexResource(this.room || '');
    this._connect();
    this.statsTimer = setInterval(() => this._pollStats(), 3000);
  }
  stop() {
    this.closed = true;
    clearInterval(this.reannounceTimer); clearInterval(this.statsTimer);
    try { this.ws?.close(); } catch {}
    for (const e of this.peers.values()) { try { e.ch?.close(); } catch {} try { e.pc.close(); } catch {} }
    for (const pc of this.pending.values()) { try { pc.close(); } catch {} }
    this.peers.clear(); this.pending.clear();
    this.onChange();
  }

  get wsState() { return this.ws ? this.ws.readyState : -1; }
  status() {
    return {
      room: this.resource, connected: this.peers.size, ws: this.wsState,
      peers: [...this.peers.values()].map((e) => ({
        id: e.id, ice: e.pc.iceConnectionState, conn: e.pc.connectionState,
        open: e.ch?.readyState === 'open', path: e.pair?.path || null, rtt: e.pair?.rtt ?? null,
      })),
    };
  }
  send(id, data) { const e = this.peers.get(id); if (e && e.ch.readyState === 'open') { try { e.ch.send(data); return true; } catch {} } return false; }
  channel(id) { return this.peers.get(id)?.ch || null; }

  // ---- signaling ----
  _connect() {
    if (this.closed) return;
    let ws;
    try { ws = this.ws = new WebSocket(this.url); } catch { setTimeout(() => this._connect(), 3000); return; }
    ws.onopen = () => { this._announce(); clearInterval(this.reannounceTimer); this.reannounceTimer = setInterval(() => this._announce(), 90_000); this.onChange(); };
    ws.onmessage = (e) => { let m; try { m = JSON.parse(e.data); } catch { return; } this._onSignal(m); };
    ws.onerror = () => {};
    ws.onclose = () => { clearInterval(this.reannounceTimer); this.onChange(); if (!this.closed) setTimeout(() => this._connect(), 3000); };
  }
  _ws(m) { if (this.ws && this.ws.readyState === 1) this.ws.send(JSON.stringify(m)); }

  async _makeOffer() {
    const pc = new RTCPeerConnection({ iceServers: this.iceServers });
    pc._ch = pc.createDataChannel(this.channelLabel);
    await pc.setLocalDescription(await pc.createOffer());
    await iceComplete(pc);
    return { pc, sdp: pc.localDescription.sdp };
  }
  async _announce() {
    if (!this.ws || this.ws.readyState !== 1) return;
    const offers = [];
    for (let i = 0; i < this.batch; i++) {
      try {
        const { pc, sdp } = await this._makeOffer();
        const offer_id = rid();
        this.pending.set(offer_id, pc);
        setTimeout(() => { if (this.pending.delete(offer_id)) { try { pc.close(); } catch {} } }, 60_000);
        offers.push({ offer_id, sdp });
      } catch {}
    }
    if (offers.length) this._ws({ type: 'announce', resource: this.resource, offers });
  }
  async _onSignal(m) {
    if (m.resource !== this.resource) return;
    if (m.type === 'offer' && m.from && typeof m.sdp === 'string') {
      try {
        const pc = new RTCPeerConnection({ iceServers: this.iceServers });
        pc.ondatachannel = (ev) => this._adopt(m.from, pc, ev.channel);
        await pc.setRemoteDescription({ type: 'offer', sdp: m.sdp });
        await pc.setLocalDescription(await pc.createAnswer());
        await iceComplete(pc);
        this._ws({ type: 'answer', resource: this.resource, to: m.from, offer_id: m.offer_id, sdp: pc.localDescription.sdp });
      } catch {}
    } else if (m.type === 'answer' && m.offer_id && typeof m.sdp === 'string') {
      const pc = this.pending.get(m.offer_id);
      if (!pc) return;
      this.pending.delete(m.offer_id);
      try { await pc.setRemoteDescription({ type: 'answer', sdp: m.sdp }); this._adopt(m.from, pc, pc._ch); }
      catch { try { pc.close(); } catch {} }
    }
  }

  // Register a peer once its channel opens — same path for offerer and answerer.
  _adopt(id, pc, ch) {
    ch.binaryType = 'arraybuffer';
    ch.bufferedAmountLowThreshold = 256 * 1024;
    const entry = { id, pc, ch, pair: null };
    const register = () => { this.peers.set(id, entry); this.onPeer(id); this.onChange(); };
    const drop = () => { if (this.peers.get(id) === entry) { this.peers.delete(id); this.onDrop(id); this.onChange(); } };
    if (ch.readyState === 'open') register(); else ch.addEventListener('open', register);
    ch.addEventListener('close', drop);
    ch.onmessage = (ev) => this.onData(id, ev.data);
    pc.onconnectionstatechange = () => { if (['failed', 'disconnected', 'closed'].includes(pc.connectionState)) drop(); };
  }

  async _pollStats() {
    for (const e of this.peers.values()) { const p = await selectedPair(e.pc); if (p) e.pair = p; }
    if (this.peers.size) this.onChange();
  }
}
