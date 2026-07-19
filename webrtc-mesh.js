// webrtc-mesh.js — proven, app-agnostic WebRTC mesh over JSS content-addressed
// signaling. Born in the play-grounds/webrtc lab (verified across Brave,
// Firefox and mobile — host/srflx/prflx paths, ~1ms RTT), hardened here.
// THIS FILE IS THE CANONICAL COPY: the lab vendors it verbatim — after
// changing it, copy it back to play-grounds/webrtc/webrtc-mesh.js.
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
    const t = setTimeout(() => { pc.removeEventListener('icegatheringstatechange', check); res(); }, ms);
    const check = () => { if (pc.iceGatheringState === 'complete') { clearTimeout(t); pc.removeEventListener('icegatheringstatechange', check); res(); } };
    pc.addEventListener('icegatheringstatechange', check);
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
  constructor({ url, room = '', iceServers, channelLabel = 'data', batch = 4, maxPeers = 8,
    onPeer = () => {}, onDrop = () => {}, onData = () => {}, onChange = () => {} }) {
    this.url = url; this.room = room; this.channelLabel = channelLabel; this.batch = batch;
    // Hard ceilings: RTCPeerConnections are expensive (ICE agents, consent-check
    // UDP every ~5s, NAT table entries) — a mesh bug must degrade into "stops
    // growing", never into browser crashes or a flooded home router.
    this.maxPeers = maxPeers;
    this._answering = 0; // concurrent answer attempts (each runs a full ICE gather)
    this.iceServers = (iceServers && iceServers.length) ? iceServers : DEFAULT_ICE;
    this.onPeer = onPeer; this.onDrop = onDrop; this.onData = onData; this.onChange = onChange;
    this.peers = new Map();     // signaling id -> { id, pc, ch, pair, inst }
    this.pending = new Map();   // offer_id -> pc (offers awaiting an answer)
    // Stable per-tab identity, exchanged as a `mesh-hello` on channel open.
    // Signaling ids churn (re-announces, tracker reconnects), so without this
    // the same browser accumulates duplicate live entries under fresh ids —
    // and a tracker that echoes an announce back even connects a tab to itself.
    this.instance = rid() + rid();
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
        id: e.id, inst: e.inst || null, ice: e.pc.iceConnectionState, conn: e.pc.connectionState,
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
    if (this.peers.size >= this.maxPeers) return; // full — don't invite connections we'd only reject
    // a fresh peer floods `batch` offers so several newcomers can each take one;
    // once the mesh has live peers, one standing offer per re-announce still
    // heals partitions and wins races without spinning up `batch` fresh
    // RTCPeerConnections every cycle (they'd just be reaped 60s later —
    // steady background churn, battery/CPU on mobile)
    const n = this.peers.size ? 1 : this.batch;
    const offers = [];
    for (let i = 0; i < n; i++) {
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
      // at capacity (or already talking to this id, or churning hard): don't
      // spin up an ICE gather we'd throw away
      if (this.peers.size >= this.maxPeers || this.peers.has(m.from) || this._answering >= 4) return;
      this._answering++;
      try {
        const pc = new RTCPeerConnection({ iceServers: this.iceServers });
        pc.ondatachannel = (ev) => this._adopt(m.from, pc, ev.channel);
        await pc.setRemoteDescription({ type: 'offer', sdp: m.sdp });
        await pc.setLocalDescription(await pc.createAnswer());
        await iceComplete(pc);
        this._ws({ type: 'answer', resource: this.resource, to: m.from, offer_id: m.offer_id, sdp: pc.localDescription.sdp });
        // if this answer never turns into a registered peer, reap the attempt
        setTimeout(() => { if (this.peers.get(m.from)?.pc !== pc) { try { pc.close(); } catch {} } }, 60_000);
      } catch {} finally { this._answering--; }
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
    const entry = { id, pc, ch, pair: null, inst: null };
    const register = () => {
      if (!this.peers.has(id) && this.peers.size >= this.maxPeers) { // cap races: full is full
        try { ch.close(); } catch {} try { pc.close(); } catch {}
        return;
      }
      const old = this.peers.get(id);
      if (old && old !== entry) { try { old.ch?.close(); } catch {} try { old.pc.close(); } catch {} } // replaced — don't leak the pc
      this.peers.set(id, entry); this.onPeer(id); this.onChange();
      try { ch.send(JSON.stringify({ t: 'mesh-hello', inst: this.instance })); } catch {}
    };
    const drop = () => {
      if (this.peers.get(id) === entry) { this.peers.delete(id); this.onDrop(id); this.onChange(); }
      // this connection's life is over either way — release its native resources
      try { entry.ch?.close(); } catch {}
      try { entry.pc.close(); } catch {}
    };
    if (ch.readyState === 'open') register();
    else {
      ch.addEventListener('open', register);
      // a channel that hasn't opened in 60s never will — reap the attempt
      setTimeout(() => { if (this.peers.get(id)?.pc !== pc) { try { ch.close(); } catch {} try { pc.close(); } catch {} } }, 60_000);
    }
    ch.addEventListener('close', drop);
    ch.onmessage = (ev) => {
      // intercept the mesh-layer hello; everything else is the app's
      if (typeof ev.data === 'string' && ev.data.length < 200 && ev.data.includes('"mesh-hello"')) {
        let m = null; try { m = JSON.parse(ev.data); } catch {}
        if (m && m.t === 'mesh-hello') { this._hello(id, entry, m.inst); return; }
      }
      this.onData(id, ev.data);
    };
    pc.onconnectionstatechange = () => { if (['failed', 'disconnected', 'closed'].includes(pc.connectionState)) drop(); };
  }

  // Instance-identity bookkeeping. Peers that predate mesh-hello simply never
  // send one (their MeshCore forwards ours to the app, which ignores unknown
  // message types) — for them behaviour is unchanged.
  _hello(id, entry, inst) {
    if (typeof inst !== 'string' || !inst || this.peers.get(id) !== entry) return;
    entry.inst = inst;
    if (inst === this.instance) return this._reap(id, entry); // a loop back to this very tab
    // duplicate connections to one tab: keep the established connection and
    // reap the newcomer — churn-free, since the standing link never resets.
    // Only the lexicographically lower instance acts (deterministic single
    // closer — no mutual-close races); a zombie survivor clears itself in
    // seconds via consent checks → connectionstatechange.
    if (this.instance < inst) {
      for (const oe of this.peers.values()) {
        if (oe !== entry && oe.inst === inst) return this._reap(id, entry);
      }
    }
  }
  _reap(id, e) {
    if (this.peers.get(id) === e) { this.peers.delete(id); this.onDrop(id); this.onChange(); }
    try { e.ch?.close(); } catch {}
    try { e.pc.close(); } catch {}
  }

  async _pollStats() {
    for (const e of this.peers.values()) { const p = await selectedPair(e.pc); if (p) e.pair = p; }
    if (this.peers.size) this.onChange();
  }
}
